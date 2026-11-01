package executor

import (
	"slices"
	"strconv"

	"github.com/elnx/seccompgo/internal/instruction"
	"github.com/elnx/seccompgo/internal/symbolic"
)

// StepCap bounds the number of visited states, so a pathological program cannot make
// the walk run unboundedly.
var StepCap = 100000

// Leaf is a reached return: the path condition, the returned value, and its line.
type Leaf struct {
	Path []*symbolic.Constraint
	Ret  *symbolic.Expr
	Line int
}

// Executor walks every path of a classic-BPF program symbolically.
type Executor struct {
	instructions []instruction.Inst
}

// NewExecutor builds an executor for instructions.
func NewExecutor(insts []instruction.Inst) *Executor {
	return &Executor{instructions: insts}
}

type stackItem struct {
	pc int
	st *symbolic.State
}

// Run walks every path depth first. It returns the feasible leaves and whether the
// step cap was hit.
func (e *Executor) Run() ([]*Leaf, bool, error) {
	var leaves []*Leaf
	visited := map[string]bool{}
	stack := []stackItem{{pc: 0, st: symbolic.Initial()}}
	steps := 0
	for len(stack) > 0 {
		if steps >= StepCap {
			return leaves, true, nil
		}
		steps++
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if it.pc >= len(e.instructions) {
			continue
		}
		vk := strconv.Itoa(it.pc) + "|" + it.st.Key()
		if visited[vk] {
			continue
		}
		visited[vk] = true
		if err := e.step(it.pc, it.st, &leaves, &stack); err != nil {
			return nil, false, err
		}
	}
	return leaves, false, nil
}

func (e *Executor) step(pc int, st *symbolic.State, leaves *[]*Leaf, stack *[]stackItem) error {
	sym, err := e.instructions[pc].Symbolize()
	if err != nil {
		return err
	}
	push := func(pc int, s *symbolic.State) {
		*stack = append(*stack, stackItem{pc: pc, st: s})
	}
	switch sym.Kind {
	case instruction.KindRet:
		ret := st.A()
		if !sym.IsA {
			ret = symbolic.Imm(uint64(sym.Val))
		}
		*leaves = append(*leaves, &Leaf{Path: st.Path(), Ret: ret, Line: pc})
	case instruction.KindLD:
		var val *symbolic.Expr
		switch sym.Rel {
		case instruction.RelImm:
			val = symbolic.Imm(uint64(sym.Val))
		case instruction.RelMem:
			if sym.Val < 16 {
				val = st.Mem()[sym.Val]
			} else {
				val = symbolic.Opaque()
			}
		default:
			val = symbolic.DataWord(sym.Val)
		}
		if sym.Dst == "x" {
			push(pc+1, st.WithX(val))
		} else {
			push(pc+1, st.WithA(val))
		}
	case instruction.KindST:
		mem := st.Mem()
		if sym.Val < 16 {
			if sym.Dst == "x" {
				mem[sym.Val] = st.X()
			} else {
				mem[sym.Val] = st.A()
			}
		}
		push(pc+1, st.WithMem(mem))
	case instruction.KindALU:
		var operand *symbolic.Expr
		if sym.SrcX {
			operand = st.X()
		} else if sym.HasOperand {
			operand = symbolic.Imm(uint64(sym.Val))
		}
		a, err := st.A().Apply(sym.Op, operand)
		if err != nil {
			return err
		}
		push(pc+1, st.WithA(a))
	case instruction.KindMisc:
		if sym.Misc == "txa" {
			push(pc+1, st.WithA(st.X()))
		} else {
			push(pc+1, st.WithX(st.A()))
		}
	case instruction.KindJmp:
		push(pc+int(sym.Val)+1, st)
	case instruction.KindCmp:
		e.branchCmp(pc, st, sym, push)
	}
	return nil
}

var split = map[string][2]string{
	"==": {"==", "!="},
	">":  {">", "<="},
	">=": {">=", "<"},
	"&":  {"set", "unset"},
}

func (e *Executor) branchCmp(pc int, st *symbolic.State, sym instruction.Sym, push func(int, *symbolic.State)) {
	if sym.Jt == sym.Jf {
		push(pc+int(sym.Jt)+1, st)
		return
	}
	rhs := symbolic.Imm(uint64(sym.Val))
	if sym.SrcX {
		rhs = st.X()
	}
	taken, els := split[sym.Op][0], split[sym.Op][1]
	if st.A().IsImm() && rhs.IsImm() {
		j := sym.Jf
		if symbolic.Evaluate(st.A().Val(), taken, rhs.Val()) {
			j = sym.Jt
		}
		push(pc+int(j)+1, st)
		return
	}
	for _, br := range [2]struct {
		j  uint8
		op string
	}{{sym.Jt, taken}, {sym.Jf, els}} {
		path := append(append([]*symbolic.Constraint(nil), st.Path()...),
			symbolic.NewConstraint(st.A(), br.op, rhs))
		if feasible(path) {
			push(pc+int(br.j)+1, st.WithPath(path))
		}
	}
}

// feasible is a rule-based satisfiability check: facts are grouped by the expression
// each constrains, and every group is checked alone.
func feasible(path []*symbolic.Constraint) bool {
	groups := map[string][]*symbolic.Constraint{}
	order := []string{}
	for _, c := range path {
		if !c.Rhs().IsImm() || c.Lhs().IsOpaque() {
			continue
		}
		k := c.Lhs().Key()
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], c)
	}
	for _, k := range order {
		if !cellFeasible(groups[k]) {
			return false
		}
	}
	return true
}

func cellFeasible(constraints []*symbolic.Constraint) bool {
	var eqs []uint32
	for _, c := range constraints {
		if c.Op() == "==" {
			v := c.Rhs().Val()
			dup := slices.Contains(eqs, v)
			if !dup {
				eqs = append(eqs, v)
			}
		}
	}
	if len(eqs) > 1 {
		return false
	}
	if len(eqs) == 1 {
		for _, c := range constraints {
			if !symbolic.Evaluate(eqs[0], c.Op(), c.Rhs().Val()) {
				return false
			}
		}
		return true
	}
	lo := int64(0)
	hi := int64(0xffffffff)
	for _, c := range constraints {
		v := int64(c.Rhs().Val())
		switch c.Op() {
		case ">":
			if v+1 > lo {
				lo = v + 1
			}
		case ">=":
			if v > lo {
				lo = v
			}
		case "<":
			if v-1 < hi {
				hi = v - 1
			}
		case "<=":
			if v < hi {
				hi = v
			}
		}
	}
	return lo <= hi
}
