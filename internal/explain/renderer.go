package explain

import (
	"fmt"
	"strings"

	"seccompgo/internal/consts"
	"seccompgo/internal/symbolic"
	"seccompgo/internal/util"
)

// Renderer renders path facts as C-like conditions.
type Renderer struct {
	fusion *QwordFusion
}

// NewRenderer builds a renderer sharing a fusion.
func NewRenderer(f *QwordFusion) *Renderer { return &Renderer{fusion: f} }

// Precedence is C-like operator precedence, higher binding tighter.
var precedence = map[string]int{
	"*": 12, "/": 12, "+": 11, "-": 11, "<<": 10, ">>": 10,
	"<": 9, "<=": 9, ">": 9, ">=": 9, "==": 8, "!=": 8,
	"&": 7, "^": 6, "|": 5,
}

const unaryPrec = 13

var comparisons = map[string]bool{"==": true, "!=": true, "<": true, "<=": true, ">": true, ">=": true}

// Conjunction renders facts joined by " && ". sys nil means no syscall context.
func (r *Renderer) Conjunction(facts []Fact, sys *string) string {
	parts := make([]string, 0, len(facts))
	for _, fact := range facts {
		switch f := fact.(type) {
		case *Qword:
			parts = append(parts, fmt.Sprintf("%s %s 0x%x", r.dataName(r.fusion.LoOff(f.Base), sys), f.Op, f.Val))
		case *symbolic.Constraint:
			parts = append(parts, r.constraint(f, sys))
		}
	}
	return strings.Join(parts, " && ")
}

func (r *Renderer) constraint(c *symbolic.Constraint, sys *string) string {
	if c.Op() == "set" {
		return "(" + r.binop("&", c.Lhs(), c.Rhs(), sys) + ") != 0"
	}
	if c.Op() == "unset" {
		return "(" + r.binop("&", c.Lhs(), c.Rhs(), sys) + ") == 0"
	}
	prec := precedence[c.Op()]
	return r.operand(c.Lhs(), c.Op(), prec, sys) + " " + c.Op() + " " +
		r.operand(c.Rhs(), c.Op(), prec, sys)
}

func (r *Renderer) expr(e *symbolic.Expr, sys *string) string {
	switch e.Kind() {
	case symbolic.KindOpaque:
		return "<opaque>"
	case symbolic.KindImm:
		return fmt.Sprintf("0x%x", e.Val())
	case symbolic.KindData:
		return r.dataName(e.Offset(), sys)
	case symbolic.KindUnop:
		return "-" + r.operand(e.Lhs(), "neg", unaryPrec, sys)
	default:
		return r.binop(e.Op(), e.Lhs(), e.Rhs(), sys)
	}
}

func (r *Renderer) binop(op string, lhs, rhs *symbolic.Expr, sys *string) string {
	prec := precedence[op]
	left := r.operand(lhs, op, prec, sys)
	right := ""
	if rhs.IsImm() && (op == "<<" || op == ">>") {
		right = fmt.Sprintf("%d", rhs.Val())
	} else {
		right = r.operand(rhs, op, prec+1, sys)
	}
	return left + " " + op + " " + right
}

func (r *Renderer) operand(child *symbolic.Expr, parentOp string, minPrec int, sys *string) string {
	s := r.expr(child, sys)
	if child.Kind() != symbolic.KindBinop {
		return s
	}
	if precedence[child.Op()] < minPrec || r.clarityWrap(parentOp, child.Op()) {
		return "(" + s + ")"
	}
	return s
}

func (r *Renderer) clarityWrap(parentOp, childOp string) bool {
	if comparisons[parentOp] {
		return false
	}
	if precedence[parentOp] == precedence[childOp] {
		return false
	}
	if precedence[childOp] == precedence["*"] && precedence[parentOp] == precedence["+"] {
		return false
	}
	return true
}

func (r *Renderer) dataName(offset uint32, sys *string) string {
	switch offset {
	case consts.SysNumber, consts.Arch:
		return consts.SeccompDataNames[offset]
	default:
		return r.qwordWordName(offset, sys)
	}
}

func (r *Renderer) qwordWordName(offset uint32, sys *string) string {
	base := r.fusion.BaseOf(offset)
	if !isQwordBase(base) {
		return fmt.Sprintf("data[%d]", offset)
	}
	var name string
	if base == consts.InstructionPointer {
		name = consts.SeccompDataNames[base]
	} else {
		idx := (base - consts.Args) / 8
		var args []string
		if sys != nil {
			args = consts.ArgNames(*sys)
		}
		if int(idx) < len(args) {
			name = args[idx]
		} else {
			name = fmt.Sprintf("args[%d]", idx)
		}
		name = util.Colorize(name, "args")
	}
	if offset == r.fusion.HiOff(base) {
		return name + " >> 32"
	}
	return name
}
