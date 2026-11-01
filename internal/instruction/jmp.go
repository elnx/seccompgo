package instruction

import (
	"fmt"

	"github.com/elnx/seccompgo/internal/consts"
	"github.com/elnx/seccompgo/internal/symbolic"
	"github.com/elnx/seccompgo/internal/util"
)

// JMP is an unconditional jump or a comparison of A against X or an immediate.
type JMP struct {
	base
}

// jumpOp returns "none", "==", ">", ">=" or "&".
func (i *JMP) jumpOp() (string, error) {
	switch i.b.Code & 0x70 {
	case 0x00:
		return "none", nil
	case 0x10:
		return "==", nil
	case 0x20:
		return ">", nil
	case 0x30:
		return ">=", nil
	case 0x40:
		return "&", nil
	}
	return "", i.invalid("unknown jmp type")
}

func (i *JMP) srcX() bool { return i.b.Code&0x8 != 0 }

func (i *JMP) at(off int) int { return i.b.Line + off + 1 }

func (i *JMP) gotoStr(off int) string {
	return fmt.Sprintf("goto %04d", i.at(off))
}

// sysnameByK names the syscall k for the inferred or declared architecture.
func (i *JMP) sysnameByK() string {
	a := i.inferArch()
	if a == "" {
		a = i.b.Arch
	}
	name, ok := consts.SyscallName(a, i.b.K)
	if !ok {
		return ""
	}
	if a == i.b.Arch {
		return name
	}
	return a + "." + name
}

func (i *JMP) srcStr(op string) string {
	if i.srcX() {
		return "X"
	}
	as := i.uniqueA()
	if len(as) != 1 {
		return fmt.Sprintf("%d", i.b.K)
	}
	a := as[0]
	if !a.PlainData() {
		return fmt.Sprintf("%d", i.b.K)
	}
	hex := fmt.Sprintf("0x%x", i.b.K)
	switch a.Offset() {
	case consts.SysNumber:
		if op == "==" {
			if name := i.sysnameByK(); name != "" {
				return util.Colorize(name, "syscall")
			}
		}
		return hex
	case consts.Arch:
		if name, ok := archNameByValue(i.b.K); ok {
			return util.Colorize(name, "arch")
		}
		return hex
	}
	return hex
}

func archNameByValue(v uint32) (string, bool) {
	for _, name := range consts.AuditArchOrder {
		if consts.AuditArch[name] == v {
			return name, true
		}
	}
	return "", false
}

func (i *JMP) ifStr(op string, neg bool) string {
	if !neg {
		return fmt.Sprintf("if (A %s %s) ", op, i.srcStr(op))
	}
	if op == "&" {
		return fmt.Sprintf("if (!(A & %s)) ", i.srcStr(op))
	}
	mirrorOp := map[string]string{">=": "<", ">": "<=", "==": "!="}[op]
	return fmt.Sprintf("if (A %s %s) ", mirrorOp, i.srcStr(op))
}

// Decompile renders the jump as assembly.
func (i *JMP) Decompile() (string, error) {
	op, err := i.jumpOp()
	if err != nil {
		return "", err
	}
	if op == "none" {
		return i.gotoStr(int(i.b.K)), nil
	}
	if i.b.Jt == 0 && i.b.Jf == 0 {
		return "/* no-op */", nil
	}
	if i.b.Jt == i.b.Jf {
		return i.gotoStr(int(i.b.Jt)), nil
	}
	if i.b.Jt == 0 {
		return i.ifStr(op, true) + i.gotoStr(int(i.b.Jf)), nil
	}
	out := i.ifStr(op, false) + i.gotoStr(int(i.b.Jt))
	if i.b.Jf != 0 {
		out += " else " + i.gotoStr(int(i.b.Jf))
	}
	return out, nil
}

// Symbolize returns the jump form used by interpreters.
func (i *JMP) Symbolize() (Sym, error) {
	op, err := i.jumpOp()
	if err != nil {
		return Sym{}, err
	}
	if op == "none" {
		return Sym{Kind: KindJmp, Val: i.b.K}, nil
	}
	return Sym{Kind: KindCmp, Op: op, SrcX: i.srcX(), Val: i.b.K, Jt: i.b.Jt, Jf: i.b.Jf}, nil
}

func (i *JMP) resolve(state *symbolic.State, e *symbolic.Expr) *symbolic.Expr {
	if !e.PlainData() {
		return e
	}
	for _, c := range state.Path() {
		if c.PlainDataEq(int(e.Offset())) {
			return c.Rhs()
		}
	}
	return e
}

func (i *JMP) narrow(state *symbolic.State) (*symbolic.State, error) {
	if !state.A().PlainData() {
		return state, nil
	}
	var rhs *symbolic.Expr
	if i.srcX() {
		rhs = i.resolve(state, state.X())
	} else {
		rhs = symbolic.Imm(uint64(i.b.K))
	}
	if !rhs.IsImm() {
		return state, nil
	}
	path := append(append([]*symbolic.Constraint(nil), state.Path()...),
		symbolic.NewConstraint(state.A(), "==", rhs))
	return state.WithPath(path), nil
}

// Branch follows both successors of a conditional jump, narrowing the taken == branch.
func (i *JMP) Branch(state *symbolic.State) ([]Branch, error) {
	op, err := i.jumpOp()
	if err != nil {
		return nil, err
	}
	if op == "none" {
		return []Branch{{PC: i.at(int(i.b.K)), State: state}}, nil
	}
	if i.b.Jt == i.b.Jf {
		return []Branch{{PC: i.at(int(i.b.Jt)), State: state}}, nil
	}
	if op == "==" {
		narrowed, err := i.narrow(state)
		if err != nil {
			return nil, err
		}
		return []Branch{
			{PC: i.at(int(i.b.Jt)), State: narrowed},
			{PC: i.at(int(i.b.Jf)), State: state},
		}, nil
	}
	return []Branch{
		{PC: i.at(int(i.b.Jt)), State: state},
		{PC: i.at(int(i.b.Jf)), State: state},
	}, nil
}
