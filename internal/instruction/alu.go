package instruction

import (
	"fmt"

	"github.com/elnx/seccompgo/internal/symbolic"
)

// ALU performs an arithmetic or bitwise operation on A.
type ALU struct {
	base
}

var aluOpSym = map[string]string{
	"add": "+", "sub": "-", "mul": "*", "div": "/", "or": "|",
	"and": "&", "lsh": "<<", "rsh": ">>", "xor": "^",
}

func (i *ALU) op() (string, error) {
	switch i.b.Code & 0xf0 {
	case 0x00:
		return "add", nil
	case 0x10:
		return "sub", nil
	case 0x20:
		return "mul", nil
	case 0x30:
		return "div", nil
	case 0x40:
		return "or", nil
	case 0x50:
		return "and", nil
	case 0x60:
		return "lsh", nil
	case 0x70:
		return "rsh", nil
	case 0x80:
		return "neg", nil
	case 0xa0:
		return "xor", nil
	}
	return "", i.invalid("unknown op")
}

func (i *ALU) srcX() bool { return i.b.Code&0x8 != 0 }

func (i *ALU) srcStr(op string) string {
	if i.srcX() {
		return "X"
	}
	if op == "lsh" || op == "rsh" {
		return fmt.Sprintf("%d", i.b.K)
	}
	return fmt.Sprintf("0x%x", i.b.K)
}

// Decompile renders the operation as assembly.
func (i *ALU) Decompile() (string, error) {
	op, err := i.op()
	if err != nil {
		return "", err
	}
	if op == "neg" {
		return "A = -A", nil
	}
	return fmt.Sprintf("A %s= %s", aluOpSym[op], i.srcStr(op)), nil
}

// Symbolize returns the operator and its right operand (nil for neg).
func (i *ALU) Symbolize() (Sym, error) {
	op, err := i.op()
	if err != nil {
		return Sym{}, err
	}
	if op == "neg" {
		return Sym{Kind: KindALU, Op: "neg"}, nil
	}
	s := Sym{Kind: KindALU, Op: aluOpSym[op], SrcX: i.srcX(), HasOperand: true}
	if !s.SrcX {
		s.Val = i.b.K
	}
	return s, nil
}

// Branch always moves to the next line, with A no longer tracked.
func (i *ALU) Branch(state *symbolic.State) ([]Branch, error) {
	return []Branch{{PC: i.b.Line + 1, State: state.WithA(symbolic.Opaque())}}, nil
}
