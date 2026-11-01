package instruction

import (
	"github.com/elnx/seccompgo/internal/symbolic"
)

// MISC copies between A and X.
type MISC struct {
	base
}

func (i *MISC) op() (string, error) {
	switch i.b.Code & 0xf8 {
	case 0x00:
		return "tax", nil
	case 0x80:
		return "txa", nil
	}
	return "", i.invalid("MISC operation only supports txa/tax")
}

// Decompile renders the copy.
func (i *MISC) Decompile() (string, error) {
	op, err := i.op()
	if err != nil {
		return "", err
	}
	if op == "txa" {
		return "A = X", nil
	}
	return "X = A", nil
}

// Symbolize returns the operation.
func (i *MISC) Symbolize() (Sym, error) {
	op, err := i.op()
	if err != nil {
		return Sym{}, err
	}
	return Sym{Kind: KindMisc, Misc: op}, nil
}

// Branch copies the value between registers.
func (i *MISC) Branch(state *symbolic.State) ([]Branch, error) {
	op, err := i.op()
	if err != nil {
		return nil, err
	}
	if op == "txa" {
		return []Branch{{PC: i.b.Line + 1, State: state.WithA(state.X())}}, nil
	}
	return []Branch{{PC: i.b.Line + 1, State: state.WithX(state.A())}}, nil
}
