package instruction

import (
	"fmt"

	"github.com/elnx/seccompgo/internal/symbolic"
)

// ST stores A (or X, when x is set) into a scratch slot.
type ST struct {
	base
	x bool
}

// Reg is the stored register name.
func (i *ST) Reg() string {
	if i.x {
		return "X"
	}
	return "A"
}

// Decompile renders the store.
func (i *ST) Decompile() (string, error) {
	return fmt.Sprintf("mem[%d] = %s", i.b.K, i.Reg()), nil
}

// Symbolize returns the source register and slot index.
func (i *ST) Symbolize() (Sym, error) {
	dst := "a"
	if i.x {
		dst = "x"
	}
	return Sym{Kind: KindST, Dst: dst, Val: i.b.K}, nil
}

// Branch records the register's value in the slot.
func (i *ST) Branch(state *symbolic.State) ([]Branch, error) {
	mem := state.Mem()
	if i.b.K < 16 {
		if i.x {
			mem[i.b.K] = state.X()
		} else {
			mem[i.b.K] = state.A()
		}
	}
	return []Branch{{PC: i.b.Line + 1, State: state.WithMem(mem)}}, nil
}
