package instruction

import (
	"fmt"

	"github.com/elnx/seccompgo/internal/consts"
	"github.com/elnx/seccompgo/internal/symbolic"
)

// RET terminates the filter.
type RET struct {
	base
}

// Decompile renders the return.
func (i *RET) Decompile() (string, error) {
	s, err := i.Symbolize()
	if err != nil {
		return "", err
	}
	if s.IsA {
		return "return A", nil
	}
	if label, ok := consts.ActionLabel(s.Val); ok {
		return "return " + label, nil
	}
	return fmt.Sprintf("return 0x%x", s.Val), nil
}

// Symbolize returns whether the action comes from A, and the immediate value.
func (i *RET) Symbolize() (Sym, error) {
	return Sym{Kind: KindRet, IsA: i.b.Code&0x18 == consts.Src["a"], Val: i.b.K}, nil
}

// Branch returns no successors: a filter stops at a return.
func (i *RET) Branch(*symbolic.State) ([]Branch, error) {
	return nil, nil
}
