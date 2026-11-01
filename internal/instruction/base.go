// Package instruction implements one Go type per classic-BPF opcode class. Each knows
// how to render itself as assembly, symbolize itself for interpreters, and move the
// symbolic state forward.
package instruction

import (
	"fmt"
	"slices"

	"github.com/elnx/seccompgo/internal/bpf"
	"github.com/elnx/seccompgo/internal/consts"
	"github.com/elnx/seccompgo/internal/symbolic"
)

// Kind is the shape of a symbolized instruction.
type Kind int

const (
	KindRet Kind = iota
	KindLD
	KindST
	KindJmp
	KindCmp
	KindALU
	KindMisc
)

// Rel describes what a load/store operand refers to.
type Rel int

const (
	RelImm Rel = iota
	RelMem
	RelData
)

// Sym is the interpreter-facing form of an instruction.
type Sym struct {
	Kind Kind

	// Dst is "a" or "x" for load/store instructions; IsA is the return-from-A flag.
	Dst string
	IsA bool

	// Val is the immediate, memory index, data offset, jump distance, or return value.
	Val uint32
	Rel Rel

	// Jt and Jf are the branch distances of a comparison.
	Jt uint8
	Jf uint8

	// Op is a comparison/ALU operator. SrcX selects the X register as the right operand;
	// HasOperand is false only for the unary ALU neg.
	Op         string
	SrcX       bool
	HasOperand bool

	// Misc is "tax" or "txa".
	Misc string
}

// Branch is one possible successor of an instruction.
type Branch struct {
	PC    int
	State *symbolic.State
}

// Inst is a decoded instruction.
type Inst interface {
	Decompile() (string, error)
	Symbolize() (Sym, error)
	Branch(*symbolic.State) ([]Branch, error)
}

// New decodes b according to its command class.
func New(b *bpf.BPF) (Inst, error) {
	cmd, ok := b.Command()
	if !ok {
		return nil, fmt.Errorf("Line %d is invalid: unknown command", b.Line)
	}
	switch cmd {
	case "alu":
		return &ALU{b: b}, nil
	case "jmp":
		return &JMP{b: b}, nil
	case "ld":
		return &LD{b: b, x: false}, nil
	case "ldx":
		return &LD{b: b, x: true}, nil
	case "misc":
		return &MISC{b: b}, nil
	case "ret":
		return &RET{b: b}, nil
	case "st":
		return &ST{b: b, x: false}, nil
	case "stx":
		return &ST{b: b, x: true}, nil
	}
	return nil, fmt.Errorf("Line %d is invalid: unknown command", b.Line)
}

type base struct {
	b *bpf.BPF
}

func (i *base) invalid(msg string) error {
	return fmt.Errorf("Line %d is invalid: %s", i.b.Line, msg)
}

// inferArch returns the architecture the reaching states pin on data[4], when they
// agree on a single known value; otherwise "".
func (i *base) inferArch() string {
	type pin struct {
		val uint32
		ok  bool
	}
	var pins []pin
	for _, st := range i.b.States {
		v, ok := st.Pinned(consts.Arch)
		p := pin{v, ok}
		found := slices.Contains(pins, p)
		if !found {
			pins = append(pins, p)
		}
	}
	if len(pins) != 1 || !pins[0].ok {
		return ""
	}
	arch, _ := consts.AuditArchSymbol(pins[0].val)
	return arch
}

// uniqueA returns the distinct A expressions reaching this line, in insertion order.
func (i *base) uniqueA() []*symbolic.Expr {
	var out []*symbolic.Expr
	for _, st := range i.b.States {
		a := st.A()
		found := false
		for _, e := range out {
			if e.Equal(a) {
				found = true
				break
			}
		}
		if !found {
			out = append(out, a)
		}
	}
	return out
}
