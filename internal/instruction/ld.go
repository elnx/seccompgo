package instruction

import (
	"fmt"

	"seccompgo/internal/consts"
	"seccompgo/internal/symbolic"
	"seccompgo/internal/util"
)

// LD loads a value into A (or X, when x is set).
type LD struct {
	base
	x bool
}

// Reg is the destination register name.
func (i *LD) Reg() string {
	if i.x {
		return "X"
	}
	return "A"
}

// mode returns "imm", "abs", "mem" or "len"; seccomp rejects ind/msh.
func (i *LD) mode() (string, error) {
	switch i.b.Code & 0xe0 {
	case 0x00:
		return "imm", nil
	case 0x20:
		return "abs", nil
	case 0x60:
		return "mem", nil
	case 0x80:
		return "len", nil
	}
	return "", i.invalid("unknown")
}

func (i *LD) loadVal() (Rel, uint32, error) {
	mode, err := i.mode()
	if err != nil {
		return RelImm, 0, err
	}
	switch mode {
	case "imm":
		return RelImm, i.b.K, nil
	case "len":
		return RelImm, consts.Size, nil
	case "mem":
		return RelMem, i.b.K, nil
	default:
		return RelData, i.b.K, nil
	}
}

func (i *LD) hiWord(k uint32) bool {
	return (k%8 == 4) != consts.BigEndian(i.b.Arch)
}

func (i *LD) argsName(idx int) string {
	k := uint32(idx*4) + consts.Args
	hi := i.hiWord(k)
	def := fmt.Sprintf("args[%d]", idx/2)
	if hi {
		def += " >> 32"
	}
	type pin struct {
		val uint32
		ok  bool
	}
	var pins []pin
	for _, st := range i.b.States {
		v, ok := st.Pinned(consts.SysNumber)
		p := pin{v, ok}
		dup := false
		for _, q := range pins {
			if q == p {
				dup = true
				break
			}
		}
		if !dup {
			pins = append(pins, p)
		}
	}
	if len(pins) != 1 || !pins[0].ok {
		return def
	}
	a := i.inferArch()
	if a == "" {
		a = i.b.Arch
	}
	sys, ok := consts.SyscallName(a, pins[0].val)
	if !ok {
		return def
	}
	args := consts.ArgNames(sys)
	if args == nil || idx/2 >= len(args) {
		return def
	}
	name := sys
	if a != i.b.Arch {
		name = a + "." + sys
	}
	comment := fmt.Sprintf("# %s(%s)", name, joinComma(args))
	argName := util.Colorize(args[idx/2], "args")
	out := argName
	if hi {
		out += " >> 32"
	}
	return out + " " + util.Colorize(comment, "gray")
}

func joinComma(xs []string) string {
	out := ""
	for j, x := range xs {
		if j > 0 {
			out += ", "
		}
		out += x
	}
	return out
}

func (i *LD) seccompDataStr() string {
	switch i.b.K {
	case consts.SysNumber, consts.Arch:
		return consts.SeccompDataNames[i.b.K]
	case consts.InstructionPointer, consts.InstructionPointer + 4:
		name := consts.SeccompDataNames[consts.InstructionPointer]
		if i.hiWord(i.b.K) {
			return name + " >> 32"
		}
		return name
	}
	k := i.b.K
	if k < consts.Args || k >= consts.Size || (k-consts.Args)%4 != 0 {
		return "INVALID"
	}
	idx := int((k - consts.Args) / 4)
	if !i.b.ShowArgInfer {
		if i.hiWord(k) {
			return fmt.Sprintf("args[%d] >> 32", idx/2)
		}
		return fmt.Sprintf("args[%d]", idx/2)
	}
	return i.argsName(idx)
}

// Decompile renders the assignment.
func (i *LD) Decompile() (string, error) {
	ret := i.Reg() + " = "
	rel, val, err := i.loadVal()
	if err != nil {
		return "", err
	}
	switch rel {
	case RelImm:
		return ret + fmt.Sprintf("%d", val), nil
	case RelMem:
		return ret + fmt.Sprintf("mem[%d]", val), nil
	default:
		return ret + i.seccompDataStr(), nil
	}
}

// Symbolize returns the destination and loaded value.
func (i *LD) Symbolize() (Sym, error) {
	rel, val, err := i.loadVal()
	if err != nil {
		return Sym{}, err
	}
	dst := "a"
	if i.x {
		dst = "x"
	}
	return Sym{Kind: KindLD, Dst: dst, Rel: rel, Val: val}, nil
}

// Branch records the loaded value in the destination register.
func (i *LD) Branch(state *symbolic.State) ([]Branch, error) {
	rel, val, err := i.loadVal()
	if err != nil {
		return nil, err
	}
	var e *symbolic.Expr
	switch rel {
	case RelImm:
		e = symbolic.Imm(uint64(val))
	case RelMem:
		if val < 16 {
			e = state.Mem()[val]
		} else {
			e = symbolic.Opaque()
		}
	default:
		e = symbolic.DataWord(val)
	}
	if i.x {
		return []Branch{{PC: i.b.Line + 1, State: state.WithX(e)}}, nil
	}
	return []Branch{{PC: i.b.Line + 1, State: state.WithA(e)}}, nil
}
