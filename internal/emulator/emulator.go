// Package emulator runs a seccomp filter once against a hypothetical syscall.
package emulator

import (
	"fmt"

	"seccompgo/internal/consts"
	"seccompgo/internal/instruction"
	"seccompgo/internal/util"
)

// Emulator holds the filter and the concrete input to run it with.
type Emulator struct {
	instructions []instruction.Inst
	sysNr        *uint64
	args         []uint64
	ip           *uint64
	arch         uint32
	archKnown    bool
	bigEndian    bool
}

// New builds an emulator. sysNr, ip and args entries may be nil/absent; reading them
// during the run then raises an undefined-variable error.
func New(insts []instruction.Inst, sysNr *uint64, args []uint64, ip *uint64, arch string) *Emulator {
	if arch == "" {
		arch = util.SystemArch()
	}
	val, known := consts.AuditArchValue(arch)
	return &Emulator{
		instructions: insts,
		sysNr:        sysNr,
		args:         args,
		ip:           ip,
		arch:         val,
		archKnown:    known,
		bigEndian:    consts.BigEndian(arch),
	}
}

// Result is the final machine state.
type Result struct {
	Ret    uint32
	HasRet bool
	PC     uint32
	A      uint32
	X      uint32
	Mem    map[uint32]uint32
}

// UndefinedVariableError matches upstream's runtime error text.
type UndefinedVariableError struct {
	PC   uint32
	Inst string
	Var  string
}

func (e *UndefinedVariableError) Error() string {
	return fmt.Sprintf("Undefined Variable\n\t%04d: %s <- `%s` is undefined", e.PC, e.Inst, e.Var)
}

// Run executes until the filter returns.
func (e *Emulator) Run() (*Result, error) {
	var pc, a, x uint32
	mem := [16]uint32{}
	memSet := [16]bool{}
	var ret uint32
	returned := false

	for {
		if int(pc) >= len(e.instructions) {
			return nil, fmt.Errorf("Line %d is out of range", pc)
		}
		inst := e.instructions[pc]
		sym, err := inst.Symbolize()
		if err != nil {
			return nil, err
		}
		switch sym.Kind {
		case instruction.KindRet:
			if sym.IsA {
				ret = a
			} else {
				ret = sym.Val
			}
			returned = true
		case instruction.KindLD:
			var val uint32
			switch sym.Rel {
			case instruction.RelImm:
				val = sym.Val
			case instruction.RelMem:
				if sym.Val < 16 {
					val = mem[sym.Val]
				}
			case instruction.RelData:
				v, err := e.dataOf(sym.Val, pc, inst)
				if err != nil {
					return nil, err
				}
				val = v
			}
			if sym.Dst == "x" {
				x = val
			} else {
				a = val
			}
		case instruction.KindST:
			if sym.Val >= 16 {
				return nil, fmt.Errorf("Expect 0 <= index < 16, got: %d", sym.Val)
			}
			if sym.Dst == "x" {
				mem[sym.Val] = x
			} else {
				mem[sym.Val] = a
			}
			memSet[sym.Val] = true
		case instruction.KindJmp:
			pc += sym.Val + 1
		case instruction.KindCmp:
			src := sym.Val
			if sym.SrcX {
				src = x
			}
			var truth bool
			switch sym.Op {
			case "==":
				truth = a == src
			case ">":
				truth = a > src
			case ">=":
				truth = a >= src
			case "&":
				truth = (a & src) != 0
			}
			j := sym.Jf
			if truth {
				j = sym.Jt
			}
			pc += uint32(j) + 1
		case instruction.KindALU:
			if sym.Op == "neg" {
				a = -a
			} else {
				src := sym.Val
				if sym.SrcX {
					src = x
				}
				if sym.Op == "/" && src == 0 {
					// Classic BPF aborts the whole program on division by zero.
					ret = consts.Action[1].Value // KILL_THREAD
					returned = true
					break
				}
				a = alu(a, sym.Op, src)
			}
		case instruction.KindMisc:
			if sym.Misc == "txa" {
				a = x
			} else {
				x = a
			}
		}
		if returned {
			break
		}
		switch sym.Kind {
		case instruction.KindLD, instruction.KindST, instruction.KindALU, instruction.KindMisc:
			pc++
		}
	}
	res := &Result{Ret: ret, HasRet: returned, PC: pc, A: a, X: x, Mem: map[uint32]uint32{}}
	for i := range mem {
		if memSet[i] {
			res.Mem[uint32(i)] = mem[i]
		}
	}
	return res, nil
}

func alu(a uint32, op string, src uint32) uint32 {
	switch op {
	case "+":
		return a + src
	case "-":
		return a - src
	case "*":
		return a * src
	case "/":
		return a / src
	case "|":
		return a | src
	case "&":
		return a & src
	case "<<":
		if src >= 32 {
			return 0
		}
		return a << src
	case ">>":
		if src >= 32 {
			return 0
		}
		return a >> src
	case "^":
		return a ^ src
	}
	return 0
}

func (e *Emulator) dataOf(index uint32, pc uint32, inst instruction.Inst) (uint32, error) {
	if index&3 != 0 || index >= consts.Size {
		return 0, fmt.Errorf("Invalid index: %d", index)
	}
	word := index / 4
	switch word {
	case 0:
		if e.sysNr == nil {
			return 0, e.undefined(pc, inst, consts.SeccompDataNames[consts.SysNumber])
		}
		return uint32(*e.sysNr), nil
	case 1:
		if !e.archKnown {
			return 0, e.undefined(pc, inst, consts.SeccompDataNames[consts.Arch])
		}
		return e.arch, nil
	case 2, 3:
		if e.ip == nil {
			return 0, e.undefined(pc, inst, consts.SeccompDataNames[consts.InstructionPointer])
		}
		return e.wordOf(*e.ip, word), nil
	default:
		argIdx := (word - 4) / 2
		if argIdx >= uint32(len(e.args)) {
			return 0, e.undefined(pc, inst, fmt.Sprintf("args[%d]", argIdx))
		}
		return e.wordOf(e.args[argIdx], word), nil
	}
}

// wordOf returns the 32-bit word at word-index index: the high half comes second on
// little-endian architectures but first on big-endian ones.
func (e *Emulator) wordOf(val uint64, index uint32) uint32 {
	hi := (index%2 == 1) != e.bigEndian
	if hi {
		return uint32(val >> 32)
	}
	return uint32(val)
}

func (e *Emulator) undefined(pc uint32, inst instruction.Inst, name string) error {
	text, err := inst.Decompile()
	if err != nil {
		text = ""
	}
	return &UndefinedVariableError{PC: pc, Inst: text, Var: name}
}
