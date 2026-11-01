package consts

import (
	"fmt"
	"strings"
)

// SysEntry is one name/number pair of a syscall table.
type SysEntry struct {
	Name string
	Num  uint32
}

var (
	syscallNameMaps    = map[string]map[string]uint32{}
	syscallReverseMaps = map[string]map[uint32]string{}
	allSyscallNames    []string
)

func init() {
	for _, arch := range SyscallTableOrder {
		entries := SyscallTables[arch]
		byName := make(map[string]uint32, len(entries))
		byNum := make(map[uint32]string, len(entries))
		for _, e := range entries {
			// Source order, matching Ruby's Hash: a later key with the same value wins
			// under Hash#invert (amd64's pread/pread64 alias is the visible case).
			byName[e.Name] = e.Num
			byNum[e.Num] = e.Name
		}
		syscallNameMaps[arch] = byName
		syscallReverseMaps[arch] = byNum
	}
	seen := map[string]bool{}
	for _, arch := range SyscallTableOrder {
		for _, e := range SyscallTables[arch] {
			if !seen[e.Name] {
				seen[e.Name] = true
				allSyscallNames = append(allSyscallNames, e.Name)
			}
		}
	}
}

// SyscallName returns the name for nr in arch, or false when unknown.
func SyscallName(arch string, nr uint32) (string, bool) {
	m := syscallReverseMaps[arch]
	if m == nil {
		return "", false
	}
	name, ok := m[nr]
	return name, ok
}

// SyscallNum returns the number of name in arch, or false when unknown.
func SyscallNum(arch, name string) (uint32, bool) {
	m := syscallNameMaps[arch]
	if m == nil {
		return 0, false
	}
	n, ok := m[name]
	return n, ok
}

// HasSyscallTable reports whether arch has a syscall table.
func HasSyscallTable(arch string) bool {
	_, ok := SyscallTables[arch]
	return ok
}

// SyscallNames returns arch's syscall names in table order.
func SyscallNames(arch string) []string {
	entries := SyscallTables[arch]
	if entries == nil {
		return nil
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name
	}
	return names
}

// AllSyscallNames returns the union of every architecture's names, in table order.
func AllSyscallNames() []string { return allSyscallNames }

// ArgNames returns the argument names of a syscall, or nil. An x32_-prefixed name falls
// back to its native prototype, as upstream does.
func ArgNames(name string) []string {
	if args, ok := SyscallArgs[name]; ok {
		return args
	}
	if after, ok := strings.CutPrefix(name, "x32_"); ok {
		if args, ok := SyscallArgs[after]; ok {
			return args
		}
	}
	return nil
}

// SeccompData field offsets of struct seccomp_data.
const (
	SysNumber          = 0
	Arch               = 4
	InstructionPointer = 8
	Args               = 16
	Size               = 64
)

// QwordBases are the byte offsets of the 64-bit fields (ip and six args).
var QwordBases = []uint32{InstructionPointer, 16, 24, 32, 40, 48, 56}

// SeccompDataNames names the fixed (non-argument) seccomp_data fields.
var SeccompDataNames = map[uint32]string{
	SysNumber:          "sys_number",
	Arch:               "arch",
	InstructionPointer: "instruction_pointer",
}

// BPF option constants.
const (
	PRSetSeccomp = 22

	SeccompModeStrict = 1
	SeccompModeFilter = 2

	SeccompSetModeStrict = 0
	SeccompSetModeFilter = 1

	RetActionFull = 0xffff0000
	RetData       = 0x0000ffff
)

// COMMAND maps BPF instruction classes.
var Command = map[string]uint16{
	"ld": 0x0, "ldx": 0x1, "st": 0x2, "stx": 0x3,
	"alu": 0x4, "jmp": 0x5, "ret": 0x6, "misc": 0x7,
}

// Jmp maps jmp operation names.
var Jmp = map[string]uint16{
	"ja": 0x00, "jeq": 0x10, "jgt": 0x20, "jge": 0x30, "jset": 0x40,
}

// Src maps source-register names.
var Src = map[string]uint16{"k": 0x0, "x": 0x8, "a": 0x10}

// Mode maps ld/ldx addressing modes.
var Mode = map[string]uint16{
	"imm": 0x00, "abs": 0x20, "ind": 0x40, "mem": 0x60, "len": 0x80, "msh": 0xa0,
}

// Op maps ALU operation names. BPF_MOD (0x90) is intentionally absent: the kernel's
// seccomp_check_filter rejects it, so it can never appear in a loadable filter.
var Op = map[string]uint16{
	"add": 0x00, "sub": 0x10, "mul": 0x20, "div": 0x30,
	"or": 0x40, "and": 0x50, "lsh": 0x60, "rsh": 0x70,
	"neg": 0x80, "xor": 0xa0,
}

// MiscOp maps misc operation names.
var MiscOp = map[string]uint16{"tax": 0x00, "txa": 0x80}

// Action maps the kernel's return actions. KILL_THREAD and KILL share a value; the
// reverse lookup below keeps the last one, so 0 renders as KILL as upstream does.
var Action = []struct {
	Name  string
	Value uint32
}{
	{"KILL_PROCESS", 0x80000000},
	{"KILL_THREAD", 0x00000000},
	{"KILL", 0x00000000},
	{"TRAP", 0x00030000},
	{"ERRNO", 0x00050000},
	{"USER_NOTIF", 0x7fc00000},
	{"LOG", 0x7ffc0000},
	{"TRACE", 0x7ff00000},
	{"ALLOW", 0x7fff0000},
}

var actionByName = func() map[string]uint32 {
	m := make(map[string]uint32, len(Action))
	for _, a := range Action {
		m[a.Name] = a.Value
	}
	return m
}()

var actionByValue = func() map[uint32]string {
	m := make(map[uint32]string, len(Action))
	for _, a := range Action {
		m[a.Value] = a.Name
	}
	return m
}()

// ActionValue returns the numeric value of an action name.
func ActionValue(name string) (uint32, bool) {
	v, ok := actionByName[name]
	return v, ok
}

// ActionName returns the bare action name of a return value, without its data part.
func ActionName(value uint32) (string, bool) {
	name, ok := actionByValue[value&RetActionFull]
	return name, ok
}

// ActionLabel names a seccomp return value, e.g. "ALLOW" or "ERRNO(5)", or returns
// false when the action bits are not a kernel-defined value.
func ActionLabel(value uint32) (string, bool) {
	name, ok := actionByValue[value&RetActionFull]
	if !ok {
		return "", false
	}
	data := value & RetData
	switch name {
	case "ERRNO":
		return fmt.Sprintf("ERRNO(%d)", data), true
	case "TRACE", "TRAP":
		if data == 0 {
			return name, true
		}
		return fmt.Sprintf("%s(%d)", name, data), true
	default:
		return name, true
	}
}

// AuditArchName maps an architecture name to its AUDIT_ARCH_* constant name.
var AuditArchName = map[string]string{
	"amd64":   "ARCH_X86_64",
	"i386":    "ARCH_I386",
	"aarch64": "ARCH_AARCH64",
	"riscv64": "ARCH_RISCV64",
	"s390x":   "ARCH_S390X",
}

// AuditArch maps an AUDIT_ARCH_* constant name to its value.
var AuditArch = map[string]uint32{
	"ARCH_X86_64":  0xc000003e,
	"ARCH_I386":    0x40000003,
	"ARCH_AARCH64": 0xc00000b7,
	"ARCH_RISCV64": 0xc00000f3,
	"ARCH_S390X":   0x80000016,
}

// AuditArchOrder is the source order of AuditArch, which the scanner's alternation uses.
var AuditArchOrder = []string{
	"ARCH_X86_64", "ARCH_I386", "ARCH_AARCH64", "ARCH_RISCV64", "ARCH_S390X",
}

// AuditArchSymbol maps an AUDIT_ARCH_* value to an architecture name, or false.
func AuditArchSymbol(val uint32) (string, bool) {
	for name, v := range AuditArch {
		if v == val {
			return auditNameToArch(name), true
		}
	}
	return "", false
}

func auditNameToArch(name string) string {
	for arch, n := range AuditArchName {
		if n == name {
			return arch
		}
	}
	return ""
}

// AuditArchValue returns the AUDIT_ARCH_* value for an architecture name.
func AuditArchValue(arch string) (uint32, bool) {
	name, ok := AuditArchName[arch]
	if !ok {
		return 0, false
	}
	v, ok := AuditArch[name]
	return v, ok
}

// AuditArchLE is __AUDIT_ARCH_LE: set iff the architecture is little-endian.
const AuditArchLE = 0x40000000

// BigEndian reports whether arch stores the high 32-bit word of a 64-bit seccomp_data
// field first.
func BigEndian(arch string) bool {
	val, ok := AuditArchValue(arch)
	if !ok {
		return false
	}
	return val&AuditArchLE == 0
}

// SupportedArchs is every architecture with a syscall table, sorted.
var SupportedArchs = []string{"aarch64", "amd64", "i386", "riscv64", "s390x"}

// ABITableOrder is the architecture order of the ptrace ABI table.
var ABITableOrder = []string{"amd64", "i386", "aarch64", "riscv64", "s390x"}
