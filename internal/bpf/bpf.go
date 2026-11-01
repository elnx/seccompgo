// Package bpf models one classic-BPF instruction (struct sock_filter).
package bpf

import (
	"encoding/binary"
	"fmt"

	"github.com/elnx/seccompgo/internal/consts"
	"github.com/elnx/seccompgo/internal/symbolic"
)

// BPF is one BPF instruction plus the architecture and line it belongs to.
type BPF struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32

	Arch string
	Line int

	// States are the symbolic states that can reach this line (filled by disasm).
	States []*symbolic.State

	// ShowArgInfer annotates argument loads with syscall parameter names.
	ShowArgInfer bool
}

// FromRaw parses one 8-byte sock_filter in arch's byte order.
func FromRaw(raw []byte, arch string, line int) (*BPF, error) {
	if len(raw) < 8 {
		return nil, fmt.Errorf("short BPF instruction: %d bytes", len(raw))
	}
	order := binary.ByteOrder(binary.LittleEndian)
	if consts.BigEndian(arch) {
		order = binary.BigEndian
	}
	return &BPF{
		Code:         order.Uint16(raw[0:2]),
		Jt:           raw[2],
		Jf:           raw[3],
		K:            order.Uint32(raw[4:8]),
		Arch:         arch,
		Line:         line,
		ShowArgInfer: true,
	}, nil
}

// FromFields builds an instruction from its four fields.
func FromFields(code uint16, jt, jf uint8, k uint32, arch string, line int) *BPF {
	return &BPF{Code: code, Jt: jt, Jf: jf, K: k, Arch: arch, Line: line, ShowArgInfer: true}
}

// Asm serializes the instruction in arch's byte order.
func (b *BPF) Asm() []byte {
	out := make([]byte, 8)
	order := binary.ByteOrder(binary.LittleEndian)
	if consts.BigEndian(b.Arch) {
		order = binary.BigEndian
	}
	order.PutUint16(out[0:2], b.Code)
	out[2] = b.Jt
	out[3] = b.Jf
	order.PutUint32(out[4:8], b.K)
	return out
}

// Command returns the instruction class name, or false for an invalid code.
func (b *BPF) Command() (string, bool) {
	switch b.Code & 7 {
	case 0:
		return "ld", true
	case 1:
		return "ldx", true
	case 2:
		return "st", true
	case 3:
		return "stx", true
	case 4:
		return "alu", true
	case 5:
		return "jmp", true
	case 6:
		return "ret", true
	case 7:
		return "misc", true
	}
	return "", false
}
