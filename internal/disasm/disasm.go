// Package disasm turns raw seccomp BPF into human-readable assembly.
package disasm

import (
	"fmt"
	"strings"

	"seccompgo/internal/bpf"
	"seccompgo/internal/instruction"
	"seccompgo/internal/symbolic"
	"seccompgo/internal/util"
)

// ToBPF splits raw into 8-byte instructions. A trailing partial instruction is ignored,
// matching upstream's raw.scan(/.{8}/m).
func ToBPF(raw []byte, arch string) ([]*bpf.BPF, error) {
	if arch == "" {
		arch = util.SystemArch()
	}
	n := len(raw) / 8
	out := make([]*bpf.BPF, 0, n)
	for i := range n {
		b, err := bpf.FromRaw(raw[i*8:(i+1)*8], arch, i)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

type stateSet struct {
	list []*symbolic.State
	seen map[string]bool
}

func (s *stateSet) add(st *symbolic.State) {
	key := st.Key()
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	if s.seen[key] {
		return
	}
	s.seen[key] = true
	s.list = append(s.list, st)
}

// Disasm renders raw BPF.
func Disasm(raw []byte, arch string, displayBPF, argInfer bool) (string, error) {
	codes, err := ToBPF(raw, arch)
	if err != nil {
		return "", err
	}
	states := make([]*stateSet, len(codes))
	for i := range states {
		states[i] = &stateSet{}
	}
	if len(codes) > 0 {
		states[0].add(symbolic.Initial())
	}
	lines := make([]string, 0, len(codes))
	for i, code := range codes {
		code.ShowArgInfer = argInfer
		sts := states[i].list
		inst, err := instruction.New(code)
		if err != nil {
			return "", err
		}
		for _, st := range sts {
			branches, err := inst.Branch(st)
			if err != nil {
				return "", err
			}
			for _, br := range branches {
				if br.PC >= 0 && br.PC < len(states) {
					states[br.PC].add(br.State)
				}
			}
		}
		code.States = sts
		text, err := inst.Decompile()
		if err != nil {
			return "", err
		}
		if displayBPF {
			lines = append(lines, fmt.Sprintf(" %04d: 0x%02x 0x%02x 0x%02x 0x%08x  %s",
				code.Line, code.Code, code.Jt, code.Jf, code.K, text))
		} else {
			lines = append(lines, fmt.Sprintf("%04d: %s", code.Line, text))
		}
	}
	dis := strings.Join(lines, "\n")
	if displayBPF {
		return " line  CODE  JT   JF      K\n=================================\n" + dis + "\n", nil
	}
	return dis + "\n", nil
}
