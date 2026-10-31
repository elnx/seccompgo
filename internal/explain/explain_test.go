package explain_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"seccompgo/internal/asm"
	"seccompgo/internal/disasm"
	"seccompgo/internal/explain"
	"seccompgo/internal/instruction"
)

func load(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func instsOf(t *testing.T, raw []byte, arch string) []instruction.Inst {
	t.Helper()
	codes, err := disasm.ToBPF(raw, arch)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]instruction.Inst, 0, len(codes))
	for _, c := range codes {
		i, err := instruction.New(c)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, i)
	}
	return out
}

func summarize(t *testing.T, raw []byte, arch string) string {
	t.Helper()
	summary, err := explain.NewExplain(instsOf(t, raw, arch), arch, nil).Summarize()
	if err != nil {
		t.Fatal(err)
	}
	return summary.String()
}

func summarizeAsm(t *testing.T, src, arch string) string {
	t.Helper()
	raw, err := asm.Asm(src, "", arch)
	if err != nil {
		t.Fatal(err)
	}
	return summarize(t, raw, arch)
}

func TestExplainGoldens(t *testing.T) {
	cases := []struct {
		name, raw, arch, gold string
	}{
		{"openssh", "../../testdata/data/openssh-preauth.bpf", "amd64", "explain_openssh.txt"},
		{"libseccomp", "../../testdata/data/libseccomp.bpf", "amd64", "explain_libseccomp.txt"},
		{"diary", "../../testdata/data/twctf-2016-diary.bpf", "amd64", "explain_diary.txt"},
		{"tctf", "../../testdata/data/tctf-2023-nothing-is-true.bpf", "amd64", "explain_tctf.txt"},
		{"complex", "../../testdata/data/complex.asm", "amd64", "explain_complex.txt"},
		{"simple", "", "amd64", "explain_simple.txt"},
		{"returnA", "", "amd64", "explain_returnA.txt"},
		{"range", "../../testdata/asm/range.asm", "amd64", "explain_range.txt"},
		{"other", "../../testdata/asm/other.asm", "amd64", "explain_other.txt"},
		{"unknown", "../../testdata/asm/unknown.asm", "amd64", "explain_unknown.txt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			switch {
			case tc.name == "simple":
				got = summarizeAsm(t, "return ALLOW\n", "amd64")
			case tc.name == "returnA":
				got = summarizeAsm(t, "return A\n", "amd64")
			case strings.HasSuffix(tc.raw, ".asm"):
				got = summarizeAsm(t, string(load(t, tc.raw)), tc.arch)
			default:
				got = summarize(t, load(t, tc.raw), tc.arch)
			}
			want := string(load(t, filepath.Join("..", "..", "testdata", "golden", tc.gold)))
			if got != want {
				t.Fatalf("mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
			}
		})
	}
}

func TestExplainSubstrings(t *testing.T) {
	operator := summarizeAsm(t, string(load(t, "../../testdata/data/operator_precedence.asm")), "amd64")
	for _, want := range []string{
		"read when count == ((fd | 0x1) & 0xff)",
		"write when count >> 4 == (buf << 2) + 0x8",
		"openat when (flags & 0xf) < 0x5",
		"close when (fd & 0x101) != 0",
		"lseek when whence == ((fd ^ 0xff) | 0x1)",
		"poll when timeout == (ufds ^ 0xff ^ 0x1)",
		"fstat when (fd & (args[2] + 0x1)) == 0x5",
		"dup2 when (oldfd + newfd) << 2 == 0x100",
		"getpid when args[0] + args[1] * 0x8 == 0x40",
	} {
		if !strings.Contains(operator, want) {
			t.Errorf("missing %q\n%s", want, operator)
		}
	}
	if got := summarizeAsm(t, string(load(t, "../../testdata/asm/conditional.asm")), "amd64"); !strings.Contains(got,
		"any syscall when (args[0] & 0xffff) == 0x5") {
		t.Errorf("conditional: %s", got)
	}
	if got := summarizeAsm(t, string(load(t, "../../testdata/asm/bittest.asm")), "amd64"); !strings.Contains(got,
		"any syscall when (sys_number & 0x1) != 0") {
		t.Errorf("bittest: %s", got)
	}
	if got := summarizeAsm(t, string(load(t, "../../testdata/asm/archbit.asm")), "amd64"); !strings.Contains(got,
		"write when (arch & 0x80000000) != 0") {
		t.Errorf("archbit: %s", got)
	}
	if got := summarizeAsm(t, string(load(t, "../../testdata/asm/ip.asm")), "amd64"); !strings.Contains(got,
		"any syscall when instruction_pointer == 0x7fff31337000") {
		t.Errorf("ip: %s", got)
	}
}

func TestExplainRangesAndFusion(t *testing.T) {
	src := `A = sys_number
A >= 0x100 ? chk : allow
chk:
A = sys_number
A < 0x200 ? err : allow
err:
return ERRNO(1)
allow:
return ALLOW
`
	got := summarizeAsm(t, src, "amd64")
	if !strings.Contains(got, "sys_number >= 0x100 && sys_number <= 0x1ff") {
		t.Errorf("bounded range missing:\n%s", got)
	}
	if !strings.Contains(got, "sys_number >= 0x200") {
		t.Errorf("upper-bound side missing:\n%s", got)
	}

	fusion := `A = sys_number
A == write ? ge_chk : next
A == read ? gt_chk : allow
ge_chk:
A = data[36]
A > 0x0 ? kill_it : next
A == 0x0 ? next : allow
A = data[32]
A >= 0x1000 ? kill_it : allow
gt_chk:
A = data[36]
A > 0x2 ? kill_it : next
A == 0x2 ? next : allow
A = data[32]
A > 0x500 ? kill_it : allow
allow:
return ALLOW
kill_it:
return KILL
`
	got = summarizeAsm(t, fusion, "amd64")
	if !strings.Contains(got, "write when count >= 0x1000") ||
		!strings.Contains(got, "read when count > 0x200000500") {
		t.Errorf("fusion missing:\n%s", got)
	}

	bigEndian := `A = data[16]
A == 0x7f ? next : kill_it
A = data[20]
A == 0x31337000 ? allow : kill_it
allow:
return ALLOW
kill_it:
return KILL
`
	got = summarizeAsm(t, bigEndian, "s390x")
	if !strings.Contains(got, "any syscall when args[0] == 0x7f31337000") {
		t.Errorf("big endian fusion missing:\n%s", got)
	}
}

func TestExplainNegationDivisionAndRegisters(t *testing.T) {
	src := `A = sys_number
A == write ? chk_neg : next
A == read  ? chk_div : next
return KILL
chk_neg:
A = args[0]
A = -A
X = A
A = args[1]
A == X ? allow : deny
chk_div:
A = args[0]
A /= 0x2
X = A
A = args[1]
A == X ? allow : deny
allow:
return ALLOW
deny:
return KILL
`
	got := summarizeAsm(t, src, "amd64")
	if !strings.Contains(got, "write when buf == -fd") || !strings.Contains(got, "read when buf == fd / 0x2") {
		t.Errorf("neg/div:\n%s", got)
	}
	src = `A = args[0]
X = A
A = sys_number
A == X ? allow : kill_it
allow:
return ALLOW
kill_it:
return KILL
`
	got = summarizeAsm(t, src, "amd64")
	if !strings.Contains(got, "any syscall when sys_number == args[0]") {
		t.Errorf("register compare:\n%s", got)
	}
	src = `A = args[0]
return A
`
	if got := summarizeAsm(t, src, "amd64"); !strings.Contains(got, "UNKNOWN:") {
		t.Errorf("unknown verdict:\n%s", got)
	}
}

func TestExplainInitialX(t *testing.T) {
	src := `A = args[0]
A == X ? allow : kill_it
allow:
return ALLOW
kill_it:
return KILL
`
	got := summarizeAsm(t, src, "amd64")
	if !strings.Contains(got, "any syscall when args[0] == 0x0") {
		t.Errorf("initial X:\n%s", got)
	}
}

func TestExplainContradictoryPathsDropped(t *testing.T) {
	src := `A = sys_number
A == 0x1 ? next : kill_it
A == 0x2 ? allow : kill_it
kill_it:
return KILL
allow:
return ALLOW
`
	got := summarizeAsm(t, src, "amd64")
	if strings.Contains(got, "ALLOW") || strings.Contains(got, "write") {
		t.Errorf("impossible path reported:\n%s", got)
	}
}
