package disasm_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"seccompgo/internal/asm"
	"seccompgo/internal/disasm"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "data", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func golden(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDisasmFixtureGoldens(t *testing.T) {
	cases := []struct {
		name, file, arch, gold string
	}{
		{"diary", "twctf-2016-diary.bpf", "amd64", "disasm_diary.txt"},
		{"libseccomp", "libseccomp.bpf", "amd64", "disasm_libseccomp.txt"},
		{"i386", "CONFidence-2017-amigo.bpf", "i386", "disasm_i386.txt"},
		{"aarch64", "DEF-CON-2020-bdooos.bpf", "aarch64", "disasm_aarch64.txt"},
		{"x32", "x32.bpf", "amd64", "disasm_x32.txt"},
		{"gctf", "gctf-2019-quals-caas.bpf", "amd64", "disasm_gctf.txt"},
		{"all_inst", "all_inst.bpf", "amd64", "disasm_all_inst.txt"},
		{"misc_alu", "misc_alu.bpf", "amd64", "disasm_misc_alu.txt"},
		{"mixed_arch", "mixed_arch.bpf", "amd64", "disasm_mixed_arch.txt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := disasm.Disasm(fixture(t, tc.file), tc.arch, true, true)
			if err != nil {
				t.Fatal(err)
			}
			if want := golden(t, tc.gold); got != want {
				t.Fatalf("output mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
			}
		})
	}
}

func TestDisasmRiscv(t *testing.T) {
	raw := []byte(
		"\x20\x00\x00\x00\x04\x00\x00\x00" +
			"\x15\x00\x00\x05\xf3\x00\x00\xc0" +
			"\x20\x00\x00\x00\x00\x00\x00\x00" +
			"\x15\x00\x02\x00\x02\x01\x00\x00" +
			"\x15\x00\x01\x00\x03\x01\x00\x00" +
			"\x06\x00\x00\x00\x00\x00\x00\x80" +
			"\x06\x00\x00\x00\x00\x00\xff\x7f" +
			"\x06\x00\x00\x00\x00\x00\x00\x00")
	got, err := disasm.Disasm(raw, "riscv64", false, true)
	if err != nil {
		t.Fatal(err)
	}
	want := `0000: A = arch
0001: if (A != ARCH_RISCV64) goto 0007
0002: A = sys_number
0003: if (A == riscv_hwprobe) goto 0006
0004: if (A == riscv_flush_icache) goto 0006
0005: return KILL_PROCESS
0006: return ALLOW
0007: return KILL
`
	if got != want {
		t.Fatalf("got:\n%s", got)
	}
}

func TestDisasmUnknownSyscallArgs(t *testing.T) {
	raw := []byte(
		"\x20\x00\x00\x00\x00\x00\x00\x00" +
			"\x15\x00\x00\x01\xE7\x03\x00\x00" +
			"\x20\x00\x00\x00\x10\x00\x00\x00" +
			"\x06\x00\x00\x00\x00\x00\x00\x00")
	got, err := disasm.Disasm(raw, "amd64", false, true)
	if err != nil {
		t.Fatal(err)
	}
	want := `0000: A = sys_number
0001: if (A != 0x3e7) goto 0003
0002: A = args[0]
0003: return KILL
`
	if got != want {
		t.Fatalf("got:\n%s", got)
	}
}

func TestDisasmElseJmpAndNoBPF(t *testing.T) {
	var raw []byte
	for _, c := range []byte{0x15, 0x25, 0x35, 0x45} {
		raw = append(raw, c, 0, 0, 1, 0, 0, 0, 0)
	}
	got, err := disasm.Disasm(raw, "amd64", false, true)
	if err != nil {
		t.Fatal(err)
	}
	want := `0000: if (A != 0) goto 0002
0001: if (A <= 0) goto 0003
0002: if (A < 0) goto 0004
0003: if (!(A & 0)) goto 0005
`
	if got != want {
		t.Fatalf("got:\n%s", got)
	}
}

func TestDisasmInvalidJmp(t *testing.T) {
	raw := append([]byte{0x55}, make([]byte, 7)...)
	_, err := disasm.Disasm(raw, "amd64", true, true)
	if err == nil || err.Error() != "Line 0 is invalid: unknown jmp type" {
		t.Fatalf("error = %v", err)
	}
}

func TestDisasmNoArgInfer(t *testing.T) {
	got, err := disasm.Disasm(fixture(t, "x32.bpf"), "amd64", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "0008: A = args[0]\n") {
		t.Fatalf("argument inference not suppressed:\n%s", got)
	}
	if strings.Contains(got, "# x32_mmap") {
		t.Fatalf("argument comment not suppressed:\n%s", got)
	}
}

func TestDisasmInfersArchFromFilter(t *testing.T) {
	src := `A = arch
A == ARCH_X86_64 ? next : dead
A = sys_number
A == write ? chk : dead
chk:
A = args[0]
return ALLOW
dead:
return KILL
`
	raw, err := asm.Asm(src, "", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	out, err := disasm.Disasm(raw, "aarch64", false, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "if (A != amd64.write) goto") {
		t.Fatalf("missing inferred syscall name:\n%s", out)
	}
	if !strings.Contains(out, "A = fd # amd64.write(fd, buf, count)") {
		t.Fatalf("missing inferred argument name:\n%s", out)
	}
}

func TestDisasmPropagatesPinnedValueThroughX(t *testing.T) {
	src := `A = args[1]
A == 0x1 ? n1 : deny
n1:
X = A
A = sys_number
A == X ? n2 : deny
n2:
A = args[0]
return ALLOW
deny:
return KILL
`
	raw, err := asm.Asm(src, "", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	out, err := disasm.Disasm(raw, "amd64", false, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "A = fd # write(fd, buf, count)") {
		t.Fatalf("missing pinned argument name:\n%s", out)
	}
}

func TestDisasmUnknownActionRoundTrip(t *testing.T) {
	for input, want := range map[string]string{
		"TRACE(5)":   "return TRACE(5)",
		"TRAP(7)":    "return TRAP(7)",
		"0x12345678": "return 0x12345678",
	} {
		raw, err := asm.Asm("return "+input, "", "amd64")
		if err != nil {
			t.Fatal(err)
		}
		out, err := disasm.Disasm(raw, "amd64", false, true)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, want) {
			t.Fatalf("%s: got %q", input, out)
		}
		line := strings.TrimPrefix(out, "0000: ")
		line = strings.TrimSuffix(line, "\n")
		round, err := asm.Asm(line, "", "amd64")
		if err != nil {
			t.Fatal(err)
		}
		if string(round) != string(raw) {
			t.Fatalf("%s: round trip differs", input)
		}
	}
}
