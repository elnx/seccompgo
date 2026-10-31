package util

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSupportedArchsUtil(t *testing.T) {
	want := []string{"aarch64", "amd64", "i386", "riscv64", "s390x"}
	got := SupportedArchs()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("supported = %v", got)
	}
}

func TestElf(t *testing.T) {
	dir := t.TempDir()
	elf := filepath.Join(dir, "elf")
	os.WriteFile(elf, append([]byte("\x7fELF"), make([]byte, 12)...), 0o644)
	if !Elf(elf) {
		t.Fatal("elf not detected")
	}
	bpf := filepath.Join(dir, "bpf")
	os.WriteFile(bpf, []byte{0x20, 0, 0, 0, 0, 0, 0, 0}, 0o644)
	if Elf(bpf) {
		t.Fatal("bpf detected as elf")
	}
	if Elf(filepath.Join(dir, "missing")) {
		t.Fatal("missing detected as elf")
	}
}

func TestProcessArchSelf(t *testing.T) {
	got := ProcessArch(os.Getpid())
	if got == "" {
		t.Fatal("no arch for self")
	}
	if got != SystemArch() {
		t.Fatalf("self arch = %q, host = %q", got, SystemArch())
	}
	if ProcessArch(0x7fffffff) != "" {
		t.Fatal("arch for missing process")
	}
}

func TestELFMachineBytes(t *testing.T) {
	want := map[string]string{
		"\x03\x00": "i386",
		"\x3e\x00": "amd64",
		"\xb7\x00": "aarch64",
		"\xf3\x00": "riscv64",
		"\x00\x16": "s390x",
	}
	for bytes, arch := range want {
		if ELFMachine[bytes] != arch {
			t.Fatalf("% x -> %q", bytes, ELFMachine[bytes])
		}
	}
}

func TestSystemArchKnown(t *testing.T) {
	arch := SystemArch()
	known := false
	for _, a := range SupportedArchs() {
		if a == arch {
			known = true
		}
	}
	if !known && arch != "unknown" {
		t.Fatalf("system arch = %q", arch)
	}
}

func TestAssets(t *testing.T) {
	for _, name := range []string{"asm.amd64.asm", "asm.i386.asm", "asm.s390x.asm", "asm.c"} {
		if s, err := Template(name); err != nil || s == "" {
			t.Fatalf("template %s: %v", name, err)
		}
	}
	if _, err := Template("asm.aarch64.asm"); err == nil {
		t.Fatal("missing template should error")
	}
	for _, name := range []string{"seccomp-tools.bash", "_seccomp-tools", "seccomp-tools.fish"} {
		if s, err := Completion(name); err != nil || s == "" {
			t.Fatalf("completion %s: %v", name, err)
		}
	}
}

func TestColorDisabled(t *testing.T) {
	DisableColor()
	if Colorize("meow", "syscall") != "meow" {
		t.Fatal("disabled color")
	}
	EnableColor()
	// A test process normally has a non-tty stdout, so colorize stays a no-op.
	if Colorize("meow", "syscall") != "meow" {
		t.Fatal("non-tty color")
	}
}
