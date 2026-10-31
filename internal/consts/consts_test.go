package consts

import "testing"

func TestEndian(t *testing.T) {
	if BigEndian("s390x") != true || BigEndian("amd64") != false ||
		BigEndian("i386") != false || BigEndian("aarch64") != false ||
		BigEndian("riscv64") != false {
		t.Fatal("endianness")
	}
	if BigEndian("nonesuch") {
		t.Fatal("unknown arch should be little-endian for callers")
	}
}

func TestAuditArchSymbol(t *testing.T) {
	for v, want := range map[uint32]string{
		0xc000003e: "amd64",
		0x40000003: "i386",
		0xc00000b7: "aarch64",
		0xc00000f3: "riscv64",
		0x80000016: "s390x",
	} {
		if got, ok := AuditArchSymbol(v); !ok || got != want {
			t.Errorf("arch_symbol(%#x) = %q,%v", v, got, ok)
		}
	}
	if _, ok := AuditArchSymbol(0x14); ok {
		t.Fatal("PPC should be unknown")
	}
}

func TestSyscallTables(t *testing.T) {
	for _, tc := range []struct {
		arch string
		name string
		num  uint32
	}{
		{"amd64", "io_uring_setup", 425},
		{"amd64", "clone3", 435},
		{"amd64", "openat2", 437},
		{"amd64", "landlock_create_ruleset", 444},
		{"amd64", "mseal", 462},
		{"i386", "io_uring_setup", 425},
		{"i386", "openat2", 437},
		{"aarch64", "landlock_create_ruleset", 444},
		{"riscv64", "clone3", 435},
		{"s390x", "futex_waitv", 449},
	} {
		if got, ok := SyscallNum(tc.arch, tc.name); !ok || got != tc.num {
			t.Errorf("%s.%s = %d,%v", tc.arch, tc.name, got, ok)
		}
	}
	// Hash#invert semantics: the later alias wins, and x32 aliases are appended.
	if name, ok := SyscallName("amd64", 17); !ok || name != "pread64" {
		t.Errorf("amd64 17 = %q,%v", name, ok)
	}
	if name, ok := SyscallName("amd64", 0x40000000); !ok || name != "x32_read" {
		t.Errorf("x32 read = %q,%v", name, ok)
	}
	if _, ok := SyscallName("nonesuch", 1); ok {
		t.Fatal("unknown table")
	}
}

func TestSyscallArgs(t *testing.T) {
	for name, want := range map[string][]string{
		"openat2":                 {"dfd", "filename", "how", "size"},
		"clone3":                  {"uargs", "size"},
		"io_uring_setup":          {"entries", "p"},
		"landlock_create_ruleset": {"attr", "size", "flags"},
		"fanotify_mark":           {"fanotify_fd", "flags", "mask", "fd", "pathname"},
		"x32_openat2":             {"dfd", "filename", "how", "size"},
	} {
		got := ArgNames(name)
		if len(got) != len(want) {
			t.Fatalf("%s = %v", name, got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s = %v, want %v", name, got, want)
			}
		}
	}
	if ArgNames("nonesuch") != nil {
		t.Fatal("unknown args")
	}
}

func TestActionLabels(t *testing.T) {
	for v, want := range map[uint32]string{
		0x7fff0000: "ALLOW",
		0x00000000: "KILL",
		0x80000000: "KILL_PROCESS",
		0x00050005: "ERRNO(5)",
		0x7ff00007: "TRACE(7)",
		0x00030005: "TRAP(5)",
		0x7ff00000: "TRACE",
		0x00030000: "TRAP",
	} {
		got, ok := ActionLabel(v)
		if !ok || got != want {
			t.Errorf("action_label(%#x) = %q,%v", v, got, ok)
		}
	}
	if _, ok := ActionLabel(0x12345678); ok {
		t.Fatal("unknown action labelled")
	}
	if name, ok := ActionName(0x00050005); !ok || name != "ERRNO" {
		t.Fatal("ActionName data")
	}
	if name, ok := ActionName(0); !ok || name != "KILL" {
		t.Fatal("ActionName kill")
	}
}

func TestSupportedArchs(t *testing.T) {
	want := []string{"aarch64", "amd64", "i386", "riscv64", "s390x"}
	if len(SupportedArchs) != len(want) {
		t.Fatal("supported archs")
	}
	for i := range want {
		if SupportedArchs[i] != want[i] {
			t.Fatal("order")
		}
	}
}
