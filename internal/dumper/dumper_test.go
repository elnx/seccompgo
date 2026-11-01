package dumper_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/elnx/seccompgo/internal/disasm"
	"github.com/elnx/seccompgo/internal/dumper"
	"github.com/elnx/seccompgo/internal/util"
)

func dataPath(name string) string {
	return filepath.Join("..", "..", "testdata", "data", name)
}

func dump(t *testing.T, args []string, limit int, timeout *float64) []dumper.Result {
	t.Helper()
	out := dumper.Dump(args, limit, timeout)
	if len(out) == 0 {
		t.Fatalf("no filters dumped from %v", args)
	}
	return out
}

func floatPtr(v float64) *float64 { return &v }

func TestDumpDiaryExact(t *testing.T) {
	if util.SystemArch() != "amd64" {
		t.Skip("requires amd64")
	}
	want, err := os.ReadFile(dataPath("twctf-2016-diary.bpf"))
	if err != nil {
		t.Fatal(err)
	}
	out := dump(t, []string{dataPath("twctf-2016-diary")}, 1, floatPtr(10))
	if len(out) != 1 {
		t.Fatalf("count = %d", len(out))
	}
	if !bytes.Equal(out[0].BPF, want) {
		t.Fatalf("filter differs\n got %x\nwant %x", out[0].BPF, want)
	}
	if out[0].Arch != "amd64" {
		t.Fatalf("arch = %q", out[0].Arch)
	}
}

func TestDumpTwoFiltersAndLimit(t *testing.T) {
	if util.SystemArch() != "amd64" {
		t.Skip("requires amd64")
	}
	out := dump(t, []string{dataPath("clone_two_seccomp")}, -1, floatPtr(10))
	if len(out) != 2 {
		t.Fatalf("count = %d", len(out))
	}
	if len(out[0].BPF) != 16 || len(out[1].BPF) != 8 {
		t.Fatalf("sizes = %d,%d", len(out[0].BPF), len(out[1].BPF))
	}
	out = dump(t, []string{dataPath("clone_two_seccomp")}, 2, floatPtr(10))
	if len(out) != 2 {
		t.Fatalf("limit 2 count = %d", len(out))
	}
	out = dump(t, []string{dataPath("clone_two_seccomp")}, 1, floatPtr(10))
	if len(out) != 1 {
		t.Fatalf("limit 1 count = %d", len(out))
	}
}

func TestDumpSeccompSyscall(t *testing.T) {
	if util.SystemArch() != "amd64" {
		t.Skip("requires amd64")
	}
	out := dump(t, []string{dataPath("syscall_seccomp")}, 1, floatPtr(10))
	if len(out) != 1 {
		t.Fatalf("count = %d", len(out))
	}
}

func TestDumpStrictMode(t *testing.T) {
	if util.SystemArch() != "amd64" {
		t.Skip("requires amd64")
	}
	want := []byte(" \x00\x00\x00\x00\x00\x00\x00\x15\x00\x04\x00\x00\x00\x00\x00\x15\x00\x03\x00\x01\x00\x00\x00\x15\x00\x02\x00\x3c\x00\x00\x00\x15\x00\x01\x00\x0f\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\xff\x7f")
	for _, bin := range []string{"strict_prctl", "strict_seccomp"} {
		out := dump(t, []string{dataPath(bin)}, 1, floatPtr(10))
		if !bytes.Equal(out[0].BPF, want) {
			t.Fatalf("%s filter differs: %x", bin, out[0].BPF)
		}
	}
}

func TestDumpNoSeccompAndMissingBinary(t *testing.T) {
	if util.SystemArch() != "amd64" {
		t.Skip("requires amd64")
	}
	if out := dumper.Dump([]string{"ls >/dev/null"}, 1, floatPtr(10)); len(out) != 0 {
		t.Fatalf("ls dumped %d filters", len(out))
	}
	old := util.Stdout
	var buf bytes.Buffer
	util.Stdout = &buf
	util.DisableColor()
	out := dumper.Dump([]string{"this_is_not_exist"}, 1, floatPtr(10))
	util.Stdout = old
	if len(out) != 0 {
		t.Fatalf("missing binary dumped %d", len(out))
	}
	if !strings.Contains(buf.String(), "Failed to execute this_is_not_exist") {
		t.Fatalf("log = %q", buf.String())
	}
}

func TestDumpTimeout(t *testing.T) {
	if util.SystemArch() != "amd64" {
		t.Skip("requires amd64")
	}
	start := time.Now()
	out := dumper.Dump([]string{"sleep", "1d"}, 1, floatPtr(0.1))
	if len(out) != 0 {
		t.Fatalf("dumped %d", len(out))
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("timeout took %v", elapsed)
	}
	cmd := "sleep 1d | " + dataPath("two_filters")
	out = dumper.Dump([]string{cmd}, -1, floatPtr(1))
	if len(out) != 2 {
		t.Fatalf("filters before timeout = %d", len(out))
	}
}

func TestStrictBPF(t *testing.T) {
	for _, tc := range []struct {
		arch string
		want string
	}{
		{"amd64", `0000: A = sys_number
0001: if (A == read) goto 0006
0002: if (A == write) goto 0006
0003: if (A == exit) goto 0006
0004: if (A == rt_sigreturn) goto 0006
0005: return KILL
0006: return ALLOW
`},
		{"i386", `0000: A = sys_number
0001: if (A == read) goto 0006
0002: if (A == write) goto 0006
0003: if (A == exit) goto 0006
0004: if (A == sigreturn) goto 0006
0005: return KILL
0006: return ALLOW
`},
	} {
		raw, err := dumper.StrictBPF(tc.arch)
		if err != nil {
			t.Fatal(err)
		}
		got, err := disasm.Disasm(raw, tc.arch, false, false)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Fatalf("%s:\n%s", tc.arch, got)
		}
	}
}

func TestDumpByPIDDoesNotExist(t *testing.T) {
	_, err := dumper.DumpByPID(0x7fffffff, 1)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errorsIs(err, syscall.ESRCH) && !errorsIs(err, syscall.EPERM) {
		t.Fatalf("unexpected error %v", err)
	}
}

func errorsIs(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
