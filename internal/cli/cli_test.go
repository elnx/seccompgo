package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"seccompgo/internal/cli"
	"seccompgo/internal/dumper"
	"seccompgo/internal/util"
)

func runCLI(t *testing.T, argv []string, stdin string) (string, int) {
	t.Helper()
	oldOut, oldIn := util.Stdout, util.Stdin
	var buf bytes.Buffer
	util.Stdout = &buf
	util.Stdin = strings.NewReader(stdin)
	util.DisableColor()
	defer func() {
		util.Stdout, util.Stdin = oldOut, oldIn
		util.EnableColor()
	}()
	code := cli.Run(argv)
	return buf.String(), code
}

func goldenText(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestHelpOutputs(t *testing.T) {
	if got, _ := runCLI(t, nil, ""); got != goldenText(t, "help_usage.txt") {
		t.Fatalf("usage:\n%s", got)
	}
	cases := map[string][]string{
		"help_dump.txt":    {"--help", "dump"},
		"help_audit.txt":   {"audit", "--help"},
		"help_disasm.txt":  {"disasm", "--help"},
		"help_emu.txt":     {"emu", "--help"},
		"help_explain.txt": {"explain", "--help"},
	}
	for gold, argv := range cases {
		got, code := runCLI(t, argv, "")
		if code != 0 {
			t.Fatalf("%v exit %d", argv, code)
		}
		if want := goldenText(t, gold); got != want {
			t.Fatalf("%v mismatch:\n--- got ---\n%s\n--- want ---\n%s", argv, got, want)
		}
	}
	got, _ := runCLI(t, []string{"qqpie", "--help"}, "")
	if got != "Invalid command 'qqpie'\n\nSee 'seccomp-tools --help' for list of valid commands\n" {
		t.Fatalf("invalid: %q", got)
	}
	got, _ = runCLI(t, []string{"--version"}, "")
	if got != "SeccompTools Version 1.7.1\n" {
		t.Fatalf("version: %q", got)
	}
}

func TestAsmFormats(t *testing.T) {
	asmFile := filepath.Join("..", "..", "testdata", "data", "libseccomp.asm")
	bpf, err := os.ReadFile(filepath.Join("..", "..", "testdata", "data", "libseccomp.bpf"))
	if err != nil {
		t.Fatal(err)
	}
	got, code := runCLI(t, []string{"asm", asmFile, "-a", "amd64"}, "")
	if code != 0 || got != goldenText(t, "asm_inspect.txt") {
		t.Fatalf("inspect (%d):\n%s", code, got)
	}
	got, _ = runCLI(t, []string{"asm", asmFile, "-a", "amd64", "-f", "c_array"}, "")
	want := "unsigned char bpf[] = {"
	for i, b := range bpf {
		if i > 0 {
			want += ","
		}
		want += itoa(int(b))
	}
	want += "};\n"
	if got != want {
		t.Fatalf("c_array:\n%s", got)
	}
	got, _ = runCLI(t, []string{"asm", asmFile, "-a", "amd64", "-f", "c_source"}, "")
	if got != goldenText(t, "asm_c_source.txt") {
		t.Fatalf("c_source:\n%s", got)
	}
	got, _ = runCLI(t, []string{"asm", asmFile, "-a", "amd64", "-f", "assembly"}, "")
	if got != goldenText(t, "asm_assembly.txt") {
		t.Fatalf("assembly:\n%s", got)
	}
	got, _ = runCLI(t, []string{"asm", "/dev/null", "-a", "i386", "-f", "assembly"}, "")
	if got != goldenText(t, "asm_assembly_i386.txt") {
		t.Fatalf("assembly i386:\n%s", got)
	}
	got, _ = runCLI(t, []string{"asm", asmFile, "-a", "amd64", "-f", "raw"}, "")
	if string(gotBytes(got)) != string(bpf) {
		t.Fatalf("raw output differs")
	}
}

// gotBytes converts the captured string (which is byte-preserving for our output)
// back to bytes without importing unsafe.
func gotBytes(s string) []byte { return []byte(s) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}

func TestAsmOutputFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.bpf")
	asmFile := filepath.Join("..", "..", "testdata", "data", "libseccomp.asm")
	if _, code := runCLI(t, []string{"asm", asmFile, "-a", "amd64", "-f", "raw", "-o", out}, ""); code != 0 {
		t.Fatalf("exit %d", code)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile(filepath.Join("..", "..", "testdata", "data", "libseccomp.bpf"))
	if string(got) != string(want) {
		t.Fatal("file bytes differ")
	}
}

func TestDisasmCLI(t *testing.T) {
	x32 := filepath.Join("..", "..", "testdata", "data", "x32.bpf")
	got, code := runCLI(t, []string{"disasm", x32, "-a", "amd64", "--asm-able"}, "")
	if code != 0 || got != goldenText(t, "disasm_asm_able_x32.txt") {
		t.Fatalf("asm-able (%d):\n%s", code, got)
	}
	got, _ = runCLI(t, []string{"disasm", x32, "-a", "amd64", "--no-arg-infer"}, "")
	if strings.Contains(got, "# x32_mmap") {
		t.Fatalf("arg infer not disabled:\n%s", got)
	}
	got, _ = runCLI(t, []string{"disasm", x32, "-a", "amd64", "--no-bpf"}, "")
	if strings.Contains(got, " line  CODE") || !strings.HasPrefix(got, "0000: A = arch\n") {
		t.Fatalf("no-bpf:\n%s", got)
	}
}

func TestDisasmUnknownHostArch(t *testing.T) {
	old := util.SystemArch
	util.SystemArch = func() string { return "unknown" }
	defer func() { util.SystemArch = old }()
	file := filepath.Join("..", "..", "testdata", "data", "libseccomp.bpf")
	got, _ := runCLI(t, []string{"disasm", file}, "")
	want := "[ERROR] Could not detect the host architecture; specify one with --arch <aarch64|amd64|i386|riscv64|s390x>.\n"
	if got != want {
		t.Fatalf("got %q", got)
	}
	got, _ = runCLI(t, []string{"disasm", file, "-a", "amd64"}, "")
	if !strings.Contains(got, "A = sys_number") {
		t.Fatalf("explicit arch failed: %s", got)
	}
}

func TestEmuCLI(t *testing.T) {
	file := filepath.Join("..", "..", "testdata", "data", "libseccomp.bpf")
	disasmOut := goldenText(t, "disasm_libseccomp.txt")
	got, code := runCLI(t, []string{"emu", file, "-a", "amd64", "0x3"}, "")
	want := disasmOut + "\nreturn ALLOW at line 0009\n"
	if code != 0 || got != want {
		t.Fatalf("normal (%d):\n--- got ---\n%s\n--- want ---\n%s", code, got, want)
	}
	got, _ = runCLI(t, []string{"emu", file, "-a", "amd64", "write", "-q"}, "")
	if got != "return ALLOW at line 0009\n" {
		t.Fatalf("quiet: %q", got)
	}
	got, _ = runCLI(t, []string{"emu", file, "-a", "i386", "-q"}, "")
	if got != "return KILL at line 0010\n" {
		t.Fatalf("i386 quiet: %q", got)
	}
	dir := t.TempDir()
	kp := filepath.Join(dir, "kp.bpf")
	os.WriteFile(kp, []byte("\x06\x00\x00\x00\x00\x00\x00\x80"), 0o644)
	got, _ = runCLI(t, []string{"emu", kp, "-a", "amd64", "-q"}, "")
	if got != "return KILL_PROCESS at line 0000\n" {
		t.Fatalf("kill process: %q", got)
	}
	ipf := filepath.Join(dir, "ip.bpf")
	os.WriteFile(ipf, []byte(
		"\x20\x00\x00\x00\x08\x00\x00\x00"+
			"\x15\x00\x00\x01\x37\x13\x00\x00"+
			"\x06\x00\x00\x00\x00\x00\xff\x7f"+
			"\x06\x00\x00\x00\x00\x00\x00\x00"), 0o644)
	got, _ = runCLI(t, []string{"emu", ipf, "-a", "amd64", "-q", "--ip", "0x1337"}, "")
	if got != "return ALLOW at line 0002\n" {
		t.Fatalf("ip allow: %q", got)
	}
	got, _ = runCLI(t, []string{"emu", ipf, "-a", "amd64", "-q", "-i", "48879"}, "")
	if got != "return KILL at line 0003\n" {
		t.Fatalf("ip kill: %q", got)
	}
}

func TestExplainCLI(t *testing.T) {
	file := filepath.Join("..", "..", "testdata", "data", "libseccomp.bpf")
	got, code := runCLI(t, []string{"explain", file, "-a", "amd64"}, "")
	want := "Seccomp policy for " + file + "\n" + goldenText(t, "explain_libseccomp.txt")
	if code != 0 || got != want {
		t.Fatalf("explain (%d):\n%s", code, got)
	}
	bpf, _ := os.ReadFile(file)
	got, _ = runCLI(t, []string{"explain", "-", "-a", "amd64"}, string(bpf))
	if !strings.HasPrefix(got, "Seccomp policy for <STDIN>\n") {
		t.Fatalf("stdin: %q", got)
	}
	got, code = runCLI(t, []string{"explain", "/no/such/file", "-a", "amd64"}, "")
	if code != 0 || !strings.HasPrefix(got, "[ERROR] No such file or directory @ rb_sysopen - /no/such/file\n") {
		t.Fatalf("missing file (%d): %q", code, got)
	}
	got, _ = runCLI(t, []string{"explain"}, "")
	if !strings.Contains(got, "Usage: seccomp-tools explain") {
		t.Fatalf("help: %q", got)
	}
	got, _ = runCLI(t, []string{"explain", file, "-a", "amd64", "junk"}, "")
	if !strings.HasPrefix(got, "[WARN] ignoring unused argument: junk\nSeccomp policy for") {
		t.Fatalf("warning: %q", got)
	}
}

func TestAuditCLI(t *testing.T) {
	diary := filepath.Join("..", "..", "testdata", "data", "twctf-2016-diary.bpf")
	got, _ := runCLI(t, []string{"audit", diary, "-a", "amd64"}, "")
	if !strings.Contains(got, "Seccomp audit of") || !strings.Contains(got, "[HIGH] Architecture is never validated") {
		t.Fatalf("human: %s", got)
	}
	gctf := filepath.Join("..", "..", "testdata", "data", "gctf-2019-quals-caas.bpf")
	got, _ = runCLI(t, []string{"audit", gctf, "-a", "amd64", "-f", "json"}, "")
	var doc struct {
		StackedFilters int `json:"stacked_filters"`
		Reports        []struct {
			Arches   []string `json:"arches"`
			Findings []struct {
				ID        string   `json:"id"`
				Severity  string   `json:"severity"`
				Syscalls  []string `json:"syscalls"`
				Condition *string  `json:"condition"`
			} `json:"findings"`
		} `json:"reports"`
	}
	if err := json.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatalf("json: %v\n%s", err, got)
	}
	if doc.StackedFilters != 1 || len(doc.Reports) != 1 || len(doc.Reports[0].Arches) != 1 {
		t.Fatalf("json shape: %+v", doc)
	}
	found := false
	for _, f := range doc.Reports[0].Findings {
		if len(f.Syscalls) == 1 && f.Syscalls[0] == "socket" {
			found = true
			if f.Severity != "medium" || f.Condition == nil || !strings.Contains(*f.Condition, "== 0x2") {
				t.Fatalf("socket finding: %+v", f)
			}
		}
	}
	if !found {
		t.Fatal("socket finding missing")
	}
	raw, _ := os.ReadFile(diary)
	got, _ = runCLI(t, []string{"audit", "-", "-a", "amd64"}, string(raw))
	if !strings.Contains(got, "Seccomp audit of <STDIN>") || !strings.Contains(got, "x32 ABI is not guarded") {
		t.Fatalf("stdin audit: %s", got)
	}
}

func TestCompletionCLI(t *testing.T) {
	for shell, file := range map[string]string{
		"bash": "seccomp-tools.bash",
		"zsh":  "_seccomp-tools",
		"fish": "seccomp-tools.fish",
	} {
		want, err := os.ReadFile(filepath.Join("..", "..", "internal", "assets", "completions", file))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := runCLI(t, []string{"completion", shell}, "")
		if got != string(want) {
			t.Fatalf("%s completion differs", shell)
		}
	}
	got, _ := runCLI(t, []string{"completion"}, "")
	if !strings.Contains(got, "Usage: seccomp-tools completion <bash|zsh|fish>") {
		t.Fatalf("help: %q", got)
	}
	got, _ = runCLI(t, []string{"completion", "powershell"}, "")
	if !strings.Contains(got, "Usage: seccomp-tools completion <bash|zsh|fish>") {
		t.Fatalf("unsupported: %q", got)
	}
}

func TestDumpUnsupported(t *testing.T) {
	old := dumper.Supported
	dumper.Supported = false
	defer func() { dumper.Supported = old }()
	got, code := runCLI(t, []string{"dump"}, "")
	if code != 0 || got != "[ERROR] Dumping a filter from an executable or process is only available on Linux.\n" {
		t.Fatalf("(%d) %q", code, got)
	}
}

func TestDumpTimeout(t *testing.T) {
	got, code := runCLI(t, []string{"dump", "-c", "sleep 1d", "-t", "1"}, "")
	if code != 0 || !strings.Contains(got, "No seccomp filter was installed.") {
		t.Fatalf("(%d) %q", code, got)
	}
}
