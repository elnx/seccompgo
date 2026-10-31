package audit_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"seccompgo/internal/asm"
	"seccompgo/internal/audit"
	"seccompgo/internal/disasm"
	"seccompgo/internal/explain"
	"seccompgo/internal/instruction"
	"seccompgo/internal/symbolic/executor"
)

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

func auditRaw(t *testing.T, raw []byte, arch string) *audit.Report {
	t.Helper()
	report, err := audit.NewAudit(instsOf(t, raw, arch), arch, nil).Run()
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func auditFile(t *testing.T, name, arch string) *audit.Report {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "data", name))
	if err != nil {
		t.Fatal(err)
	}
	return auditRaw(t, raw, arch)
}

func auditAsm(t *testing.T, src, arch string) *audit.Report {
	t.Helper()
	raw, err := asm.Asm(src, "", arch)
	if err != nil {
		t.Fatal(err)
	}
	return auditRaw(t, raw, arch)
}

func ids(r *audit.Report) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range r.Findings {
		if !seen[f.ID] {
			seen[f.ID] = true
			out = append(out, f.ID)
		}
	}
	return out
}

func hasID(r *audit.Report, id string) bool {
	for _, v := range ids(r) {
		if v == id {
			return true
		}
	}
	return false
}

func finding(r *audit.Report, id string) *audit.Finding {
	for _, f := range r.Findings {
		if f.ID == id {
			return f
		}
	}
	return nil
}

func TestAuditCleanAllowlist(t *testing.T) {
	r := auditFile(t, "libseccomp.bpf", "amd64")
	if len(r.Findings) != 0 {
		t.Fatalf("findings = %#v", r.Findings)
	}
	if !strings.Contains(r.String(), "No weaknesses found") {
		t.Fatal("missing clean report text")
	}
}

func TestAuditDiaryDenylist(t *testing.T) {
	r := auditFile(t, "twctf-2016-diary.bpf", "amd64")
	for _, id := range []string{"arch-unchecked", "dangerous-allow", "permissive-default", "x32-guard"} {
		if !hasID(r, id) {
			t.Errorf("missing %s in %v", id, ids(r))
		}
	}
	for _, f := range r.Findings {
		ok := false
		for _, s := range audit.Severities {
			if f.Severity == s {
				ok = true
			}
		}
		if !ok {
			t.Errorf("bad severity %q", f.Severity)
		}
	}
	r = auditFile(t, "twctf-2016-diary.bpf", "i386")
	if !hasID(r, "arch-unchecked") || !hasID(r, "permissive-default") {
		t.Fatalf("i386 ids = %v", ids(r))
	}
	if hasID(r, "x32-guard") {
		t.Fatal("x32 reported on i386")
	}
}

func TestAuditArchVariants(t *testing.T) {
	r := auditAsm(t, `A = arch
A == 0xc000003e ? next : other
A = sys_number
A == execve ? dead : next
return ERRNO(1)
other:
return ALLOW
dead:
return KILL
`, "amd64")
	f := finding(r, "arch-unchecked")
	if f == nil || !strings.Contains(f.Title, "Unlisted architectures reach ALLOW") {
		t.Fatalf("arch finding = %#v", f)
	}
}

func TestAuditAarch64AndMultiArch(t *testing.T) {
	r := auditFile(t, "DEF-CON-2020-bdooos.bpf", "aarch64")
	if len(r.Arches) != 1 || r.Arches[0] != "aarch64" {
		t.Fatalf("arches = %v", r.Arches)
	}
	if hasID(r, "x32-guard") {
		t.Fatal("x32 reported on aarch64")
	}
	r = auditFile(t, "tctf-2023-nothing-is-true.bpf", "amd64")
	if len(r.Arches) != 2 || r.Arches[0] != "i386" || r.Arches[1] != "amd64" {
		t.Fatalf("arches = %v", r.Arches)
	}
}

func TestAuditEquivalentGaps(t *testing.T) {
	r := auditAsm(t, `A = sys_number
A == execve ? dead : next
A == execveat ? ok : next
return KILL
ok:
return ALLOW
dead:
return KILL
`, "amd64")
	f := finding(r, "syscall-alt-gap")
	if f == nil || f.Severity != "high" || strings.Join(f.Syscalls, " ") != "execve execveat" {
		t.Fatalf("gap = %#v", f)
	}
	r = auditAsm(t, `A = sys_number
A == open ? dead : next
A == openat2 ? ok : next
return KILL
ok:
return ALLOW
dead:
return KILL
`, "amd64")
	f = finding(r, "syscall-alt-gap")
	if f == nil || strings.Join(f.Syscalls, " ") != "open openat2" {
		t.Fatalf("open gap = %#v", f)
	}
	r = auditAsm(t, `A = sys_number
A == open ? ok : next
A == read ? ok : next
A == write ? ok : next
return KILL
ok:
return ALLOW
`, "amd64")
	f = finding(r, "orw-chain")
	if f == nil || strings.Join(f.Syscalls, " ") != "open read write" {
		t.Fatalf("orw = %#v", f)
	}
}

func TestAuditDangerousAndCond(t *testing.T) {
	r := auditAsm(t, `A = sys_number
A == io_uring_setup ? ok : next
return KILL
ok:
return ALLOW
`, "amd64")
	f := finding(r, "dangerous-allow")
	if f == nil || f.Severity != "high" || !strings.Contains(f.Detail, "bypassing filters") {
		t.Fatalf("iou = %#v", f)
	}
	r = auditFile(t, "gctf-2019-quals-caas.bpf", "amd64")
	var socket *audit.Finding
	for _, f := range r.Findings {
		if len(f.Syscalls) == 1 && f.Syscalls[0] == "socket" {
			socket = f
		}
	}
	if socket == nil || socket.Condition == nil || !strings.Contains(*socket.Condition, "== 0x2") {
		t.Fatalf("socket = %#v", socket)
	}
}

func TestAuditX32FalsePositive(t *testing.T) {
	r := auditAsm(t, `A = arch
A == 0xc000003e ? next : dead
A = sys_number
A == write ? ok : next
return KILL
ok:
return ALLOW
dead:
return KILL
`, "amd64")
	if hasID(r, "x32-guard") {
		t.Fatalf("x32 false positive: %v", ids(r))
	}
}

func TestAuditTruncation(t *testing.T) {
	old := executor.StepCap
	executor.StepCap = 1
	defer func() { executor.StepCap = old }()
	r := auditFile(t, "libseccomp.bpf", "amd64")
	if !r.Truncated {
		t.Fatal("not truncated")
	}
	if !strings.Contains(r.String(), "analysis truncated") {
		t.Fatal("missing warning")
	}
	data := r.JSON()
	if !data.Truncated {
		t.Fatal("json truncated false")
	}
}

func TestAuditPolicy(t *testing.T) {
	src := `A = sys_number
A == write ? ok : next
return ERRNO(1)
ok:
return ALLOW
`
	insts := instsOf(t, mustAsm(t, src, "amd64"), "amd64")
	leaves, _, err := executor.NewExecutor(insts).Run()
	if err != nil {
		t.Fatal(err)
	}
	analysis := explain.NewAnalysis(leaves)
	p := audit.NewPolicy(analysis, analysis.Sections("amd64")[0])
	if !p.ReachableAsAllow(*p.Number("write")) {
		t.Fatal("write not allowed")
	}
	if p.ReachableAsAllow(*p.Number("read")) {
		t.Fatal("read allowed")
	}
	if got := p.ReachableActions(*p.Number("read")); len(got) != 1 || got[0] != "ERRNO(1)" {
		t.Fatalf("read actions = %v", got)
	}
	if def, ok := p.DefaultLabel(); !ok || def != "ERRNO(1)" {
		t.Fatalf("default = %q,%v", def, ok)
	}
	if p.ExplicitlyDenied(*p.Number("read")) {
		t.Fatal("read considered explicitly denied")
	}

	denySrc := `A = sys_number
A == execve ? dead : next
return ALLOW
dead:
return KILL
`
	insts = instsOf(t, mustAsm(t, denySrc, "amd64"), "amd64")
	leaves, _, _ = executor.NewExecutor(insts).Run()
	analysis = explain.NewAnalysis(leaves)
	p = audit.NewPolicy(analysis, analysis.Sections("amd64")[0])
	if !p.ExplicitlyDenied(*p.Number("execve")) {
		t.Fatal("execve not explicitly denied")
	}
	if p.ReachableAsAllow(*p.Number("execve")) {
		t.Fatal("execve allowed")
	}
	if !p.ReachableAsAllow(*p.Number("execve") | 0x40000000) {
		t.Fatal("x32 execve not allowed")
	}

	jsetSrc := `A = sys_number
A & 0x40000000 ? dead : next
A == execve ? dead : next
return ALLOW
dead:
return KILL
`
	insts = instsOf(t, mustAsm(t, jsetSrc, "amd64"), "amd64")
	leaves, _, _ = executor.NewExecutor(insts).Run()
	analysis = explain.NewAnalysis(leaves)
	p = audit.NewPolicy(analysis, analysis.Sections("amd64")[0])
	if p.ReachableAsAllow(*p.Number("execve") | 0x40000000) {
		t.Fatal("jset guard bypassed")
	}
}

func mustAsm(t *testing.T, src, arch string) []byte {
	t.Helper()
	raw, err := asm.Asm(src, "", arch)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
