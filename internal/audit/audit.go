// Package audit assesses a seccomp filter for weaknesses and escape routes.
package audit

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/elnx/seccompgo/internal/consts"
	"github.com/elnx/seccompgo/internal/explain"
	"github.com/elnx/seccompgo/internal/instruction"
	"github.com/elnx/seccompgo/internal/symbolic"
	"github.com/elnx/seccompgo/internal/symbolic/executor"
	"github.com/elnx/seccompgo/internal/util"
)

// Severities, most to least severe.
var Severities = []string{"high", "medium", "low"}

// Finding is one weakness reported by a check.
type Finding struct {
	ID          string
	Severity    string
	Title       string
	Detail      string
	Arch        *string
	Syscalls    []string
	Condition   *string
	Remediation string
}

// Rank is the report sort key.
func (f *Finding) Rank() (int, string, string) {
	idx := len(Severities)
	for i, s := range Severities {
		if s == f.Severity {
			idx = i
			break
		}
	}
	return idx, f.ID, strings.Join(f.Syscalls, ",")
}

type dangerMeta struct {
	severity string
	why      string
}

var dangerous = map[string]dangerMeta{
	"execve":            {"high", "arbitrary program execution"},
	"execveat":          {"high", "arbitrary program execution"},
	"ptrace":            {"high", "inspect/inject into other processes"},
	"process_vm_readv":  {"high", "read another process's memory"},
	"process_vm_writev": {"high", "write another process's memory"},
	"io_uring_setup": {
		"high", "reads/writes/opens as ring operations, bypassing filters on those syscalls",
	},
	"socket":  {"medium", "network access (exfiltration)"},
	"connect": {"medium", "network access (exfiltration)"},
}

var dangerousOrder = []string{
	"execve", "execveat", "ptrace", "process_vm_readv", "process_vm_writev",
	"io_uring_setup", "socket", "connect",
}

var dangerousByArch = map[string]map[string]dangerMeta{
	"i386": {"socketcall": {"medium", "multiplexed socket API (exfiltration)"}},
}

type altGroup struct {
	name  string
	names []string
}

var altGroups = []altGroup{
	{"exec", []string{"execve", "execveat"}},
	{"open", []string{"open", "openat", "openat2"}},
	{"read", []string{"read", "readv", "pread64", "preadv", "preadv2"}},
	{"write", []string{"write", "writev", "pwrite64", "pwritev", "sendfile"}},
	{"fork", []string{"fork", "vfork", "clone", "clone3"}},
}

var orwOpen = []string{"open", "openat", "openat2"}
var orwRead = []string{"read", "readv", "pread64", "preadv", "preadv2"}
var orwWrite = []string{"write", "writev", "pwrite64", "pwritev", "sendfile"}

func dangerousFor(arch string) []struct {
	name string
	meta dangerMeta
} {
	out := make([]struct {
		name string
		meta dangerMeta
	}, 0, len(dangerousOrder))
	seen := map[string]bool{}
	for _, name := range dangerousOrder {
		out = append(out, struct {
			name string
			meta dangerMeta
		}{name, dangerous[name]})
		seen[name] = true
	}
	add := dangerousByArch[arch]
	var extra []string
	for name := range add {
		if !seen[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	for _, name := range extra {
		out = append(out, struct {
			name string
			meta dangerMeta
		}{name, add[name]})
	}
	return out
}

// Policy is one architecture's view of a filter.
type Policy struct {
	analysis *explain.Analysis
	ArchVal  *uint32
	ArchSym  string
	Title    string
	Leaves   []*executor.Leaf
	fusion   *explain.QwordFusion
	renderer *explain.Renderer
}

// NewPolicy builds a policy from one analysis section.
func NewPolicy(analysis *explain.Analysis, section explain.Section) *Policy {
	p := &Policy{
		analysis: analysis,
		ArchVal:  section.ArchVal,
		ArchSym:  section.ArchSym,
		Title:    section.Title,
		Leaves:   section.Leaves,
	}
	if section.ArchSym != "" {
		p.fusion = explain.NewQwordFusion(section.ArchSym)
		p.renderer = explain.NewRenderer(p.fusion)
	}
	return p
}

// ArchName is the display name of this section's architecture.
func (p *Policy) ArchName() string {
	if p.ArchSym != "" {
		return p.ArchSym
	}
	return p.Title
}

// Number returns the number of a syscall on this arch, or nil.
func (p *Policy) Number(name string) *uint32 {
	if p.ArchSym == "" {
		return nil
	}
	if v, ok := consts.SyscallNum(p.ArchSym, name); ok {
		return &v
	}
	return nil
}

// DefaultLabel returns the catch-all action label.
func (p *Policy) DefaultLabel() (string, bool) {
	return p.analysis.DefaultLabel(p.Leaves)
}

// ReachableActions returns the distinct actions reachable for nr.
func (p *Policy) ReachableActions(nr uint32) []string {
	var out []string
	seen := map[string]bool{}
	for _, l := range p.reachableLeaves(nr) {
		label := explain.VerdictLabel(l.Ret)
		if !seen[label] {
			seen[label] = true
			out = append(out, label)
		}
	}
	return out
}

// ReachableAsAllow reports whether nr can reach ALLOW.
func (p *Policy) ReachableAsAllow(nr uint32) bool {
	for _, l := range p.reachableLeaves(nr) {
		if explain.VerdictLabel(l.Ret) == "ALLOW" {
			return true
		}
	}
	return false
}

// ExplicitlyDenied reports whether a rule pins nr to a non-ALLOW action.
func (p *Policy) ExplicitlyDenied(nr uint32) bool {
	if p.ReachableAsAllow(nr) {
		return false
	}
	for _, l := range p.Leaves {
		if p.analysis.Facts(l).SysEq != nil && *p.analysis.Facts(l).SysEq == nr &&
			explain.VerdictLabel(l.Ret) != "ALLOW" {
			return true
		}
	}
	return false
}

// ConditionFor returns the argument condition for nr reaching action.
func (p *Policy) ConditionFor(nr uint32, action string) *string {
	if p.renderer == nil {
		return nil
	}
	var lists [][]explain.Fact
	name := p.nameOf(nr)
	for _, l := range p.reachableLeaves(nr) {
		if explain.VerdictLabel(l.Ret) != action {
			continue
		}
		res := p.analysis.Facts(l).Residual
		list := make([]explain.Fact, 0, len(res))
		for _, c := range res {
			list = append(list, c)
		}
		lists = append(lists, list)
	}
	var conds []string
	seen := map[string]bool{}
	for _, list := range p.fusion.MergeOr(lists) {
		text := p.renderer.Conjunction(p.fusion.Fold(list), name)
		if !seen[text] {
			seen[text] = true
			conds = append(conds, text)
		}
	}
	for _, c := range conds {
		if c == "" {
			return nil
		}
	}
	if len(conds) == 0 {
		return nil
	}
	out := strings.Join(conds, " or ")
	return &out
}

func (p *Policy) nameOf(nr uint32) *string {
	if p.ArchSym == "" {
		return nil
	}
	if name, ok := consts.SyscallName(p.ArchSym, nr); ok {
		return &name
	}
	return nil
}

func (p *Policy) reachableLeaves(nr uint32) []*executor.Leaf {
	var out []*executor.Leaf
	for _, l := range p.Leaves {
		ok := true
		for _, c := range l.Path {
			if !c.PlainDataFact(consts.SysNumber) {
				continue
			}
			if !symbolic.Evaluate(nr, c.Op(), c.Rhs().Val()) {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, l)
		}
	}
	return out
}

// Report is the findings for one filter.
type Report struct {
	Source    *string
	Arches    []string
	Findings  []*Finding
	Truncated bool
}

// SeverityTheme maps a severity to its color theme.
var severityTheme = map[string]string{"high": "error", "medium": "warn", "low": "info"}

// TruncationWarning qualifies an incomplete report.
const TruncationWarning = "WARNING: analysis truncated; this report is incomplete - weaknesses in the rules the walk\n" +
	"         did not reach are not listed.\n"

// Width is the widest line a finding is wrapped to.
const Width = 120

// NewReport sorts findings and builds a report.
func NewReport(source *string, arches []string, findings []*Finding, truncated bool) *Report {
	sorted := append([]*Finding(nil), findings...)
	sort.SliceStable(sorted, func(i, j int) bool {
		ai, bi, ci := sorted[i].Rank()
		aj, bj, cj := sorted[j].Rank()
		if ai != aj {
			return ai < aj
		}
		if bi != bj {
			return bi < bj
		}
		return ci < cj
	})
	for i, f := range sorted {
		if f.Syscalls == nil {
			sorted[i].Syscalls = []string{}
		}
	}
	if arches == nil {
		arches = []string{}
	}
	return &Report{Source: source, Arches: arches, Findings: sorted, Truncated: truncated}
}

// String renders the human report.
func (r *Report) String() string {
	var out strings.Builder
	if r.Source != nil {
		fmt.Fprintf(&out, "Seccomp audit of %s\n", *r.Source)
	}
	if len(r.Arches) > 0 {
		fmt.Fprintf(&out, "Architectures: %s\n", strings.Join(r.Arches, ", "))
	}
	if r.Truncated {
		out.WriteString(TruncationWarning)
	}
	if len(r.Findings) == 0 {
		out.WriteString("\nNo weaknesses found.\n")
		return out.String()
	}
	for _, f := range r.Findings {
		out.WriteString(r.render(f))
	}
	return out.String()
}

func (r *Report) render(f *Finding) string {
	var out strings.Builder
	tag := util.Colorize("["+strings.ToUpper(f.Severity)+"]", severityTheme[f.Severity])
	arch := ""
	if f.Arch != nil {
		arch = " (" + util.Colorize(*f.Arch, "arch") + ")"
	}
	fmt.Fprintf(&out, "\n%s %s%s\n", tag, highlight(f.Title, f.Syscalls), arch)
	out.WriteString(paragraph(f.Detail, f.Syscalls, "    ", "    "))
	if f.Condition != nil {
		out.WriteString(paragraph(*f.Condition, f.Syscalls, "    when: ", "          "))
	}
	out.WriteString(paragraph(f.Remediation, f.Syscalls, "    fix:  ", "          "))
	return out.String()
}

func paragraph(text string, names []string, first, hang string) string {
	lines := []string{}
	indent := first
	line := ""
	hasLine := false
	for _, word := range strings.Fields(text) {
		if !hasLine {
			line = word
			hasLine = true
		} else if utf8.RuneCountInString(indent)+utf8.RuneCountInString(line)+1+utf8.RuneCountInString(word) <= Width {
			line += " " + word
		} else {
			lines = append(lines, indent+line)
			indent = hang
			line = word
		}
	}
	if hasLine {
		lines = append(lines, indent+line)
	}
	var out strings.Builder
	for _, l := range lines {
		out.WriteString(highlight(l, names))
		out.WriteByte('\n')
	}
	return out.String()
}

func highlight(text string, names []string) string {
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
		text = re.ReplaceAllStringFunc(text, func(string) string {
			return util.Colorize(name, "syscall")
		})
	}
	return text
}

// JSON shapes used by the CLI.
type ReportJSON struct {
	Source    *string       `json:"source"`
	Arches    []string      `json:"arches"`
	Truncated bool          `json:"truncated"`
	Findings  []FindingJSON `json:"findings"`
}

// FindingJSON is the JSON-ready shape of a finding.
type FindingJSON struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Title       string   `json:"title"`
	Detail      string   `json:"detail"`
	Arch        *string  `json:"arch"`
	Syscalls    []string `json:"syscalls"`
	Condition   *string  `json:"condition"`
	Remediation string   `json:"remediation"`
}

// JSON converts the report to its JSON-ready shape.
func (r *Report) JSON() ReportJSON {
	findings := make([]FindingJSON, 0, len(r.Findings))
	for _, f := range r.Findings {
		sys := f.Syscalls
		if sys == nil {
			sys = []string{}
		}
		findings = append(findings, FindingJSON{
			ID: f.ID, Severity: f.Severity, Title: f.Title, Detail: f.Detail,
			Arch: f.Arch, Syscalls: sys, Condition: f.Condition, Remediation: f.Remediation,
		})
	}
	return ReportJSON{Source: r.Source, Arches: r.Arches, Truncated: r.Truncated, Findings: findings}
}

// Check is a per-architecture rule.
type Check func(*Policy) []*Finding

// FilterCheck is a whole-filter rule.
type FilterCheck func(*explain.Analysis) []*Finding

// FilterChecks run once over the whole filter.
var FilterChecks = []FilterCheck{archUnchecked}

// SectionChecks run per architecture everywhere.
var SectionChecks = []Check{permissiveDefault, syscallAltGap, orwChain, dangerousAllow}

// SectionByArch adds arch-specific checks.
var SectionByArch = map[string][]Check{"amd64": {x32Guard}}

// SectionChecksFor returns the checks for archSym.
func SectionChecksFor(archSym string) []Check {
	out := append([]Check(nil), SectionChecks...)
	out = append(out, SectionByArch[archSym]...)
	return out
}

// Audit walks a filter and runs every check.
type Audit struct {
	instructions []instruction.Inst
	arch         string
	source       *string
}

// NewAudit builds an audit for a filter.
func NewAudit(insts []instruction.Inst, arch string, source *string) *Audit {
	return &Audit{instructions: insts, arch: arch, source: source}
}

// Run walks the filter and returns the report.
func (a *Audit) Run() (*Report, error) {
	leaves, truncated, err := executor.NewExecutor(a.instructions).Run()
	if err != nil {
		return nil, err
	}
	analysis := explain.NewAnalysis(leaves)
	sections := analysis.Sections(a.arch)
	policies := make([]*Policy, 0, len(sections))
	arches := make([]string, 0, len(sections))
	for _, section := range sections {
		p := NewPolicy(analysis, section)
		policies = append(policies, p)
		arches = append(arches, p.ArchName())
	}
	var findings []*Finding
	for _, check := range FilterChecks {
		findings = append(findings, check(analysis)...)
	}
	for _, p := range policies {
		for _, check := range SectionChecksFor(p.ArchSym) {
			findings = append(findings, check(p)...)
		}
	}
	return NewReport(a.source, arches, findings, truncated), nil
}
