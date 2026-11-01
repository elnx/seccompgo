package explain

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/elnx/seccompgo/internal/consts"
	"github.com/elnx/seccompgo/internal/instruction"
	"github.com/elnx/seccompgo/internal/symbolic/executor"
	"github.com/elnx/seccompgo/internal/util"
)

// Summary renders a walked filter as a per-action policy.
type Summary struct {
	arch      string
	source    *string
	truncated bool
	fusion    *QwordFusion
	renderer  *Renderer
	analysis  *Analysis
}

// NewSummary builds a summary from executor leaves.
func NewSummary(leaves []*executor.Leaf, arch string, source *string, truncated bool) *Summary {
	fusion := NewQwordFusion(arch)
	return &Summary{
		arch:      arch,
		source:    source,
		truncated: truncated,
		fusion:    fusion,
		renderer:  NewRenderer(fusion),
		analysis:  NewAnalysis(leaves),
	}
}

// TruncationWarning qualifies an incomplete policy.
const TruncationWarning = "WARNING: analysis truncated; this policy is incomplete - rules the walk did not reach are\n" +
	"         absent below, and the syscalls they name read as the default action.\n"

// SysName is the displayed syscall-number field.
const SysName = "sys_number"

// X32SyscallBit is the conventional x32 ABI lower-bound guard.
const X32SyscallBit = 0x40000000

// WrapWidth is the widest a wrapped bucket line may get.
const WrapWidth = 72

type bucket struct {
	simple  []string
	complex []string
}

func (s *Summary) facts(l *executor.Leaf) *PathFacts { return s.analysis.Facts(l) }

// String renders the policy.
func (s *Summary) String() string {
	var out strings.Builder
	if s.source != nil {
		fmt.Fprintf(&out, "Seccomp policy for %s\n", *s.source)
	}
	if s.truncated {
		out.WriteString(TruncationWarning)
	}
	for _, section := range s.analysis.Sections(s.arch) {
		out.WriteByte('\n')
		out.WriteString(s.renderSection(section.Title, s.sectionBuckets(section.ArchSym, section.Leaves)))
	}
	out.WriteString(s.renderOtherArches())
	return out.String()
}

func (s *Summary) renderOtherArches() string {
	if len(s.analysis.ArchValues()) == 0 {
		return ""
	}
	leaves := s.analysis.OtherLeaves()
	def, ok := s.analysis.DefaultLabel(leaves)
	if !ok {
		return ""
	}
	buckets := s.ruleBuckets("", false, leaves, def, true)
	if len(buckets) == 0 {
		return "\nOther architectures: " + def + "\n"
	}
	s.addDefault(buckets, def, true)
	return "\n" + s.renderSection("<any other>", buckets)
}

func (s *Summary) sectionBuckets(archSym string, leaves []*executor.Leaf) map[string]*bucket {
	def, ok := s.analysis.DefaultLabel(leaves)
	buckets := s.ruleBuckets(archSym, archSym != "", leaves, def, ok)
	s.addDefault(buckets, def, ok)
	return buckets
}

func (s *Summary) renderSection(title string, buckets map[string]*bucket) string {
	var out strings.Builder
	fmt.Fprintf(&out, "Architecture: %s\n", util.Colorize(title, "arch"))
	if len(buckets) == 0 {
		out.WriteString("\n  (no return reached; filter runs off the end)\n")
		return out.String()
	}
	for _, pair := range s.sortedBuckets(buckets) {
		out.WriteString(s.renderBucket(pair.label, pair.b))
	}
	return out.String()
}

type labelBucket struct {
	label string
	b     *bucket
}

func (s *Summary) sortedBuckets(buckets map[string]*bucket) []labelBucket {
	out := make([]labelBucket, 0, len(buckets))
	for label, b := range buckets {
		out = append(out, labelBucket{label, b})
	}
	sort.SliceStable(out, func(i, j int) bool {
		ai, al := VerdictRank(out[i].label)
		bi, bl := VerdictRank(out[j].label)
		if ai != bi {
			return ai < bi
		}
		return al < bl
	})
	return out
}

func (s *Summary) ruleBuckets(archSym string, hasArch bool, leaves []*executor.Leaf, def string, hasDef bool) map[string]*bucket {
	var named, ranged, conditional []*executor.Leaf
	var rest []*executor.Leaf
	for _, l := range leaves {
		if s.facts(l).SysEq != nil {
			named = append(named, l)
		} else {
			rest = append(rest, l)
		}
	}
	var rest2 []*executor.Leaf
	for _, l := range rest {
		if s.facts(l).SysRange != nil {
			ranged = append(ranged, l)
		} else {
			rest2 = append(rest2, l)
		}
	}
	for _, l := range rest2 {
		if len(s.facts(l).Residual) > 0 {
			conditional = append(conditional, l)
		}
	}

	buckets := map[string]*bucket{}
	s.addNamed(buckets, archSym, hasArch, named, def, hasDef)
	s.addRanges(buckets, ranged)
	s.addConditional(buckets, conditional, def, hasDef)
	return buckets
}

type namedGroup struct {
	nr     uint32
	leaves []*executor.Leaf
}

func (s *Summary) addNamed(buckets map[string]*bucket, archSym string, hasArch bool, leaves []*executor.Leaf, def string, hasDef bool) {
	var groups []namedGroup
	index := map[uint32]int{}
	for _, l := range leaves {
		nr := *s.facts(l).SysEq
		if i, ok := index[nr]; ok {
			groups[i].leaves = append(groups[i].leaves, l)
		} else {
			index[nr] = len(groups)
			groups = append(groups, namedGroup{nr: nr, leaves: []*executor.Leaf{l}})
		}
	}
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].nr < groups[j].nr })
	for _, g := range groups {
		var sys *string
		if hasArch {
			if name, ok := consts.SyscallName(archSym, g.nr); ok {
				sys = &name
			}
		}
		nameText := ""
		if sys != nil {
			nameText = util.Colorize(*sys, "syscall")
		} else {
			nameText = util.Colorize(fmt.Sprintf("0x%x", g.nr), "syscall")
		}
		var labels []string
		byLabel := map[string][]*executor.Leaf{}
		for _, l := range g.leaves {
			label := VerdictLabel(l.Ret)
			if _, ok := byLabel[label]; !ok {
				labels = append(labels, label)
			}
			byLabel[label] = append(byLabel[label], l)
		}
		for _, label := range labels {
			if hasDef && label == def {
				continue
			}
			conds := s.mergedConds(byLabel[label], sys)
			plain := contains(conds, "")
			entry := nameText
			if !plain {
				entry += " when " + strings.Join(conds, " or ")
			}
			s.add(buckets, label, entry, plain)
		}
	}
}

type rangeGroup struct {
	r      SysRange
	leaves []*executor.Leaf
}

func (s *Summary) addRanges(buckets map[string]*bucket, leaves []*executor.Leaf) {
	var groups []rangeGroup
	index := map[SysRange]int{}
	for _, l := range leaves {
		r := *s.facts(l).SysRange
		if i, ok := index[r]; ok {
			groups[i].leaves = append(groups[i].leaves, l)
		} else {
			index[r] = len(groups)
			groups = append(groups, rangeGroup{r: r, leaves: []*executor.Leaf{l}})
		}
	}
	for _, g := range groups {
		text := fmt.Sprintf("%s >= 0x%x", SysName, g.r.Lo)
		if g.r.HasHi {
			text += fmt.Sprintf(" && %s <= 0x%x", SysName, g.r.Hi)
		}
		var labels []string
		byLabel := map[string][]*executor.Leaf{}
		for _, l := range g.leaves {
			label := VerdictLabel(l.Ret)
			if _, ok := byLabel[label]; !ok {
				labels = append(labels, label)
			}
			byLabel[label] = append(byLabel[label], l)
		}
		for _, label := range labels {
			conds := s.mergedConds(byLabel[label], nil)
			entry := text
			if !contains(conds, "") {
				entry += " when " + strings.Join(conds, " or ")
			}
			if g.r.Lo == X32SyscallBit && !g.r.HasHi {
				entry += "  (x32 ABI)"
			}
			s.add(buckets, label, entry, false)
		}
	}
}

func (s *Summary) addConditional(buckets map[string]*bucket, leaves []*executor.Leaf, def string, hasDef bool) {
	var labels []string
	byLabel := map[string][]*executor.Leaf{}
	for _, l := range leaves {
		label := VerdictLabel(l.Ret)
		if _, ok := byLabel[label]; !ok {
			labels = append(labels, label)
		}
		byLabel[label] = append(byLabel[label], l)
	}
	for _, label := range labels {
		if hasDef && label == def {
			continue
		}
		conds := s.mergedConds(byLabel[label], nil)
		s.add(buckets, label, "any syscall when "+strings.Join(conds, " or "), false)
	}
}

func (s *Summary) mergedConds(leaves []*executor.Leaf, sys *string) []string {
	lists := make([][]Fact, 0, len(leaves))
	for _, l := range leaves {
		list := make([]Fact, 0, len(s.facts(l).Residual))
		for _, c := range s.facts(l).Residual {
			list = append(list, c)
		}
		lists = append(lists, list)
	}
	var out []string
	seen := map[string]bool{}
	for _, list := range s.fusion.MergeOr(lists) {
		text := s.renderer.Conjunction(s.fusion.Fold(list), sys)
		if !seen[text] {
			seen[text] = true
			out = append(out, text)
		}
	}
	return out
}

func (s *Summary) addDefault(buckets map[string]*bucket, def string, hasDef bool) {
	if !hasDef {
		return
	}
	scope := "any other syscall"
	if len(buckets) == 0 {
		scope = "any syscall"
	}
	if s.truncated {
		scope += "; incomplete"
	}
	s.add(buckets, def, "<default> ("+scope+")", false)
}

func (s *Summary) add(buckets map[string]*bucket, label, text string, simple bool) {
	b := buckets[label]
	if b == nil {
		b = &bucket{}
		buckets[label] = b
	}
	if simple {
		b.simple = append(b.simple, text)
	} else {
		b.complex = append(b.complex, text)
	}
}

func (s *Summary) renderBucket(label string, b *bucket) string {
	var out strings.Builder
	fmt.Fprintf(&out, "\n  %s:\n", label)
	for _, line := range wrapLines(b.simple) {
		out.WriteString("    " + line + "\n")
	}
	for _, line := range b.complex {
		out.WriteString("    " + line + "\n")
	}
	return out.String()
}

func wrapLines(tokens []string) []string {
	if len(tokens) == 0 {
		return nil
	}
	var lines []string
	line := ""
	for _, tok := range tokens {
		piece := tok
		if line != "" {
			piece = ", " + tok
		}
		if line != "" && utf8.RuneCountInString(line)+utf8.RuneCountInString(piece) > WrapWidth {
			lines = append(lines, line)
			line = tok
		} else {
			line += piece
		}
	}
	lines = append(lines, line)
	return lines
}

func contains(xs []string, x string) bool {
	return slices.Contains(xs, x)
}

// Explain walks a filter and returns its summary.
type Explain struct {
	instructions []instruction.Inst
	arch         string
	source       *string
}

// NewExplain builds an Explain for a filter.
func NewExplain(insts []instruction.Inst, arch string, source *string) *Explain {
	return &Explain{instructions: insts, arch: arch, source: source}
}

// Summarize walks the filter and renders the policy.
func (e *Explain) Summarize() (*Summary, error) {
	leaves, truncated, err := executor.NewExecutor(e.instructions).Run()
	if err != nil {
		return nil, err
	}
	return NewSummary(leaves, e.arch, e.source, truncated), nil
}
