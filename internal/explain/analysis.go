// Package explain summarizes a filter as a per-action policy.
package explain

import (
	"fmt"

	"seccompgo/internal/consts"
	"seccompgo/internal/symbolic"
	"seccompgo/internal/symbolic/executor"
)

// PathFacts is the seccomp reading of one leaf's path condition.
type PathFacts struct {
	path     []*symbolic.Constraint
	SysEq    *uint32
	ArchEq   *uint32
	SysRange *SysRange
	Residual []*symbolic.Constraint
}

// SysRange is an inclusive syscall-number range; Hi is meaningful only when HasHi.
type SysRange struct {
	Lo    int64
	Hi    int64
	HasHi bool
}

// U32Max is the upper end of an unconstrained syscall-number range.
const U32Max = 0xffffffff

// NewPathFacts derives every query for a path.
func NewPathFacts(path []*symbolic.Constraint) *PathFacts {
	f := &PathFacts{path: path}
	f.SysEq = f.eq(consts.SysNumber)
	f.ArchEq = f.eq(consts.Arch)
	f.SysRange = f.computeSysRange()
	f.Residual = f.computeResidual()
	return f
}

func (f *PathFacts) eq(offset int) *uint32 {
	for _, c := range f.path {
		if c.PlainDataEq(offset) {
			v := c.Rhs().Val()
			return &v
		}
	}
	return nil
}

func (f *PathFacts) computeSysRange() *SysRange {
	var lo, hi *int64
	for _, c := range f.path {
		if !c.PlainDataFact(consts.SysNumber) {
			continue
		}
		v := int64(c.Rhs().Val())
		switch c.Op() {
		case ">":
			n := v + 1
			if lo == nil || n > *lo {
				lo = &n
			}
		case ">=":
			n := v
			if lo == nil || n > *lo {
				lo = &n
			}
		case "<":
			n := v - 1
			if hi == nil || n < *hi {
				hi = &n
			}
		case "<=":
			n := v
			if hi == nil || n < *hi {
				hi = &n
			}
		}
	}
	if lo == nil {
		return nil
	}
	r := &SysRange{Lo: *lo}
	if hi != nil {
		r.Hi, r.HasHi = *hi, true
	}
	return r
}

func (f *PathFacts) computeResidual() []*symbolic.Constraint {
	pinned := map[string]bool{}
	for _, c := range f.path {
		if c.Op() == "==" && c.Rhs().IsImm() && !c.Lhs().IsOpaque() {
			pinned[c.Lhs().Key()] = true
		}
	}
	var out []*symbolic.Constraint
	seen := map[string]bool{}
	for _, c := range f.path {
		redundant := c.Op() != "==" && c.Rhs().IsImm() && pinned[c.Lhs().Key()]
		if !c.PlainDataFact(-1) {
			if redundant {
				continue
			}
		} else {
			switch c.Lhs().Offset() {
			case consts.SysNumber:
				if redundant || (c.Op() != "set" && c.Op() != "unset") {
					continue
				}
			case consts.Arch:
				if redundant || c.Op() == "==" || c.Op() == "!=" {
					continue
				}
			default:
				if redundant {
					continue
				}
			}
		}
		if seen[c.Key()] {
			continue
		}
		seen[c.Key()] = true
		out = append(out, c)
	}
	return out
}

// ArchConsistent reports whether every constant arch fact accepts val.
func (f *PathFacts) ArchConsistent(val uint32) bool {
	for _, c := range f.path {
		if !c.PlainDataFact(consts.Arch) {
			continue
		}
		if !symbolic.Evaluate(val, c.Op(), c.Rhs().Val()) {
			return false
		}
	}
	return true
}

// CatchAll reports whether the path matches no syscall, range, or argument.
func (f *PathFacts) CatchAll() bool {
	return f.SysEq == nil && f.SysRange == nil && len(f.Residual) == 0
}

// Section is one architecture's view of the filter.
type Section struct {
	ArchVal *uint32
	ArchSym string
	Title   string
	Leaves  []*executor.Leaf
}

// Analysis derives the common groundwork every consumer of a walk needs.
type Analysis struct {
	leaves    []*executor.Leaf
	facts     map[*executor.Leaf]*PathFacts
	archVals  []uint32
	archReady bool
}

// NewAnalysis builds an analysis over a walk.
func NewAnalysis(leaves []*executor.Leaf) *Analysis {
	return &Analysis{leaves: leaves, facts: map[*executor.Leaf]*PathFacts{}}
}

// Facts returns leaf's path facts, computed once.
func (a *Analysis) Facts(leaf *executor.Leaf) *PathFacts {
	if f, ok := a.facts[leaf]; ok {
		return f
	}
	f := NewPathFacts(leaf.Path)
	a.facts[leaf] = f
	return f
}

// ArchValues returns the distinct architecture values the filter branches on.
func (a *Analysis) ArchValues() []uint32 {
	if a.archReady {
		return a.archVals
	}
	a.archReady = true
	for _, l := range a.leaves {
		if v := a.Facts(l).ArchEq; v != nil {
			dup := false
			for _, old := range a.archVals {
				if old == *v {
					dup = true
					break
				}
			}
			if !dup {
				a.archVals = append(a.archVals, *v)
			}
		}
	}
	return a.archVals
}

// Sections splits the walk into architecture sections.
func (a *Analysis) Sections(declared string) []Section {
	vals := a.ArchValues()
	if len(vals) == 0 {
		return []Section{{ArchSym: declared, Title: declared, Leaves: a.leaves}}
	}
	out := make([]Section, 0, len(vals))
	for i := range vals {
		v := vals[i]
		sym, ok := consts.AuditArchSymbol(v)
		title := sym
		if !ok {
			title = fmt.Sprintf("0x%x (unknown)", v)
		}
		var leaves []*executor.Leaf
		for _, l := range a.leaves {
			if a.Facts(l).ArchConsistent(v) {
				leaves = append(leaves, l)
			}
		}
		av := v
		out = append(out, Section{ArchVal: &av, ArchSym: sym, Title: title, Leaves: leaves})
	}
	return out
}

// OtherLeaves returns leaves reachable when arch is none of the checked values.
func (a *Analysis) OtherLeaves() []*executor.Leaf {
	var out []*executor.Leaf
	for _, l := range a.leaves {
		if a.Facts(l).ArchEq == nil {
			out = append(out, l)
		}
	}
	return out
}

// DefaultLabel returns the catch-all action label of leaves, or false.
func (a *Analysis) DefaultLabel(leaves []*executor.Leaf) (string, bool) {
	var chosen *executor.Leaf
	for _, l := range leaves {
		if a.Facts(l).CatchAll() {
			chosen = l
			break
		}
	}
	if chosen == nil && len(leaves) > 0 {
		chosen = leaves[0]
	}
	if chosen == nil {
		return "", false
	}
	return VerdictLabel(chosen.Ret), true
}
