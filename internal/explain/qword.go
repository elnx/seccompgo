package explain

import (
	"fmt"

	"github.com/elnx/seccompgo/internal/consts"
	"github.com/elnx/seccompgo/internal/symbolic"
)

// Fact is a rendered path fact: either a *symbolic.Constraint or a *Qword.
type Fact interface {
	Key() string
}

// Qword is a 64-bit field fact reassembled from two 32-bit word checks.
type Qword struct {
	Base uint32
	Op   string
	Val  uint64
}

// Key mirrors Constraint.Key so fused lists stay comparable.
func (q *Qword) Key() string {
	return fmt.Sprintf("q%d,%s,%d", q.Base, q.Op, q.Val)
}

// QwordFusion fuses 32-bit word facts back into whole-field facts.
type QwordFusion struct {
	hiFirst bool
}

// NewQwordFusion builds a fusion for arch's word order.
func NewQwordFusion(arch string) *QwordFusion {
	return &QwordFusion{hiFirst: consts.BigEndian(arch)}
}

// LoOff is the byte offset of the low word of the field at base.
func (f *QwordFusion) LoOff(base uint32) uint32 {
	if f.hiFirst {
		return base + 4
	}
	return base
}

// HiOff is the byte offset of the high word of the field at base.
func (f *QwordFusion) HiOff(base uint32) uint32 {
	if f.hiFirst {
		return base
	}
	return base + 4
}

// BaseOf is the byte offset of the 64-bit field containing offset.
func (f *QwordFusion) BaseOf(offset uint32) uint32 {
	return offset - offset%8
}

func isQwordBase(base uint32) bool {
	for _, b := range consts.QwordBases {
		if b == base {
			return true
		}
	}
	return false
}

// Fold fuses the word facts of one path condition; unpaired facts pass through.
func (f *QwordFusion) Fold(facts []Fact) []Fact {
	eqs := map[uint32]*symbolic.Constraint{}
	for _, fact := range facts {
		c, ok := fact.(*symbolic.Constraint)
		if !ok || !c.PlainDataEq(-1) {
			continue
		}
		if _, seen := eqs[c.Lhs().Offset()]; !seen {
			eqs[c.Lhs().Offset()] = c
		}
	}
	replace := map[*symbolic.Constraint]*Qword{}
	drop := map[*symbolic.Constraint]bool{}
	for _, base := range consts.QwordBases {
		hi := eqs[f.HiOff(base)]
		if hi == nil {
			continue
		}
		if lo := eqs[f.LoOff(base)]; lo != nil {
			replace[lo] = &Qword{Base: base, Op: "==", Val: uint64(hi.Rhs().Val())<<32 | uint64(lo.Rhs().Val())}
		} else if hi.Rhs().Val() == 0 {
			if lo := f.loBound(facts, f.LoOff(base)); lo != nil {
				replace[lo] = &Qword{Base: base, Op: lo.Op(), Val: uint64(lo.Rhs().Val())}
			} else {
				continue
			}
		} else {
			continue
		}
		drop[hi] = true
	}
	out := make([]Fact, 0, len(facts))
	for _, fact := range facts {
		c, ok := fact.(*symbolic.Constraint)
		if !ok {
			out = append(out, fact)
			continue
		}
		if drop[c] {
			continue
		}
		if q, ok := replace[c]; ok {
			out = append(out, q)
		} else {
			out = append(out, c)
		}
	}
	return out
}

func (f *QwordFusion) loBound(facts []Fact, off uint32) *symbolic.Constraint {
	for _, fact := range facts {
		c, ok := fact.(*symbolic.Constraint)
		if ok && c.PlainDataFact(int(off)) && (c.Op() == "<" || c.Op() == "<=") {
			return c
		}
	}
	return nil
}

type opPair struct{ hi, lo string }

var orMerge = map[opPair]string{
	{"<", "<"}: "<", {"<", "<="}: "<=",
	{">", ">"}: ">", {">", ">="}: ">=",
	{"!=", "!="}: "!=",
}

// MergeOr fuses sibling or-branches expressing one 64-bit comparison.
func (f *QwordFusion) MergeOr(lists [][]Fact) [][]Fact {
	out := append([][]Fact(nil), lists...)
	for {
		var ok bool
		out, ok = f.mergeOnePair(out)
		if !ok {
			break
		}
	}
	return out
}

func (f *QwordFusion) mergeOnePair(lists [][]Fact) ([][]Fact, bool) {
	for i := range lists {
		for j := range lists {
			if i == j {
				continue
			}
			fused, ok := f.fusePair(lists[i], lists[j])
			if !ok {
				continue
			}
			lo, hi := i, j
			if lo > hi {
				lo, hi = hi, lo
			}
			lists[lo] = fused
			lists = append(lists[:hi], lists[hi+1:]...)
			return lists, true
		}
	}
	return lists, false
}

func minus(a, b []Fact) []Fact {
	keys := map[string]bool{}
	for _, x := range b {
		keys[x.Key()] = true
	}
	var out []Fact
	for _, x := range a {
		if !keys[x.Key()] {
			out = append(out, x)
		}
	}
	return out
}

func (f *QwordFusion) fusePair(a, b []Fact) ([]Fact, bool) {
	onlyA := minus(a, b)
	if len(onlyA) != 1 {
		return nil, false
	}
	hi, ok := onlyA[0].(*symbolic.Constraint)
	if !ok || !hi.PlainDataFact(-1) {
		return nil, false
	}
	base := f.BaseOf(hi.Lhs().Offset())
	if !isQwordBase(base) || hi.Lhs().Offset() != f.HiOff(base) {
		return nil, false
	}
	hiOp, hiVal := strict(hi.Op(), int64(hi.Rhs().Val()))
	onlyB := minus(b, a)
	var eq, lo *symbolic.Constraint
	for _, x := range onlyB {
		c, ok := x.(*symbolic.Constraint)
		if !ok {
			continue
		}
		if eq == nil && c.PlainDataEq(int(hi.Lhs().Offset())) && int64(c.Rhs().Val()) == hiVal {
			eq = c
		}
		if lo == nil && c.PlainDataFact(int(f.LoOff(base))) {
			lo = c
		}
	}
	if len(onlyB) != 2 || eq == nil || lo == nil {
		return nil, false
	}
	op, ok := orMerge[opPair{hiOp, lo.Op()}]
	if !ok {
		return nil, false
	}
	out := make([]Fact, 0, len(b))
	for _, x := range b {
		if c, ok := x.(*symbolic.Constraint); ok {
			if c == eq {
				out = append(out, &Qword{Base: base, Op: op,
					Val: uint64(hiVal)<<32 | uint64(lo.Rhs().Val())})
				continue
			}
			if c == lo {
				continue
			}
		}
		out = append(out, x)
	}
	return out, true
}

func strict(op string, val int64) (string, int64) {
	switch op {
	case ">=":
		return ">", val - 1
	case "<=":
		return "<", val + 1
	}
	return op, val
}
