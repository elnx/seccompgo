package explain_test

import (
	"strings"
	"testing"

	"seccompgo/internal/explain"
	"seccompgo/internal/symbolic"
	"seccompgo/internal/symbolic/executor"
)

func con(off uint32, op string, val uint64) *symbolic.Constraint {
	return symbolic.NewConstraint(symbolic.DataWord(off), op, symbolic.Imm(val))
}

func flat(list []explain.Fact) [][]any {
	var out [][]any
	for _, f := range list {
		switch v := f.(type) {
		case *explain.Qword:
			out = append(out, []any{"qword", v.Base, v.Op, v.Val})
		case *symbolic.Constraint:
			out = append(out, []any{v.Lhs().Offset(), v.Op(), uint64(v.Rhs().Val())})
		}
	}
	return out
}

func TestQwordKeyAndOrder(t *testing.T) {
	q := &explain.Qword{Base: 16, Op: "==", Val: 0x100000002}
	if q.Key() != "q16,==,4294967298" {
		t.Fatalf("key = %s", q.Key())
	}
	le := explain.NewQwordFusion("amd64")
	if le.LoOff(16) != 16 || le.HiOff(16) != 20 {
		t.Fatal("little endian order")
	}
	be := explain.NewQwordFusion("s390x")
	if be.LoOff(16) != 20 || be.HiOff(16) != 16 {
		t.Fatal("big endian order")
	}
}

func TestQwordFold(t *testing.T) {
	f := explain.NewQwordFusion("amd64")
	got := flat(f.Fold([]explain.Fact{con(20, "==", 1), con(16, "==", 2)}))
	if len(got) != 1 || got[0][1] != uint32(16) || got[0][2] != "==" || got[0][3] != uint64(0x100000002) {
		t.Fatalf("fold ==: %#v", got)
	}
	got = flat(f.Fold([]explain.Fact{con(20, "==", 0), con(16, "<", 0x1000)}))
	if len(got) != 1 || got[0][2] != "<" || got[0][3] != uint64(0x1000) {
		t.Fatalf("fold bound: %#v", got)
	}
	got = flat(f.Fold([]explain.Fact{con(20, "==", 1)}))
	if len(got) != 1 || got[0][0] != uint32(20) {
		t.Fatalf("fold half: %#v", got)
	}
}

func TestQwordMergeOr(t *testing.T) {
	f := explain.NewQwordFusion("amd64")
	for _, tc := range []struct {
		hiOp, loOp, want string
	}{
		{">", ">", ">"}, {">", ">=", ">="}, {"<", "<", "<"}, {"<", "<=", "<="}, {"!=", "!=", "!="},
	} {
		lists := [][]explain.Fact{
			{con(20, tc.hiOp, 2)},
			{con(20, "==", 2), con(16, tc.loOp, 0x500)},
		}
		merged := f.MergeOr(lists)
		if len(merged) != 1 {
			t.Fatalf("%s: lists = %d", tc.loOp, len(merged))
		}
		got := flat(merged[0])
		if len(got) != 1 || got[0][2] != tc.want || got[0][3] != uint64(0x200000500) {
			t.Fatalf("%s: %#v", tc.loOp, got)
		}
	}
	lists := [][]explain.Fact{
		{con(20, ">=", 3)},
		{con(20, "==", 2), con(16, ">=", 0x10)},
	}
	got := flat(f.MergeOr(lists)[0])
	if len(got) != 1 || got[0][2] != ">=" || got[0][3] != uint64(0x200000010) {
		t.Fatalf("normalized: %#v", got)
	}
	for _, tc := range []struct {
		hiOp string
		val  uint64
		lo   uint64
	}{
		{">=", 0, 0x10},
		{"<=", 0xffffffff, 0x10},
	} {
		lists = [][]explain.Fact{
			{con(20, tc.hiOp, tc.val)},
			{con(20, "==", tc.val), con(16, ">=", tc.lo)},
		}
		merged := f.MergeOr(lists)
		if len(merged) != 2 {
			t.Fatalf("boundary fused: %#v", merged)
		}
	}
	lists = [][]explain.Fact{{con(0, "==", 1)}, {con(0, "==", 2)}}
	if merged := f.MergeOr(lists); len(merged) != 2 {
		t.Fatalf("unrelated merged: %#v", merged)
	}
}

func TestRenderer(t *testing.T) {
	r := explain.NewRenderer(explain.NewQwordFusion("amd64"))
	render := func(c *symbolic.Constraint) string { return r.Conjunction([]explain.Fact{c}, nil) }
	cases := []struct {
		c    *symbolic.Constraint
		want string
	}{
		{con(0, "==", 1), "sys_number == 0x1"},
		{con(4, "==", 1), "arch == 0x1"},
		{con(8, "==", 1), "instruction_pointer == 0x1"},
		{con(16, "==", 1), "args[0] == 0x1"},
		{con(20, "==", 1), "args[0] >> 32 == 0x1"},
		{con(16, "set", 0x101), "(args[0] & 0x101) != 0"},
		{con(16, "unset", 0x101), "(args[0] & 0x101) == 0"},
	}
	for _, tc := range cases {
		if got := render(tc.c); got != tc.want {
			t.Errorf("render = %q, want %q", got, tc.want)
		}
	}
	read := "read"
	if got := r.Conjunction([]explain.Fact{con(16, "==", 1)}, &read); got != "fd == 0x1" {
		t.Errorf("syscall arg name = %q", got)
	}
	be := explain.NewRenderer(explain.NewQwordFusion("s390x"))
	if got := be.Conjunction([]explain.Fact{con(16, "==", 1)}, nil); got != "args[0] >> 32 == 0x1" {
		t.Errorf("big endian = %q", got)
	}
	bin, _ := symbolic.DataWord(16).Apply("&", symbolic.Imm(0xff))
	if got := render(symbolic.NewConstraint(bin, "==", symbolic.Imm(5))); got != "(args[0] & 0xff) == 0x5" {
		t.Errorf("precedence = %q", got)
	}
	shift, _ := symbolic.DataWord(16).Apply(">>", symbolic.Imm(4))
	if got := render(symbolic.NewConstraint(shift, "==", symbolic.Imm(5))); got != "args[0] >> 4 == 0x5" {
		t.Errorf("shift = %q", got)
	}
	add, _ := symbolic.DataWord(24).Apply("+", symbolic.Imm(1))
	mix, _ := symbolic.DataWord(16).Apply("&", add)
	if got := render(symbolic.NewConstraint(mix, "==", symbolic.Imm(5))); got != "(args[0] & (args[1] + 0x1)) == 0x5" {
		t.Errorf("mixed = %q", got)
	}
	neg, _ := symbolic.DataWord(16).Apply("neg", nil)
	if got := render(symbolic.NewConstraint(neg, "==", symbolic.Imm(1))); got != "-args[0] == 0x1" {
		t.Errorf("neg = %q", got)
	}
}

func TestPathFacts(t *testing.T) {
	mk := func(cs ...*symbolic.Constraint) *explain.PathFacts { return explain.NewPathFacts(cs) }
	f := mk(con(0, "==", 5))
	if f.SysEq == nil || *f.SysEq != 5 {
		t.Fatal("sys_eq")
	}
	f = mk(con(4, "==", 0xc000003e))
	if f.ArchEq == nil || *f.ArchEq != 0xc000003e {
		t.Fatal("arch_eq")
	}
	if mk(con(0, ">", 5)).SysEq != nil || mk(con(16, "==", 5)).SysEq != nil {
		t.Fatal("false pins")
	}
	f = mk(con(0, ">=", 0x100), con(0, "<", 0x200))
	if f.SysRange == nil || f.SysRange.Lo != 0x100 || !f.SysRange.HasHi || f.SysRange.Hi != 0x1ff {
		t.Fatalf("range = %+v", f.SysRange)
	}
	f = mk(con(0, ">", 0xff))
	if f.SysRange == nil || f.SysRange.Lo != 0x100 || f.SysRange.HasHi {
		t.Fatalf("lower range = %+v", f.SysRange)
	}
	if mk(con(0, "<", 0x40000000)).SysRange != nil {
		t.Fatal("upper-only range")
	}
	f = mk(con(0, "==", 5), con(4, "==", 0xc000003e))
	if len(f.Residual) != 0 {
		t.Fatalf("residual = %#v", f.Residual)
	}
	if len(mk(con(0, ">=", 0x100)).Residual) != 0 {
		t.Fatal("range fact residual")
	}
	f = mk(con(0, "set", 1), con(16, "==", 3))
	if len(f.Residual) != 2 {
		t.Fatalf("residual kept = %d", len(f.Residual))
	}
	f = mk(con(16, "==", 3), con(16, ">", 0))
	if len(f.Residual) != 1 || f.Residual[0].Op() != "==" {
		t.Fatalf("pinned residual = %#v", f.Residual)
	}
	if len(mk(con(16, "==", 3), con(16, "==", 3)).Residual) != 1 {
		t.Fatal("residual dedup")
	}
	masked, _ := symbolic.DataWord(16).Apply("&", symbolic.Imm(0xff))
	pin := symbolic.NewConstraint(masked, "==", symbolic.Imm(4))
	other := symbolic.NewConstraint(masked, "!=", symbolic.Imm(3))
	if got := mk(other, pin).Residual; len(got) != 1 || !got[0].Equal(pin) {
		t.Fatalf("transform residual = %#v", got)
	}
	pinOpaque := symbolic.NewConstraint(symbolic.Opaque(), "==", symbolic.Imm(1))
	otherOpaque := symbolic.NewConstraint(symbolic.Opaque(), "!=", symbolic.Imm(2))
	if len(mk(pinOpaque, otherOpaque).Residual) != 2 {
		t.Fatal("opaque residual")
	}
	if !mk(con(4, "==", 0xc000003e)).ArchConsistent(0xc000003e) ||
		mk(con(4, "==", 0xc000003e)).ArchConsistent(0x40000003) {
		t.Fatal("arch consistency")
	}
	if !mk(con(4, "set", 0x80000000)).ArchConsistent(0xc000003e) ||
		mk(con(4, "set", 0x80000000)).ArchConsistent(0x40000003) {
		t.Fatal("arch bit consistency")
	}
	if !mk(con(4, "unset", 0x40000000)).ArchConsistent(0x80000016) ||
		mk(con(4, "unset", 0x40000000)).ArchConsistent(0xc000003e) {
		t.Fatal("arch unset consistency")
	}
	if !mk().CatchAll() || mk(con(0, "==", 5)).CatchAll() ||
		mk(con(0, ">=", 1)).CatchAll() || mk(con(16, "==", 3)).CatchAll() {
		t.Fatal("catch all")
	}
}

func leaf(ret uint32, path ...*symbolic.Constraint) *executor.Leaf {
	return &executor.Leaf{Path: path, Ret: symbolic.Imm(uint64(ret)), Line: 0}
}

func TestVerdict(t *testing.T) {
	cases := map[uint32]string{
		0x7fff0000: "ALLOW",
		0:          "KILL",
		0x80000000: "KILL_PROCESS",
		0x00050005: "ERRNO(5)",
		0x7ff00007: "TRACE(7)",
		0x00030005: "TRAP(5)",
		0x7ff00000: "TRACE",
		0x00030000: "TRAP",
		0x12345678: "KILL_PROCESS (unknown action 0x12345678)",
	}
	for v, want := range cases {
		if got := explain.VerdictLabel(symbolic.Imm(uint64(v))); got != want {
			t.Errorf("label(%#x) = %q, want %q", v, got, want)
		}
	}
	if got := explain.VerdictLabel(symbolic.DataWord(0)); got != "UNKNOWN" {
		t.Errorf("unknown = %q", got)
	}
	if idx, _ := explain.VerdictRank("ALLOW"); idx != 0 {
		t.Fatal("ALLOW rank")
	}
	if idx, _ := explain.VerdictRank("KILL"); idx != 6 {
		t.Fatal("KILL rank")
	}
	a, _ := explain.VerdictRank("ERRNO(5)")
	b, _ := explain.VerdictRank("ERRNO(1)")
	if a != b {
		t.Fatal("ERRNO ranks differ")
	}
}

func TestSummaryHandBuilt(t *testing.T) {
	src := "a.bpf"
	out := explain.NewSummary([]*executor.Leaf{leaf(0x7fff0000)}, "amd64", &src, false).String()
	if !strings.HasPrefix(out, "Seccomp policy for a.bpf\n\nArchitecture: amd64\n") {
		t.Fatalf("header: %q", out)
	}
	out = explain.NewSummary(nil, "amd64", nil, true).String()
	if !strings.Contains(out, "analysis truncated") {
		t.Fatal("truncation warning")
	}
	out = explain.NewSummary(nil, "amd64", nil, false).String()
	if !strings.Contains(out, "no return reached") {
		t.Fatal("no return note")
	}
	out = explain.NewSummary([]*executor.Leaf{leaf(0x12345678)}, "amd64", nil, false).String()
	if !strings.Contains(out, "KILL_PROCESS (unknown action 0x12345678):") {
		t.Fatal("unknown action label")
	}
	path := []*symbolic.Constraint{con(0, "==", 5)}
	out = explain.NewSummary([]*executor.Leaf{leaf(0x7fff0000, path...), leaf(0)}, "nonesuch", nil, false).String()
	if !strings.Contains(out, "0x5") {
		t.Fatalf("numeric syscall: %s", out)
	}
	path = []*symbolic.Constraint{con(0, "==", 59), con(20, "==", 0x7ffe), con(16, "==", 0xa12f7d0e)}
	out = explain.NewSummary([]*executor.Leaf{leaf(0x7fff0000, path...), leaf(0)}, "amd64", nil, false).String()
	if !strings.Contains(out, "execve when filename == 0x7ffea12f7d0e") {
		t.Fatalf("qword syscall: %s", out)
	}
	path = []*symbolic.Constraint{con(0, "==", 1)}
	out = explain.NewSummary([]*executor.Leaf{leaf(0x7fff0000, path...), leaf(0)}, "amd64", nil, true).String()
	if !strings.Contains(out, "<default> (any other syscall; incomplete)") {
		t.Fatalf("default incomplete: %s", out)
	}
	out = explain.NewSummary([]*executor.Leaf{leaf(0)}, "amd64", nil, true).String()
	if !strings.Contains(out, "<default> (any syscall; incomplete)") {
		t.Fatalf("whole default incomplete: %s", out)
	}
}
