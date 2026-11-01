package executor_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/elnx/seccompgo/internal/bpf"
	"github.com/elnx/seccompgo/internal/consts"
	"github.com/elnx/seccompgo/internal/disasm"
	"github.com/elnx/seccompgo/internal/instruction"
	"github.com/elnx/seccompgo/internal/symbolic"
	"github.com/elnx/seccompgo/internal/symbolic/executor"
)

func cmd(command string, parts map[string]string) uint16 {
	code := consts.Command[command]
	maps := []map[string]uint16{consts.Jmp, consts.Mode, consts.Op, consts.MiscOp, consts.Src}
	for _, name := range parts {
		for _, m := range maps {
			code |= m[name]
		}
	}
	return code
}

func inst(t *testing.T, code uint16, jt, jf uint8, k uint32) instruction.Inst {
	t.Helper()
	i, err := instruction.New(bpf.FromFields(code, jt, jf, k, "amd64", 0))
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func run(t *testing.T, insts []instruction.Inst) ([]*executor.Leaf, bool) {
	t.Helper()
	leaves, truncated, err := executor.NewExecutor(insts).Run()
	if err != nil {
		t.Fatal(err)
	}
	return leaves, truncated
}

func runRets(t *testing.T, insts []instruction.Inst) []uint32 {
	t.Helper()
	leaves, _ := run(t, insts)
	return rets(leaves)
}

func rets(leaves []*executor.Leaf) []uint32 {
	out := make([]uint32, 0, len(leaves))
	for _, l := range leaves {
		out = append(out, l.Ret.Val())
	}
	return out
}

func contains(xs []uint32, x uint32) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func TestExecutorEveryInstruction(t *testing.T) {
	insts := []instruction.Inst{
		inst(t, cmd("ldx", map[string]string{"mode": "imm"}), 0, 0, 7),
		inst(t, cmd("ld", map[string]string{"mode": "abs"}), 0, 0, 0),
		inst(t, cmd("st", nil), 0, 0, 3),
		inst(t, cmd("stx", nil), 0, 0, 4),
		inst(t, cmd("ld", map[string]string{"mode": "mem"}), 0, 0, 3),
		inst(t, cmd("ld", map[string]string{"mode": "imm"}), 0, 0, 9),
		inst(t, cmd("alu", map[string]string{"op": "and", "src": "k"}), 0, 0, 0xff),
		inst(t, cmd("alu", map[string]string{"op": "add", "src": "x"}), 0, 0, 0),
		inst(t, cmd("misc", map[string]string{"misc": "tax"}), 0, 0, 0),
		inst(t, cmd("misc", map[string]string{"misc": "txa"}), 0, 0, 0),
		inst(t, cmd("jmp", map[string]string{"jmp": "ja"}), 0, 0, 0),
		inst(t, cmd("ret", nil), 0, 0, 0x7fff0000),
	}
	leaves, truncated := run(t, insts)
	if truncated {
		t.Fatal("truncated")
	}
	if got := rets(leaves); len(got) != 1 || got[0] != 0x7fff0000 {
		t.Fatalf("rets = %#v", got)
	}
	if leaves[0].Line != 11 {
		t.Fatalf("line = %d", leaves[0].Line)
	}
}

func TestExecutorReturnA(t *testing.T) {
	leaves, _ := run(t, []instruction.Inst{
		inst(t, cmd("ld", map[string]string{"mode": "imm"}), 0, 0, 5),
		inst(t, cmd("ret", map[string]string{"src": "a"}), 0, 0, 0),
	})
	if !leaves[0].Ret.Equal(symbolic.Imm(5)) {
		t.Fatalf("ret = %v", leaves[0].Ret)
	}
	leaves, _ = run(t, []instruction.Inst{inst(t, cmd("ret", map[string]string{"src": "a"}), 0, 0, 0)})
	if !leaves[0].Ret.Equal(symbolic.Imm(0)) {
		t.Fatalf("initial A ret = %v", leaves[0].Ret)
	}
}

func TestExecutorConstantComparison(t *testing.T) {
	insts := []instruction.Inst{
		inst(t, cmd("jmp", map[string]string{"jmp": "jeq", "src": "x"}), 0, 1, 0),
		inst(t, cmd("ret", nil), 0, 0, 0x7fff0000),
		inst(t, cmd("ret", nil), 0, 0, 0),
	}
	leaves, _ := run(t, insts)
	if got := rets(leaves); len(got) != 1 || got[0] != 0x7fff0000 {
		t.Fatalf("rets = %#v", got)
	}
	if len(leaves[0].Path) != 0 {
		t.Fatalf("path = %v", leaves[0].Path)
	}
}

func TestExecutorLibseccompLeaves(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "data", "libseccomp.bpf"))
	if err != nil {
		t.Fatal(err)
	}
	codes, err := disasm.ToBPF(raw, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	var insts []instruction.Inst
	for _, c := range codes {
		i, _ := instruction.New(c)
		insts = append(insts, i)
	}
	leaves, _ := run(t, insts)
	got := rets(leaves)
	for _, want := range []uint32{0x7fff0000, 0x00050005, 0} {
		if !contains(got, want) {
			t.Fatalf("missing ret %#x in %#v", want, got)
		}
	}
	found := false
	for _, l := range leaves {
		if l.Ret.Val() == 0x7fff0000 && len(l.Path) == 3 {
			found = true
		}
	}
	if !found {
		t.Fatal("no 3-fact ALLOW leaf")
	}
}

func TestExecutorNarrowX(t *testing.T) {
	insts := []instruction.Inst{
		inst(t, cmd("ldx", map[string]string{"mode": "imm"}), 0, 0, 1),
		inst(t, cmd("ld", map[string]string{"mode": "abs"}), 0, 0, 0),
		inst(t, cmd("jmp", map[string]string{"jmp": "jeq", "src": "x"}), 0, 1, 0),
		inst(t, cmd("ret", nil), 0, 0, 0x7fff0000),
		inst(t, cmd("ret", nil), 0, 0, 0),
	}
	got := runRets(t, insts)
	if !contains(got, 0x7fff0000) || !contains(got, 0) {
		t.Fatalf("rets = %#v", got)
	}
}

func TestExecutorDataToData(t *testing.T) {
	insts := []instruction.Inst{
		inst(t, cmd("ld", map[string]string{"mode": "abs"}), 0, 0, 16),
		inst(t, cmd("misc", map[string]string{"misc": "tax"}), 0, 0, 0),
		inst(t, cmd("ld", map[string]string{"mode": "abs"}), 0, 0, 24),
		inst(t, cmd("alu", map[string]string{"op": "and", "src": "x"}), 0, 0, 0),
		inst(t, cmd("jmp", map[string]string{"jmp": "jeq"}), 0, 1, 5),
		inst(t, cmd("ret", nil), 0, 0, 0x7fff0000),
		inst(t, cmd("ret", nil), 0, 0, 0),
	}
	leaves, _ := run(t, insts)
	var expr *symbolic.Expr
	for _, l := range leaves {
		if l.Ret.Val() == 0x7fff0000 {
			expr = l.Path[0].Lhs()
		}
	}
	if expr == nil || expr.Kind() != symbolic.KindBinop || expr.Op() != "&" ||
		!expr.Lhs().Equal(symbolic.DataWord(24)) || !expr.Rhs().Equal(symbolic.DataWord(16)) {
		t.Fatalf("expr = %+v", expr)
	}
}

func TestExecutorUnaryNeg(t *testing.T) {
	insts := []instruction.Inst{
		inst(t, cmd("ld", map[string]string{"mode": "abs"}), 0, 0, 16),
		inst(t, cmd("alu", map[string]string{"op": "neg"}), 0, 0, 0),
		inst(t, cmd("jmp", map[string]string{"jmp": "jeq"}), 0, 1, 5),
		inst(t, cmd("ret", nil), 0, 0, 0x7fff0000),
		inst(t, cmd("ret", nil), 0, 0, 0),
	}
	leaves, _ := run(t, insts)
	var expr *symbolic.Expr
	for _, l := range leaves {
		if l.Ret.Val() == 0x7fff0000 {
			expr = l.Path[0].Lhs()
		}
	}
	if expr == nil || expr.Kind() != symbolic.KindUnop || expr.Op() != "neg" ||
		!expr.Lhs().Equal(symbolic.DataWord(16)) {
		t.Fatalf("expr = %+v", expr)
	}
}

func TestExecutorEqualJumpTargets(t *testing.T) {
	insts := []instruction.Inst{
		inst(t, cmd("ld", map[string]string{"mode": "abs"}), 0, 0, 0),
		inst(t, cmd("jmp", map[string]string{"jmp": "jeq"}), 1, 1, 5),
		inst(t, cmd("ret", nil), 0, 0, 0),
		inst(t, cmd("ret", nil), 0, 0, 0x7fff0000),
	}
	leaves, _ := run(t, insts)
	if got := rets(leaves); len(got) != 1 || got[0] != 0x7fff0000 {
		t.Fatalf("rets = %#v", got)
	}
	if len(leaves[0].Path) != 0 {
		t.Fatalf("path = %v", leaves[0].Path)
	}
}

func TestExecutorRunsOffEnd(t *testing.T) {
	leaves, _ := run(t, []instruction.Inst{inst(t, cmd("ld", map[string]string{"mode": "abs"}), 0, 0, 0)})
	if len(leaves) != 0 {
		t.Fatalf("leaves = %#v", leaves)
	}
}

func TestExecutorStepCap(t *testing.T) {
	old := executor.StepCap
	executor.StepCap = 1
	defer func() { executor.StepCap = old }()
	_, truncated := run(t, []instruction.Inst{
		inst(t, cmd("ld", map[string]string{"mode": "abs"}), 0, 0, 0),
		inst(t, cmd("ret", nil), 0, 0, 0),
	})
	if !truncated {
		t.Fatal("not truncated")
	}
}

func TestExecutorRejoiningDiamonds(t *testing.T) {
	n := 11
	var insts []instruction.Inst
	for i := 0; i < n; i++ {
		insts = append(insts,
			inst(t, cmd("ld", map[string]string{"mode": "abs"}), 0, 0, uint32(i*4)),
			inst(t, cmd("jmp", map[string]string{"jmp": "jeq", "src": "k"}), 1, 0, uint32(0x1000+i)),
			inst(t, cmd("jmp", map[string]string{"jmp": "ja"}), 0, 0, 0),
		)
	}
	insts = append(insts, inst(t, cmd("ret", nil), 0, 0, 0x7fff0000))
	done := make(chan struct{})
	var leaves []*executor.Leaf
	go func() {
		leaves, _ = run(t, insts)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("walk too slow")
	}
	if len(leaves) != 1<<n {
		t.Fatalf("leaves = %d, want %d", len(leaves), 1<<n)
	}
}

func TestExecutorFeasibility(t *testing.T) {
	// A == 1 then A == 2 never reaches ALLOW.
	insts := []instruction.Inst{
		inst(t, cmd("ld", map[string]string{"mode": "abs"}), 0, 0, 0),
		inst(t, cmd("jmp", map[string]string{"jmp": "jeq"}), 0, 1, 1),
		inst(t, cmd("jmp", map[string]string{"jmp": "jeq"}), 1, 0, 2),
		inst(t, cmd("ret", nil), 0, 0, 0),
		inst(t, cmd("ret", nil), 0, 0, 0x7fff0000),
	}
	if got := runRets(t, insts); contains(got, 0x7fff0000) {
		t.Fatalf("impossible path allowed: %#v", got)
	}
	// A > 10 && A == 5 is impossible.
	insts = []instruction.Inst{
		inst(t, cmd("ld", map[string]string{"mode": "abs"}), 0, 0, 0),
		inst(t, cmd("jmp", map[string]string{"jmp": "jgt"}), 0, 3, 10),
		inst(t, cmd("jmp", map[string]string{"jmp": "jeq"}), 1, 2, 5),
		inst(t, cmd("ret", nil), 0, 0, 0),
		inst(t, cmd("ret", nil), 0, 0, 0x7fff0000),
		inst(t, cmd("ret", nil), 0, 0, 0),
	}
	if got := runRets(t, insts); contains(got, 0x7fff0000) {
		t.Fatalf("range contradiction allowed: %#v", got)
	}
	// (A & 0xff) == 3 and == 4 cannot both hold.
	insts = []instruction.Inst{
		inst(t, cmd("ld", map[string]string{"mode": "abs"}), 0, 0, 0),
		inst(t, cmd("alu", map[string]string{"op": "and", "src": "k"}), 0, 0, 0xff),
		inst(t, cmd("jmp", map[string]string{"jmp": "jeq"}), 0, 1, 3),
		inst(t, cmd("jmp", map[string]string{"jmp": "jeq"}), 1, 0, 4),
		inst(t, cmd("ret", nil), 0, 0, 0),
		inst(t, cmd("ret", nil), 0, 0, 0x7fff0000),
	}
	if got := runRets(t, insts); contains(got, 0x7fff0000) {
		t.Fatalf("derived contradiction allowed: %#v", got)
	}
	// Distinct opaque values pinned to 1 and 2 are feasible.
	insts = []instruction.Inst{
		inst(t, cmd("ld", map[string]string{"mode": "mem"}), 0, 0, 0),
		inst(t, cmd("jmp", map[string]string{"jmp": "jeq"}), 0, 2, 1),
		inst(t, cmd("ld", map[string]string{"mode": "mem"}), 0, 0, 1),
		inst(t, cmd("jmp", map[string]string{"jmp": "jeq"}), 1, 0, 2),
		inst(t, cmd("ret", nil), 0, 0, 0),
		inst(t, cmd("ret", nil), 0, 0, 0x7fff0000),
	}
	if got := runRets(t, insts); !contains(got, 0x7fff0000) {
		t.Fatalf("opaque path dropped: %#v", got)
	}
	// Range emptiness keeps A <= 10 and A > 10 && A >= 5.
	insts = []instruction.Inst{
		inst(t, cmd("ld", map[string]string{"mode": "abs"}), 0, 0, 0),
		inst(t, cmd("jmp", map[string]string{"jmp": "jgt"}), 1, 0, 10),
		inst(t, cmd("ret", nil), 0, 0, 0x1111),
		inst(t, cmd("jmp", map[string]string{"jmp": "jge"}), 1, 0, 5),
		inst(t, cmd("ret", nil), 0, 0, 0x2222),
		inst(t, cmd("ret", nil), 0, 0, 0x3333),
	}
	got := runRets(t, insts)
	if !contains(got, 0x1111) || !contains(got, 0x3333) || contains(got, 0x2222) {
		t.Fatalf("range rets = %#v", got)
	}
}
