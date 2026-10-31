package symbolic

import "testing"

func TestExprKinds(t *testing.T) {
	e := Imm(0x1_0000_0005)
	if !e.IsImm() || e.IsOpaque() || e.PlainData() || e.Val() != 5 {
		t.Fatalf("bad imm: %+v", e)
	}
	d := DataWord(16)
	if !d.PlainData() || d.Offset() != 16 {
		t.Fatalf("bad data: %+v", d)
	}
	if !Opaque().IsOpaque() {
		t.Fatal("opaque")
	}
}

func TestExprApply(t *testing.T) {
	must := func(e *Expr, err error) *Expr {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	if v := must(Imm(6).Apply("+", Imm(7))).Val(); v != 13 {
		t.Fatalf("6+7 = %d", v)
	}
	if v := must(Imm(1).Apply("<<", Imm(4))).Val(); v != 0x10 {
		t.Fatalf("1<<4 = %d", v)
	}
	if v := must(Imm(0x100).Apply(">>", Imm(4))).Val(); v != 0x10 {
		t.Fatalf("0x100>>4 = %d", v)
	}
	if v := must(Imm(0xffffffff).Apply("+", Imm(2))).Val(); v != 1 {
		t.Fatalf("wrap = %d", v)
	}
	for _, n := range []uint32{32, 0xffffffff} {
		if v := must(Imm(1).Apply("<<", Imm(uint64(n)))).Val(); v != 0 {
			t.Fatalf("1<<%d = %d", n, v)
		}
	}
	if v := must(Imm(6).Apply("/", Imm(0))).Val(); v != 0 {
		t.Fatalf("6/0 = %d", v)
	}
	if v := must(Imm(6).Apply("/", Imm(2))).Val(); v != 3 {
		t.Fatalf("6/2 = %d", v)
	}
	data := DataWord(16)
	bin := must(data.Apply("&", Imm(0xffff)))
	if bin.Kind() != KindBinop || bin.Op() != "&" || !bin.Lhs().Equal(data) || !bin.Rhs().Equal(Imm(0xffff)) {
		t.Fatalf("binop = %+v", bin)
	}
	two := must(DataWord(32).Apply("|", DataWord(16)))
	if two.Op() != "|" || !two.Lhs().Equal(DataWord(32)) {
		t.Fatalf("two = %+v", two)
	}
	rooted := must(Imm(0x1337).Apply("&", DataWord(0)))
	if rooted.Lhs().Kind() != KindImm {
		t.Fatalf("rooted = %+v", rooted)
	}
	neg := must(Imm(5).Apply("neg", nil))
	if !neg.IsImm() || neg.Val() != 0xfffffffb {
		t.Fatalf("neg 5 = %+v", neg)
	}
	if v := must(Imm(1).Apply("neg", nil)).Val(); v != 0xffffffff {
		t.Fatalf("neg 1 = %d", v)
	}
	if v := must(Imm(0x80000000).Apply("neg", nil)).Val(); v != 0x80000000 {
		t.Fatalf("neg 0x80000000 = %d", v)
	}
	negData := must(DataWord(0).Apply("neg", nil))
	if negData.Kind() != KindUnop || negData.Op() != "neg" || !negData.Lhs().Equal(DataWord(0)) {
		t.Fatalf("negData = %+v", negData)
	}
	if !must(Opaque().Apply("neg", nil)).IsOpaque() {
		t.Fatal("opaque neg")
	}
	if !must(must(DataWord(0).Apply("neg", nil)).Apply("neg", nil)).Equal(DataWord(0)) {
		t.Fatal("double neg")
	}
	sum := must(DataWord(0).Apply("+", DataWord(4)))
	if !must(must(sum.Apply("neg", nil)).Apply("neg", nil)).Equal(sum) {
		t.Fatal("double neg binop")
	}
	if !must(DataWord(16).Apply("+", Opaque())).IsOpaque() {
		t.Fatal("opaque rhs")
	}
	if !must(Opaque().Apply("+", Imm(1))).IsOpaque() {
		t.Fatal("opaque lhs")
	}
	if _, err := DataWord(16).Apply("%", Imm(2)); err == nil {
		t.Fatal("expected unsupported operator")
	}
}

func TestExprEquality(t *testing.T) {
	if !DataWord(16).Equal(DataWord(16)) || DataWord(16).Equal(DataWord(20)) {
		t.Fatal("data equality")
	}
	a, _ := DataWord(0).Apply("&", Imm(1))
	b, _ := DataWord(0).Apply("&", Imm(1))
	c, _ := DataWord(0).Apply("&", Imm(2))
	if !a.Equal(b) || a.Equal(c) || a.Key() != b.Key() {
		t.Fatal("binop equality")
	}
}
