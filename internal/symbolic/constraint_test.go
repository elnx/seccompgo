package symbolic

import "testing"

func TestConstraintNormalization(t *testing.T) {
	c := NewConstraint(Imm(5), ">", DataWord(0))
	if !c.Lhs().Equal(DataWord(0)) || c.Op() != "<" || !c.Rhs().Equal(Imm(5)) {
		t.Fatalf("not normalized: %v", c)
	}
	d := NewConstraint(DataWord(0), "<", Imm(5))
	if c.Key() != d.Key() {
		t.Fatal("spellings differ")
	}
	sym := NewConstraint(DataWord(0), "==", DataWord(4))
	if !sym.Lhs().Equal(DataWord(0)) || sym.Op() != "==" {
		t.Fatal("symbolic sides swapped")
	}
	imm := NewConstraint(Imm(1), "==", Imm(2))
	if imm.Op() != "==" || !imm.Lhs().Equal(Imm(1)) {
		t.Fatal("imm sides swapped")
	}
}

func TestConstraintEvaluate(t *testing.T) {
	cases := []struct {
		v    uint32
		op   string
		k    uint32
		want bool
	}{
		{5, "==", 5, true}, {6, ">", 5, true}, {5, "<=", 5, true}, {5, "!=", 5, false},
		{1, "set", 3, true}, {4, "set", 3, false}, {4, "unset", 3, true}, {1, "unset", 3, false},
	}
	for _, c := range cases {
		if got := Evaluate(c.v, c.op, c.k); got != c.want {
			t.Errorf("Evaluate(%d,%s,%d)=%v", c.v, c.op, c.k, got)
		}
	}
}

func TestConstraintShapes(t *testing.T) {
	c := NewConstraint(DataWord(4), ">", Imm(5))
	if !c.PlainDataFact(-1) || !c.PlainDataFact(4) || c.PlainDataFact(8) {
		t.Fatal("plain data fact")
	}
	if NewConstraint(DataWord(0), "==", DataWord(4)).PlainDataFact(-1) {
		t.Fatal("data-vs-data")
	}
	bin, _ := DataWord(0).Apply("&", Imm(1))
	if NewConstraint(bin, "==", Imm(0)).PlainDataFact(-1) {
		t.Fatal("transformed lhs")
	}
	eq := NewConstraint(DataWord(4), "==", Imm(5))
	if !eq.PlainDataEq(4) || eq.PlainDataEq(0) {
		t.Fatal("plain data eq")
	}
	if NewConstraint(DataWord(4), "!=", Imm(5)).PlainDataEq(-1) {
		t.Fatal("!= is not eq")
	}
	if eq.Key() == NewConstraint(DataWord(4), "!=", Imm(5)).Key() {
		t.Fatal("keys collide")
	}
}

func TestStateInitialAndPinned(t *testing.T) {
	st := Initial()
	if !st.A().Equal(Imm(0)) || !st.X().Equal(Imm(0)) {
		t.Fatal("registers not zeroed")
	}
	for _, m := range st.Mem() {
		if !m.IsOpaque() {
			t.Fatal("scratch not opaque")
		}
	}
	if len(st.Path()) != 0 {
		t.Fatal("path not empty")
	}
	c := NewConstraint(DataWord(0), "==", Imm(5))
	st2 := st.WithPath([]*Constraint{c})
	if v, ok := st2.Pinned(0); !ok || v != 5 {
		t.Fatalf("pinned = %d,%v", v, ok)
	}
	if _, ok := st2.Pinned(4); ok {
		t.Fatal("wrong offset pinned")
	}
	if !st.A().Equal(Imm(0)) {
		t.Fatal("original mutated")
	}
}

func TestStateKey(t *testing.T) {
	a := Initial().WithA(DataWord(0))
	b := Initial().WithA(DataWord(0))
	c := Initial().WithA(DataWord(4))
	if a.Key() != b.Key() || a.Key() == c.Key() || Initial().Key() != Initial().Key() {
		t.Fatal("state keys")
	}
}
