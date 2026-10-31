// Package symbolic provides the value expressions, path constraints and immutable
// machine states used by the symbolic executor.
package symbolic

import (
	"fmt"
	"strconv"
)

// Kind identifies what an Expr describes.
type Kind int

const (
	KindImm Kind = iota
	KindData
	KindBinop
	KindUnop
	KindOpaque
)

// Expr is a symbolic value: a constant, a word of the input buffer, an arithmetic
// combination of two expressions, a unary operation, or an undescribable value.
type Expr struct {
	kind   Kind
	val    uint32
	offset uint32
	op     string
	lhs    *Expr
	rhs    *Expr
	key    string
}

// representable is exactly the set of binary ALU operators Instruction::ALU can
// produce. The unary neg is handled separately.
var representable = map[string]bool{
	"+": true, "-": true, "*": true, "/": true, "|": true,
	"&": true, "<<": true, ">>": true, "^": true,
}

// Imm builds a known 32-bit constant, masking wider inputs.
func Imm(val uint64) *Expr {
	v := uint32(val)
	return &Expr{kind: KindImm, val: v, key: "i" + strconv.FormatUint(uint64(v), 10)}
}

// DataWord builds a reference to the input-buffer word at byte offset.
func DataWord(offset uint32) *Expr {
	return &Expr{kind: KindData, offset: offset, key: "d" + strconv.FormatUint(uint64(offset), 10)}
}

// BinopExpr combines two expressions arithmetically.
func BinopExpr(op string, lhs, rhs *Expr) *Expr {
	return &Expr{kind: KindBinop, op: op, lhs: lhs, rhs: rhs,
		key: "(" + lhs.key + op + rhs.key + ")"}
}

// UnopExpr applies a unary operation (only "neg") to operand.
func UnopExpr(op string, operand *Expr) *Expr {
	return &Expr{kind: KindUnop, op: op, lhs: operand, key: "(" + op + operand.key + ")"}
}

// Opaque builds a value that cannot be described symbolically.
func Opaque() *Expr { return &Expr{kind: KindOpaque, key: "o"} }

// Kind returns the expression kind.
func (e *Expr) Kind() Kind { return e.kind }

// Val returns the constant when the expression is an immediate.
func (e *Expr) Val() uint32 { return e.val }

// Offset returns the buffer byte offset when the expression is a data word.
func (e *Expr) Offset() uint32 { return e.offset }

// Op returns the operator when the expression is a binop or unop.
func (e *Expr) Op() string { return e.op }

// Lhs and Rhs return the operands.
func (e *Expr) Lhs() *Expr { return e.lhs }
func (e *Expr) Rhs() *Expr { return e.rhs }

// IsImm reports whether e is a constant.
func (e *Expr) IsImm() bool { return e.kind == KindImm }

// PlainData reports whether e is a bare data-buffer word.
func (e *Expr) PlainData() bool { return e.kind == KindData }

// IsOpaque reports whether e cannot be described.
func (e *Expr) IsOpaque() bool { return e.kind == KindOpaque }

// Key is a unique textual identity; equality and hashing are defined on it.
func (e *Expr) Key() string { return e.key }

// Equal compares expressions by content.
func (e *Expr) Equal(other *Expr) bool { return other != nil && e.key == other.key }

// Apply performs an ALU operation. neg is unary and ignores operand.
func (e *Expr) Apply(op string, operand *Expr) (*Expr, error) {
	if op == "neg" {
		return e.applyNeg(), nil
	}
	if !representable[op] {
		return nil, fmt.Errorf("unsupported operator %s", op)
	}
	if e.IsOpaque() || operand.IsOpaque() {
		return Opaque(), nil
	}
	if e.IsImm() && operand.IsImm() {
		return Imm(uint64(fold(e.val, op, operand.val))), nil
	}
	return BinopExpr(op, e, operand), nil
}

func (e *Expr) applyNeg() *Expr {
	if e.IsOpaque() {
		return Opaque()
	}
	if e.IsImm() {
		return Imm(uint64(fold(0, "-", e.val)))
	}
	if e.kind == KindUnop { // the only unop is neg
		return e.lhs
	}
	return UnopExpr("neg", e)
}

func fold(lhs uint32, op string, rhs uint32) uint32 {
	switch op {
	case "/":
		if rhs == 0 {
			return 0 // a real filter is rejected at load for div-by-zero
		}
		return lhs / rhs
	case "<<", ">>":
		if rhs >= 32 {
			return 0 // short-circuit instead of building a huge integer
		}
		if op == "<<" {
			return lhs << rhs
		}
		return lhs >> rhs
	case "+":
		return lhs + rhs
	case "-":
		return lhs - rhs
	case "*":
		return lhs * rhs
	case "|":
		return lhs | rhs
	case "&":
		return lhs & rhs
	case "^":
		return lhs ^ rhs
	}
	return 0
}

// String renders the expression in the same shape as the key.
func (e *Expr) String() string { return e.key }
