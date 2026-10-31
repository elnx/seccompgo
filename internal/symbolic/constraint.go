package symbolic

// Constraint is one fact that must hold on a path, e.g. data[0] == 1 or
// (data[16] & 0xff) != 3. A lone constant is normalized to the right-hand side.
type Constraint struct {
	lhs *Expr
	op  string
	rhs *Expr
	key string
}

var mirror = map[string]string{
	"==": "==", "!=": "!=", ">": "<", ">=": "<=", "<": ">", "<=": ">=",
	"set": "set", "unset": "unset",
}

// NewConstraint builds a normalized constraint.
func NewConstraint(a *Expr, op string, b *Expr) *Constraint {
	if a.IsImm() && !b.IsImm() {
		a, op, b = b, mirror[op], a
	}
	return &Constraint{lhs: a, op: op, rhs: b, key: a.key + op + b.key}
}

// Lhs returns the tested expression.
func (c *Constraint) Lhs() *Expr { return c.lhs }

// Rhs returns the constant or expression compared against.
func (c *Constraint) Rhs() *Expr { return c.rhs }

// Op returns the comparison operator.
func (c *Constraint) Op() string { return c.op }

// Key is a unique textual identity.
func (c *Constraint) Key() string { return c.key }

// Equal compares constraints by content.
func (c *Constraint) Equal(other *Constraint) bool { return other != nil && c.key == other.key }

// Evaluate applies a constraint operator to concrete operands.
func Evaluate(value uint32, op string, k uint32) bool {
	switch op {
	case "==":
		return value == k
	case "!=":
		return value != k
	case ">":
		return value > k
	case ">=":
		return value >= k
	case "<":
		return value < k
	case "<=":
		return value <= k
	case "set":
		return value&k != 0
	case "unset":
		return value&k == 0
	}
	return false
}

// PlainDataFact reports whether this is a bare word compared against a constant.
// offset < 0 accepts any word offset.
func (c *Constraint) PlainDataFact(offset int) bool {
	return c.lhs.PlainData() && c.rhs.IsImm() &&
		(offset < 0 || int(c.lhs.offset) == offset)
}

// PlainDataEq reports whether this is a bare word == constant fact.
func (c *Constraint) PlainDataEq(offset int) bool {
	return c.op == "==" && c.PlainDataFact(offset)
}

// String renders the constraint in the same shape as the key.
func (c *Constraint) String() string { return c.key }
