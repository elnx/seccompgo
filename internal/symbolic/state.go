package symbolic

import (
	"strconv"
	"strings"
	"sync"
)

// State is one immutable snapshot of the classic-BPF machine: A, X, 16 scratch slots,
// and the path condition.
type State struct {
	a    *Expr
	x    *Expr
	mem  [16]*Expr
	path []*Constraint
	key  *stateKey
}

type stateKey struct {
	once sync.Once
	val  string
}

// Initial is the kernel-guaranteed entry state: A = X = 0, unknown scratch slots, no
// facts assumed.
func Initial() *State {
	s := &State{a: Imm(0), x: Imm(0)}
	for i := range s.mem {
		s.mem[i] = Opaque()
	}
	return s
}

// A returns register A.
func (s *State) A() *Expr { return s.a }

// X returns register X.
func (s *State) X() *Expr { return s.x }

// Mem returns the 16 scratch slots.
func (s *State) Mem() [16]*Expr { return s.mem }

// Path returns the accumulated path condition.
func (s *State) Path() []*Constraint { return s.path }

// WithA returns a copy with A replaced.
func (s *State) WithA(a *Expr) *State {
	n := &State{a: a, x: s.x, mem: s.mem, path: s.path}
	return n
}

// WithX returns a copy with X replaced.
func (s *State) WithX(x *Expr) *State {
	n := &State{a: s.a, x: x, mem: s.mem, path: s.path}
	return n
}

// WithMem returns a copy with the scratch slots replaced.
func (s *State) WithMem(mem [16]*Expr) *State {
	n := &State{a: s.a, x: s.x, mem: mem, path: s.path}
	return n
}

// WithPath returns a copy with the path condition replaced.
func (s *State) WithPath(path []*Constraint) *State {
	n := &State{a: s.a, x: s.x, mem: s.mem, path: path}
	return n
}

// Key is a unique textual identity for this state, used by the executor's visited set.
func (s *State) Key() string {
	if s.key == nil {
		s.key = &stateKey{}
	}
	s.key.once.Do(func() {
		var b strings.Builder
		b.WriteString(s.a.key)
		b.WriteByte(';')
		b.WriteString(s.x.key)
		b.WriteByte(';')
		for i, m := range s.mem {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(m.key)
		}
		b.WriteByte(';')
		for i, c := range s.path {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(c.key)
		}
		s.key.val = b.String()
	})
	return s.key.val
}

// Pinned returns the constant the data word at byte offset is pinned to by an == fact.
func (s *State) Pinned(offset uint32) (uint32, bool) {
	for _, c := range s.path {
		if c.PlainDataEq(int(offset)) {
			return c.rhs.val, true
		}
	}
	return 0, false
}

// String returns the state key.
func (s *State) String() string { return s.Key() }

// OffsetString is a helper shared with callers that need the decimal byte offset.
func OffsetString(offset uint32) string { return strconv.FormatUint(uint64(offset), 10) }
