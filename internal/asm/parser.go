package asm

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/elnx/seccompgo/internal/consts"
)

type scalarKind int

const (
	scalarA scalarKind = iota
	scalarX
	scalarLen
	scalarConst
	scalarData
	scalarMem
	scalarNeg
)

// Scalar is a register, a constant, a data[] or mem[] operand.
type Scalar struct {
	kind scalarKind
	val  uint32
}

func regA() Scalar                 { return Scalar{kind: scalarA} }
func regX() Scalar                 { return Scalar{kind: scalarX} }
func lenScalar() Scalar            { return Scalar{kind: scalarLen} }
func constScalar(v uint32) Scalar  { return Scalar{kind: scalarConst, val: v} }
func dataScalar(off uint32) Scalar { return Scalar{kind: scalarData, val: off} }
func memScalar(idx uint32) Scalar  { return Scalar{kind: scalarMem, val: idx} }
func negScalar() Scalar            { return Scalar{kind: scalarNeg} }

// Val returns the scalar's payload.
func (s Scalar) Val() uint32 { return s.val }

// IsA, IsX, IsLen, IsConst, IsData, IsMem report the scalar's kind.
func (s Scalar) IsA() bool     { return s.kind == scalarA }
func (s Scalar) IsX() bool     { return s.kind == scalarX }
func (s Scalar) IsLen() bool   { return s.kind == scalarLen }
func (s Scalar) IsConst() bool { return s.kind == scalarConst }
func (s Scalar) IsData() bool  { return s.kind == scalarData }
func (s Scalar) IsMem() bool   { return s.kind == scalarMem }
func (s Scalar) IsNeg() bool   { return s.kind == scalarNeg }

// Statement is one parsed instruction, possibly with labels attached.
type Statement struct {
	Type stmtType

	// alu
	AluOp  string
	AluVal Scalar
	// assignment
	Dst Scalar
	Src Scalar
	// conditional: Cmp nil means an unconditional jump.
	Cmp *Comparison
	Jt  *Token
	Jf  *Token
	JtD int
	JfD int
	// return
	Ret Scalar

	Symbols []*Token
}

type stmtType int

const (
	stmtALU stmtType = iota
	stmtAssign
	stmtIf
	stmtRet
)

// Comparison is an if-condition.
type Comparison struct {
	Op   string
	Rval Scalar
}

type parser struct {
	sc   *Scanner
	toks []*Token
	pos  int
}

func (p *parser) cur() *Token {
	if p.pos >= len(p.toks) {
		return nil
	}
	return p.toks[p.pos]
}

func (p *parser) peek(n int) *Token {
	if p.pos+n >= len(p.toks) {
		return nil
	}
	return p.toks[p.pos+n]
}

func (p *parser) take() *Token {
	t := p.cur()
	if t != nil {
		p.pos++
	}
	return t
}

func (p *parser) prev(off int) *Token {
	i := p.pos - 1 + off
	if i < 0 || i >= len(p.toks) {
		return nil
	}
	return p.toks[i]
}

func (p *parser) syntaxError() error {
	t := p.cur()
	if t == nil {
		t = p.prev(0)
		if t == nil {
			return &ParseError{Msg: "unexpected string nil\n"}
		}
		return &ParseError{Msg: p.sc.FormatError(t, "unexpected string nil")}
	}
	return &ParseError{Msg: p.sc.FormatError(t, fmt.Sprintf("unexpected string %q", t.Str))}
}

func (p *parser) syntaxErrorAt(t *Token) error {
	if t == nil {
		return &ParseError{Msg: "unexpected string nil\n"}
	}
	return &ParseError{Msg: p.sc.FormatError(t, fmt.Sprintf("unexpected string %q", t.Str))}
}

func (p *parser) raiseAt(t *Token, msg string) error {
	if t == nil {
		return &ParseError{Msg: msg}
	}
	return &ParseError{Msg: p.sc.FormatError(t, msg)}
}

func (p *parser) expect(sym string) (*Token, error) {
	t := p.cur()
	if t == nil || t.Sym != sym {
		return nil, p.syntaxError()
	}
	p.pos++
	return t, nil
}

func (p *parser) skipNewlines() {
	for p.cur() != nil && p.cur().Sym == "NEWLINE" {
		p.pos++
	}
}

// parse turns the token stream into statements.
func (p *parser) parse() ([]*Statement, error) {
	if len(p.toks) == 0 {
		return nil, nil
	}
	var out []*Statement
	for {
		p.skipNewlines()
		if p.cur() == nil {
			break
		}
		var symbols []*Token
		var lastNewline *Token
		lastSymbol := (*Token)(nil)
		for p.cur() != nil && p.cur().Sym == "SYMBOL" {
			t := p.take()
			lastSymbol = t
			if t.Str == "next" {
				return nil, p.raiseAt(t, "'next' is a reserved label")
			}
			symbols = append(symbols, t)
			for p.cur() != nil && p.cur().Sym == "NEWLINE" {
				lastNewline = p.take()
			}
			if p.cur() == nil {
				if lastNewline != nil {
					return nil, p.syntaxErrorAt(lastNewline)
				}
				return nil, p.syntaxErrorAt(lastSymbol)
			}
		}
		if p.cur() == nil {
			return nil, p.syntaxError()
		}
		st, err := p.parseStatement()
		if err != nil {
			return nil, err
		}
		st.Symbols = symbols
		out = append(out, st)
	}
	return out, nil
}

func (p *parser) parseStatement() (*Statement, error) {
	t := p.cur()
	if t == nil {
		return nil, p.syntaxError()
	}
	switch t.Sym {
	case "A":
		n := p.peek(1)
		if n == nil {
			return nil, p.syntaxError()
		}
		switch n.Sym {
		case "=":
			return p.parseAssign()
		case "ALU_OP":
			return p.parseArithmetic()
		case "&":
			if n2 := p.peek(2); n2 != nil && n2.Sym == "=" {
				return p.parseArithmetic()
			}
			return p.parseTernary()
		case "COMPARE":
			return p.parseTernary()
		}
		return nil, p.syntaxError()
	case "X", "MEM":
		return p.parseAssign()
	case "IF":
		return p.parseIf()
	case "GOTO":
		return p.parseGoto()
	case "RETURN":
		return p.parseReturn()
	}
	return nil, p.syntaxError()
}

// parseArithmetic: A <op>= <newlines> x_constexpr
func (p *parser) parseArithmetic() (*Statement, error) {
	if _, err := p.expect("A"); err != nil {
		return nil, err
	}
	opTok := p.cur()
	if opTok == nil {
		return nil, p.syntaxError()
	}
	var op string
	if opTok.Sym == "ALU_OP" || opTok.Sym == "&" {
		op = opTok.Str
		p.pos++
	} else {
		return nil, p.syntaxError()
	}
	if _, err := p.expect("="); err != nil {
		return nil, err
	}
	p.skipNewlines()
	val, err := p.parseXConstexpr()
	if err != nil {
		return nil, err
	}
	return &Statement{Type: stmtALU, AluOp: op + "=", AluVal: val}, nil
}

// parseAssign handles A = ..., X = ..., mem[i] = ...
func (p *parser) parseAssign() (*Statement, error) {
	first := p.cur()
	if first == nil {
		return nil, p.syntaxError()
	}
	switch first.Sym {
	case "MEM":
		m, err := p.parseMemory()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect("="); err != nil {
			return nil, err
		}
		reg, err := p.parseAX()
		if err != nil {
			return nil, err
		}
		return &Statement{Type: stmtAssign, Dst: m, Src: reg}, nil
	case "A":
		p.pos++
		if _, err := p.expect("="); err != nil {
			return nil, err
		}
		var src Scalar
		var err error
		t := p.cur()
		if t == nil {
			return nil, p.syntaxError()
		}
		switch t.Sym {
		case "X":
			p.pos++
			src = regX()
		case "LEN":
			p.pos++
			src = lenScalar()
		case "MEM":
			src, err = p.parseMemory()
		case "ALU_OP":
			p.pos++
			if _, e := p.expect("A"); e != nil {
				return nil, e
			}
			if t.Str != "-" {
				return nil, p.raiseAt(p.prev(-1), "do you mean A = -A?")
			}
			src = negScalar()
		case "ARGS", "ARGS_H", "INSTRUCTION_POINTER", "SYS_NUMBER", "ARCH", "DATA":
			src, err = p.parseArgument()
		case "INT", "HEX_INT", "ARCH_VAL", "SYSCALL", "(":
			src, err = p.parseConstexpr()
		default:
			return nil, p.syntaxError()
		}
		if err != nil {
			return nil, err
		}
		return &Statement{Type: stmtAssign, Dst: regA(), Src: src}, nil
	case "X":
		p.pos++
		if _, err := p.expect("="); err != nil {
			return nil, err
		}
		var src Scalar
		var err error
		t := p.cur()
		if t == nil {
			return nil, p.syntaxError()
		}
		switch t.Sym {
		case "A":
			p.pos++
			src = regA()
		case "MEM":
			src, err = p.parseMemory()
		case "INT", "HEX_INT", "ARCH_VAL", "SYSCALL", "(":
			src, err = p.parseConstexpr()
		default:
			return nil, p.syntaxError()
		}
		if err != nil {
			return nil, err
		}
		return &Statement{Type: stmtAssign, Dst: regX(), Src: src}, nil
	}
	return nil, p.syntaxError()
}

func (p *parser) parseAX() (Scalar, error) {
	t := p.cur()
	if t == nil {
		return Scalar{}, p.syntaxError()
	}
	switch t.Sym {
	case "A":
		p.pos++
		return regA(), nil
	case "X":
		p.pos++
		return regX(), nil
	}
	return Scalar{}, p.syntaxError()
}

// parseTernary parses the shorthand `A cmp rhs ? jt : jf`.
func (p *parser) parseTernary() (*Statement, error) {
	return p.parseIf()
}

// parseXConstexpr: X | constexpr
func (p *parser) parseXConstexpr() (Scalar, error) {
	t := p.cur()
	if t != nil && t.Sym == "X" {
		p.pos++
		return regX(), nil
	}
	return p.parseConstexpr()
}

func (p *parser) parseConstexpr() (Scalar, error) {
	t := p.cur()
	if t == nil {
		return Scalar{}, p.syntaxError()
	}
	switch t.Sym {
	case "(":
		p.pos++
		v, err := p.parseConstexpr()
		if err != nil {
			return Scalar{}, err
		}
		if _, err := p.expect(")"); err != nil {
			return Scalar{}, err
		}
		return v, nil
	case "INT", "HEX_INT", "ARCH_VAL", "SYSCALL":
		p.pos++
		v, err := p.numberValue(t)
		if err != nil {
			return Scalar{}, err
		}
		return constScalar(v), nil
	}
	return Scalar{}, p.syntaxError()
}

func (p *parser) numberValue(t *Token) (uint32, error) {
	switch t.Sym {
	case "INT":
		n, err := strconv.ParseInt(t.Str, 10, 64)
		if err != nil {
			return 0, p.raiseAt(t, "invalid integer "+t.Str)
		}
		return uint32(n), nil
	case "HEX_INT":
		n, err := strconv.ParseInt(t.Str, 0, 64)
		if err != nil {
			return 0, p.raiseAt(t, "invalid integer "+t.Str)
		}
		return uint32(n), nil
	case "ARCH_VAL":
		if v, ok := consts.AuditArch[t.Str]; ok {
			return v, nil
		}
		return 0, p.raiseAt(t, fmt.Sprintf("unexpected string %q", t.Str))
	case "SYSCALL":
		name := t.Str
		if i := strings.IndexByte(name, '.'); i >= 0 {
			arch, sys := name[:i], name[i+1:]
			if v, ok := consts.SyscallNum(strings.ToLower(arch), sys); ok {
				return v, nil
			}
			return 0, p.raiseAt(t, fmt.Sprintf("syscall '%s' doesn't exist on %s", sys, arch))
		}
		if v, ok := consts.SyscallNum(p.sc.Arch, name); ok {
			return v, nil
		}
		return 0, p.raiseAt(t, fmt.Sprintf("syscall '%s' doesn't exist on %s", name, p.sc.Arch))
	}
	return 0, p.syntaxError()
}

// parseMemory: mem[constexpr]
func (p *parser) parseMemory() (Scalar, error) {
	if _, err := p.expect("MEM"); err != nil {
		return Scalar{}, err
	}
	if _, err := p.expect("["); err != nil {
		return Scalar{}, err
	}
	v, err := p.parseConstexpr()
	if err != nil {
		return Scalar{}, err
	}
	last := p.prev(0)
	if _, err := p.expect("]"); err != nil {
		return Scalar{}, err
	}
	if v.Val() > 15 {
		return Scalar{}, p.raiseAt(last, fmt.Sprintf("index of mem[] must between 0 and 15, got %d", v.Val()))
	}
	return memScalar(v.Val()), nil
}

// parseArgument: args[i], args_h[i], instruction_pointer, or the scalar fields.
func (p *parser) parseArgument() (Scalar, error) {
	t := p.cur()
	if t == nil {
		return Scalar{}, p.syntaxError()
	}
	switch t.Sym {
	case "SYS_NUMBER":
		p.pos++
		return dataScalar(consts.SysNumber), nil
	case "ARCH":
		p.pos++
		return dataScalar(consts.Arch), nil
	case "DATA":
		p.pos++
		if _, err := p.expect("["); err != nil {
			return Scalar{}, err
		}
		v, err := p.parseConstexpr()
		if err != nil {
			return Scalar{}, err
		}
		last := p.prev(0)
		if _, err := p.expect("]"); err != nil {
			return Scalar{}, err
		}
		idx := v.Val()
		if idx%4 != 0 || idx >= consts.Size {
			return Scalar{}, p.raiseAt(last,
				fmt.Sprintf("index of data[] must be a multiple of 4 and less than %d, got %d", consts.Size, idx))
		}
		return dataScalar(idx), nil
	case "ARGS", "ARGS_H":
		name := t.Str
		p.pos++
		if _, err := p.expect("["); err != nil {
			return Scalar{}, err
		}
		v, err := p.parseConstexpr()
		if err != nil {
			return Scalar{}, err
		}
		last := p.prev(0)
		if _, err := p.expect("]"); err != nil {
			return Scalar{}, err
		}
		idx := v.Val()
		if idx > 5 {
			return Scalar{}, p.raiseAt(last,
				fmt.Sprintf("index of %s[] must between 0 and 5, got %d", name, idx))
		}
		hi := strings.HasSuffix(strings.ToLower(name), "h")
		off := wordOffset(consts.Args+idx*8, hi, p.sc.Arch)
		return p.parseArgShift(dataScalar(off))
	case "INSTRUCTION_POINTER":
		p.pos++
		off := wordOffset(consts.InstructionPointer, false, p.sc.Arch)
		return p.parseArgShift(dataScalar(off))
	}
	return Scalar{}, p.syntaxError()
}

func wordOffset(base uint32, hi bool, arch string) uint32 {
	if hi == consts.BigEndian(arch) {
		return base
	}
	return base + 4
}

// parseArgShift accepts the optional ">> 32" after a 64-bit argument load.
func (p *parser) parseArgShift(s Scalar) (Scalar, error) {
	t := p.cur()
	if t == nil || (t.Sym != "ALU_OP" && t.Sym != "&") {
		return s, nil
	}
	opTok := t
	p.pos++
	intTok := p.cur()
	if intTok == nil || intTok.Sym != "INT" {
		return Scalar{}, p.syntaxError()
	}
	p.pos++
	n, err := strconv.ParseInt(intTok.Str, 10, 64)
	if err != nil {
		n = 1 << 62
	}
	if opTok.Str != ">>" {
		return Scalar{}, p.raiseAt(opTok, "operator after an argument can only be '>> 32'")
	}
	if n != 32 {
		return Scalar{}, p.raiseAt(intTok, "operator after an argument can only be '>> 32'")
	}
	return dataScalar(s.Val() ^ 4), nil
}

// parseIf: if (comparison) goto X [else goto Y] | A cmp rhs ? X : Y
func (p *parser) parseIf() (*Statement, error) {
	t := p.cur()
	if t != nil && t.Sym == "IF" {
		p.pos++
		if _, err := p.expect("("); err != nil {
			return nil, err
		}
		p.skipNewlines()
		cmp, parity, err := p.parseComparisonInner()
		if err != nil {
			return nil, err
		}
		p.skipNewlines()
		if _, err := p.expect(")"); err != nil {
			return nil, err
		}
		p.skipNewlines()
		jt, err := p.parseGotoExpr()
		if err != nil {
			return nil, err
		}
		p.skipNewlines()
		var jf *Token
		if c := p.cur(); c != nil && c.Sym == "ELSE" {
			p.pos++
			p.skipNewlines()
			jf, err = p.parseGotoExpr()
			if err != nil {
				return nil, err
			}
		}
		if parity%2 == 1 {
			jt, jf = jf, jt
		}
		return &Statement{Type: stmtIf, Cmp: cmp, Jt: jt, Jf: jf}, nil
	}
	// A compare x_constexpr ? jt : jf
	if _, err := p.expect("A"); err != nil {
		return nil, err
	}
	opTok := p.cur()
	if opTok == nil || (opTok.Sym != "COMPARE" && opTok.Sym != "&") {
		return nil, p.syntaxError()
	}
	p.pos++
	rhs, err := p.parseXConstexpr()
	if err != nil {
		return nil, err
	}
	jtTok := p.cur()
	if jtTok == nil || jtTok.Sym != "GOTO_SYMBOL" {
		return nil, p.syntaxError()
	}
	p.pos++
	jfTok := p.cur()
	if jfTok == nil || jfTok.Sym != "GOTO_SYMBOL" {
		return nil, p.syntaxError()
	}
	p.pos++
	return &Statement{
		Type: stmtIf,
		Cmp:  &Comparison{Op: opTok.Str, Rval: rhs},
		Jt:   jtTok, Jf: jfTok,
	}, nil
}

func (p *parser) parseComparisonInner() (*Comparison, int, error) {
	t := p.cur()
	if t == nil {
		return nil, 0, p.syntaxError()
	}
	if t.Sym == "!" {
		p.pos++
		if _, err := p.expect("("); err != nil {
			return nil, 0, err
		}
		cmp, parity, err := p.parseComparisonInner()
		if err != nil {
			return nil, 0, err
		}
		if _, err := p.expect(")"); err != nil {
			return nil, 0, err
		}
		return cmp, parity + 1, nil
	}
	if _, err := p.expect("A"); err != nil {
		return nil, 0, err
	}
	p.skipNewlines()
	opTok := p.cur()
	if opTok == nil || (opTok.Sym != "COMPARE" && opTok.Sym != "&") {
		return nil, 0, p.syntaxError()
	}
	p.pos++
	p.skipNewlines()
	rhs, err := p.parseXConstexpr()
	if err != nil {
		return nil, 0, err
	}
	return &Comparison{Op: opTok.Str, Rval: rhs}, 0, nil
}

func (p *parser) parseGotoExpr() (*Token, error) {
	if _, err := p.expect("GOTO"); err != nil {
		return nil, err
	}
	return p.parseGotoSymbol()
}

func (p *parser) parseGotoSymbol() (*Token, error) {
	t := p.cur()
	if t == nil || t.Sym != "GOTO_SYMBOL" {
		return nil, p.syntaxError()
	}
	p.pos++
	return t, nil
}

func (p *parser) parseGoto() (*Statement, error) {
	if _, err := p.expect("GOTO"); err != nil {
		return nil, err
	}
	t, err := p.parseGotoSymbol()
	if err != nil {
		return nil, err
	}
	return &Statement{Type: stmtIf, Jt: t, Jf: t}, nil
}

func (p *parser) parseReturn() (*Statement, error) {
	if _, err := p.expect("RETURN"); err != nil {
		return nil, err
	}
	t := p.cur()
	if t == nil {
		return nil, p.syntaxError()
	}
	switch t.Sym {
	case "A":
		p.pos++
		return &Statement{Type: stmtRet, Ret: regA()}, nil
	case "ACTION":
		p.pos++
		v, ok := consts.ActionValue(t.Str)
		if !ok {
			return nil, p.raiseAt(t, fmt.Sprintf("unknown action %q", t.Str))
		}
		if c := p.cur(); c != nil && c.Sym == "(" {
			p.pos++
			expr, err := p.parseConstexpr()
			if err != nil {
				return nil, err
			}
			if _, err := p.expect(")"); err != nil {
				return nil, err
			}
			v |= expr.Val() & consts.RetData
		}
		return &Statement{Type: stmtRet, Ret: constScalar(v)}, nil
	default:
		v, err := p.parseConstexpr()
		if err != nil {
			return nil, err
		}
		return &Statement{Type: stmtRet, Ret: v}, nil
	}
}
