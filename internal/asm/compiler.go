package asm

import (
	"fmt"
	"regexp"
	"strconv"

	"seccompgo/internal/bpf"
	"seccompgo/internal/consts"
	"seccompgo/internal/util"
)

// JumpDistanceMax is the farthest relative BPF jump.
const JumpDistanceMax = 255

type label struct {
	tok *Token
	idx int
}

// Compiler compiles seccomp assembly.
type Compiler struct {
	sc      *Scanner
	arch    string
	symbols map[string]label
	line    int
}

// NewCompiler builds a compiler for source. filename is used only in error messages.
func NewCompiler(source, filename, arch string) *Compiler {
	if filename == "-" {
		filename = ""
	}
	return &Compiler{sc: NewScanner(source, arch, filename), arch: arch, symbols: map[string]label{}}
}

var canonicalInt = regexp.MustCompile(`^-?[0-9]+$`)

// Compile parses and emits the instructions.
func (c *Compiler) Compile() ([]*bpf.BPF, error) {
	if err := c.sc.ValidateOrError(); err != nil {
		return nil, err
	}
	p := &parser{sc: c.sc, toks: c.sc.Scan()}
	statements, err := p.parse()
	if err != nil {
		return nil, err
	}
	if err := c.fixupSymbols(statements); err != nil {
		return nil, err
	}
	if err := c.resolveSymbols(statements); err != nil {
		return nil, err
	}
	out := make([]*bpf.BPF, 0, len(statements))
	for idx, st := range statements {
		c.line = idx
		var b *bpf.BPF
		switch st.Type {
		case stmtALU:
			b, err = c.emitALU(st.AluOp, st.AluVal)
		case stmtAssign:
			b, err = c.emitAssign(st.Dst, st.Src)
		case stmtIf:
			b, err = c.emitCmp(st.Cmp, st.JtD, st.JfD, st.Jt, st.Jf)
		case stmtRet:
			b, err = c.emitRet(st.Ret)
		}
		if err != nil {
			return nil, err
		}
		if b != nil {
			out = append(out, b)
		}
	}
	return out, nil
}

func (c *Compiler) fixupSymbols(statements []*Statement) error {
	for idx, st := range statements {
		seen := map[string]bool{}
		for _, s := range st.Symbols {
			if seen[s.Str] {
				continue
			}
			seen[s.Str] = true
			if old, ok := c.symbols[s.Str]; ok {
				msg := c.sc.FormatError(s, fmt.Sprintf("duplicate label '%s'", s.Str))
				msg += c.sc.FormatError(old.tok, "previously defined here")
				return &DuplicateLabelError{Msg: msg}
			}
			c.symbols[s.Str] = label{tok: s, idx: idx}
		}
	}
	return nil
}

func (c *Compiler) resolveSymbols(statements []*Statement) error {
	for idx, st := range statements {
		if st.Type != stmtIf {
			continue
		}
		jt, err := c.resolveSymbol(idx, st.Jt)
		if err != nil {
			return err
		}
		jf, err := c.resolveSymbol(idx, st.Jf)
		if err != nil {
			return err
		}
		st.JtD, st.JfD = jt, jf
	}
	return nil
}

func (c *Compiler) resolveSymbol(index int, tok *Token) (int, error) {
	if tok == nil {
		return 0, nil
	}
	str := tok.Str
	if str == "next" {
		return 0, nil
	}
	if l, ok := c.symbols[str]; ok {
		dis := l.idx - index - 1
		if dis < 0 {
			return 0, &BackwardJumpError{Msg: c.sc.FormatError(tok,
				fmt.Sprintf("Does not support backward jumping to '%s'", str))}
		}
		return dis, nil
	}
	if canonicalInt.MatchString(str) {
		n, err := strconv.Atoi(str)
		if err == nil && strconv.Itoa(n) == str {
			return n, nil
		}
	}
	return 0, &UndefinedLabelError{Msg: c.sc.FormatError(tok,
		fmt.Sprintf("Cannot find label '%s'", str))}
}

func (c *Compiler) emit(parts []string, k uint32, jt, jf uint8) *bpf.BPF {
	var code uint16
	for _, a := range parts {
		code |= consts.Command[a]
		code |= consts.Jmp[a]
		code |= consts.Src[a]
		code |= consts.Mode[a]
		code |= consts.Op[a]
		code |= consts.MiscOp[a]
	}
	return bpf.FromFields(code, jt, jf, k, c.arch, c.line)
}

func (c *Compiler) emitAssign(dst, src Scalar) (*bpf.BPF, error) {
	if src.IsNeg() {
		return c.emit([]string{"alu", "neg"}, 0, 0, 0), nil
	}
	if (dst.IsA() && src.IsX()) || (dst.IsX() && src.IsA()) {
		if dst.IsA() {
			return c.emit([]string{"misc", "txa"}, 0, 0, 0), nil
		}
		return c.emit([]string{"misc", "tax"}, 0, 0, 0), nil
	}
	if dst.IsMem() {
		if src.IsX() {
			return c.emit([]string{"stx"}, dst.Val(), 0, 0), nil
		}
		return c.emit([]string{"st"}, dst.Val(), 0, 0), nil
	}
	return c.emitLD(dst, src)
}

func (c *Compiler) emitLD(dst, src Scalar) (*bpf.BPF, error) {
	ld := "ld"
	if dst.IsX() {
		ld = "ldx"
	}
	switch {
	case src.IsLen():
		return c.emit([]string{ld, "len"}, 0, 0, 0), nil
	case src.IsConst():
		return c.emit([]string{ld, "imm"}, src.Val(), 0, 0), nil
	case src.IsMem():
		return c.emit([]string{ld, "mem"}, src.Val(), 0, 0), nil
	case src.IsData():
		return c.emit([]string{ld, "abs"}, src.Val(), 0, 0), nil
	}
	return nil, fmt.Errorf("Line %d is invalid: invalid assignment", c.line)
}

var aluNames = map[string]string{
	"+": "add", "-": "sub", "*": "mul", "/": "div", "|": "or",
	"&": "and", "<<": "lsh", ">>": "rsh", "^": "xor",
}

func (c *Compiler) emitALU(opEq string, val Scalar) (*bpf.BPF, error) {
	opName := opEq[:len(opEq)-1]
	parts := []string{"alu", aluNames[opName]}
	k := uint32(0)
	if val.IsX() {
		parts = append(parts, "x")
	} else {
		parts = append(parts, "k")
		k = val.Val()
	}
	return c.emit(parts, k, 0, 0), nil
}

func (c *Compiler) emitRet(val Scalar) (*bpf.BPF, error) {
	if val.IsA() {
		return c.emit([]string{"ret", "a"}, 0, 0, 0), nil
	}
	return c.emit([]string{"ret"}, val.Val(), 0, 0), nil
}

func (c *Compiler) emitCmp(cmp *Comparison, jt, jf int, jtTok, jfTok *Token) (*bpf.BPF, error) {
	origJt, origJf := jt, jf
	jop := "ja"
	if cmp != nil {
		switch cmp.Op {
		case "==":
			jop = "jeq"
		case "!=":
			jop, jt, jf = "jeq", jf, jt
		case ">=":
			jop = "jge"
		case "<=":
			jop, jt, jf = "jgt", jf, jt
		case ">":
			jop = "jgt"
		case "<":
			jop, jt, jf = "jge", jf, jt
		case "&":
			jop = "jset"
		}
	}
	if jop == "ja" || jt == jf {
		return c.emit([]string{"jmp", "none"}, uint32(jt), 0, 0), nil
	}
	for _, pair := range [2]struct {
		dis int
		tok *Token
	}{{origJt, jtTok}, {origJf, jfTok}} {
		if pair.dis > JumpDistanceMax {
			if pair.tok == nil {
				return nil, &LongJumpError{Msg: fmt.Sprintf(
					"Does not support jumping farther than %d, got: %d", JumpDistanceMax, pair.dis)}
			}
			return nil, &LongJumpError{Msg: c.sc.FormatError(pair.tok, fmt.Sprintf(
				"Does not support jumping farther than %d, got: %d", JumpDistanceMax, pair.dis))}
		}
	}
	src := "k"
	k := cmp.Rval.Val()
	if cmp.Rval.IsX() {
		src = "x"
		k = 0
	}
	return c.emit([]string{"jmp", jop, src}, k, uint8(jt), uint8(jf)), nil
}

// Asm compiles assembly source into raw BPF bytes.
func Asm(source, filename, arch string) ([]byte, error) {
	if arch == "" {
		arch = util.SystemArch()
	}
	c := NewCompiler(source, filename, arch)
	codes, err := c.Compile()
	if err != nil {
		return nil, err
	}
	var out []byte
	for _, code := range codes {
		out = append(out, code.Asm()...)
	}
	return out, nil
}
