// Package asm compiles seccomp assembly into raw BPF.
package asm

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/elnx/seccompgo/internal/consts"
)

// Token is one scanner token with its source location.
type Token struct {
	Sym  string
	Str  string
	Line int
	Col  int
}

// Equal compares all token fields.
func (t *Token) Equal(o *Token) bool {
	return o != nil && t.Sym == o.Sym && t.Str == o.Str && t.Line == o.Line && t.Col == o.Col
}

// Error types mirroring the Ruby library's exception classes.
type UnrecognizedTokenError struct{ Msg string }
type UndefinedLabelError struct{ Msg string }
type ParseError struct{ Msg string }
type BackwardJumpError struct{ Msg string }
type DuplicateLabelError struct{ Msg string }
type LongJumpError struct{ Msg string }

func (e *UnrecognizedTokenError) Error() string { return e.Msg }
func (e *UndefinedLabelError) Error() string    { return e.Msg }
func (e *ParseError) Error() string             { return e.Msg }
func (e *BackwardJumpError) Error() string      { return e.Msg }
func (e *DuplicateLabelError) Error() string    { return e.Msg }
func (e *LongJumpError) Error() string          { return e.Msg }

// Scanner converts assembly text into tokens.
type Scanner struct {
	Source   string
	Arch     string
	Filename string

	syscalls []string
	tokens   []*Token
	scanned  bool

	keywordRe    *regexp.Regexp
	actionRe     *regexp.Regexp
	archRe       *regexp.Regexp
	syscallRe    *regexp.Regexp
	syscallAllRe *regexp.Regexp
	gotoRe       *regexp.Regexp
	symbolRe     *regexp.Regexp
	newlineRe    *regexp.Regexp
	spaceRe      *regexp.Regexp
	commentRe    *regexp.Regexp
	hexRe        *regexp.Regexp
	intRe        *regexp.Regexp
	aluRe        *regexp.Regexp
	compareRe    *regexp.Regexp
	punctRe      *regexp.Regexp
	ternaryRe    *regexp.Regexp
	unknownRe    *regexp.Regexp
}

var keywords = []string{
	"a", "x", "if", "else", "return", "mem", "args", "args_h",
	"data", "len", "sys_number", "arch", "instruction_pointer",
}

var compareOps = []string{"==", "!=", ">=", "<=", ">", "<"}
var aluOps = []string{"+", "-", "*", "/", "|", "^", "<<", ">>"}

// keyWordSym maps a lower-case keyword to its token symbol (upper-case).
var keyWordSym = map[string]string{
	"a": "A", "x": "X", "if": "IF", "else": "ELSE", "return": "RETURN",
	"mem": "MEM", "args": "ARGS", "args_h": "ARGS_H", "data": "DATA",
	"len": "LEN", "sys_number": "SYS_NUMBER", "arch": "ARCH",
	"instruction_pointer": "INSTRUCTION_POINTER",
}

// NewScanner builds a scanner for source. filename "" becomes <inline>.
func NewScanner(source, arch, filename string) *Scanner {
	if filename == "" {
		filename = "<inline>"
	}
	s := &Scanner{Source: source, Arch: arch, Filename: filename}
	s.syscalls = consts.SyscallNames(arch)
	return s
}

func alt(names []string) string {
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = regexp.QuoteMeta(n)
	}
	return strings.Join(parts, "|")
}

func (s *Scanner) compressInit() {
	kw := strings.Join(keywords, "|")
	s.keywordRe = regexp.MustCompile(`(?i)\A\b(` + kw + `)\b`)
	actions := make([]string, len(consts.Action))
	for i, a := range consts.Action {
		actions[i] = a.Name
	}
	s.actionRe = regexp.MustCompile(`\A\b(` + strings.Join(actions, "|") + `)\b`)
	s.archRe = regexp.MustCompile(`(?i)\A\b(` + strings.Join(consts.AuditArchOrder, "|") + `)\b`)
	if len(s.syscalls) > 0 {
		s.syscallRe = archSyscallRegexp(s.Arch)
	}
	s.syscallAllRe = allSyscallRegexp()
	s.gotoRe = regexp.MustCompile(`(?i)\A(goto|jmp|jump)\s+(\w+)\b`)
	s.symbolRe = regexp.MustCompile(`\A(\w+):`)
	s.newlineRe = regexp.MustCompile(`\A\n+`)
	s.spaceRe = regexp.MustCompile(`\A\s+`)
	s.commentRe = regexp.MustCompile(`\A#.*`)
	s.hexRe = regexp.MustCompile(`\A-?0x[0-9a-f]+\b`)
	s.intRe = regexp.MustCompile(`\A-?[0-9]+\b`)
	s.aluRe = regexp.MustCompile(`\A(` + alt(aluOps) + `)`)
	s.compareRe = regexp.MustCompile(`\A(` + alt(compareOps) + `)`)
	s.punctRe = regexp.MustCompile(`\A(\(|\)|=|\[|\]|&|!)`)
	s.ternaryRe = regexp.MustCompile(`\A\?\s*(\w+)\s*:\s*(\w+)`)
	s.unknownRe = regexp.MustCompile(`\A([^\s]+)(\s?)`)
}

// regex fields, compiled lazily by Scan.
type scannerRegexes struct{}

// Scan returns every token in source order.
func (s *Scanner) Scan() []*Token {
	if s.scanned {
		return s.tokens
	}
	s.scanned = true
	s.compressInit()
	str := s.Source
	row, col := 0, 0
	runes := func(x string) int { return len([]rune(x)) }
	add := func(sym, text string, line, c int) {
		s.tokens = append(s.tokens, &Token{Sym: sym, Str: text, Line: line, Col: c})
	}
	// bumpTo advances one ASCII match of n bytes.
	bumpBytes := func(n int) {
		col += runes(str[:n])
		str = str[n:]
	}
	for str != "" {
		if loc := s.newlineRe.FindStringIndex(str); loc != nil {
			m := str[:loc[1]]
			if len(s.tokens) > 0 {
				add("NEWLINE", m, row, col)
			}
			row += strings.Count(m, "\n")
			col = 0
			str = str[loc[1]:]
			continue
		}
		if loc := s.spaceRe.FindStringIndex(str); loc != nil {
			bumpBytes(loc[1])
			continue
		}
		if loc := s.commentRe.FindStringIndex(str); loc != nil {
			bumpBytes(loc[1])
			continue
		}
		if m := s.symbolRe.FindStringSubmatchIndex(str); m != nil {
			text := str[m[2]:m[3]]
			add("SYMBOL", text, row, col)
			bumpBytes(m[1])
			continue
		}
		if m := s.gotoRe.FindStringSubmatchIndex(str); m != nil {
			add("GOTO", str[m[2]:m[3]], row, col+runes(str[:m[2]]))
			add("GOTO_SYMBOL", str[m[4]:m[5]], row, col+runes(str[:m[4]]))
			bumpBytes(m[1])
			continue
		}
		if m := s.keywordRe.FindStringSubmatchIndex(str); m != nil {
			text := str[m[2]:m[3]]
			add(keyWordSym[strings.ToLower(text)], text, row, col)
			bumpBytes(m[1])
			continue
		}
		if m := s.actionRe.FindStringSubmatchIndex(str); m != nil {
			add("ACTION", str[m[2]:m[3]], row, col)
			bumpBytes(m[1])
			continue
		}
		if m := s.archRe.FindStringSubmatchIndex(str); m != nil {
			add("ARCH_VAL", str[m[2]:m[3]], row, col)
			bumpBytes(m[1])
			continue
		}
		if s.syscallRe != nil {
			if m := s.syscallRe.FindStringSubmatchIndex(str); m != nil {
				add("SYSCALL", str[m[2]:m[3]], row, col)
				bumpBytes(m[1])
				continue
			}
		}
		if m := s.syscallAllRe.FindStringSubmatchIndex(str); m != nil {
			add("SYSCALL", str[:m[1]], row, col)
			bumpBytes(m[1])
			continue
		}
		if m := s.hexRe.FindStringIndex(str); m != nil {
			add("HEX_INT", str[:m[1]], row, col)
			bumpBytes(m[1])
			continue
		}
		if m := s.intRe.FindStringIndex(str); m != nil {
			add("INT", str[:m[1]], row, col)
			bumpBytes(m[1])
			continue
		}
		if m := s.aluRe.FindStringSubmatchIndex(str); m != nil {
			add("ALU_OP", str[m[2]:m[3]], row, col)
			bumpBytes(m[1])
			continue
		}
		if m := s.compareRe.FindStringSubmatchIndex(str); m != nil {
			add("COMPARE", str[m[2]:m[3]], row, col)
			bumpBytes(m[1])
			continue
		}
		if m := s.punctRe.FindStringSubmatchIndex(str); m != nil {
			text := str[m[2]:m[3]]
			add(text, text, row, col)
			bumpBytes(m[1])
			continue
		}
		if m := s.ternaryRe.FindStringSubmatchIndex(str); m != nil {
			add("GOTO_SYMBOL", str[m[2]:m[3]], row, col+runes(str[:m[2]]))
			add("GOTO_SYMBOL", str[m[4]:m[5]], row, col+runes(str[:m[4]]))
			bumpBytes(m[1])
			continue
		}
		if m := s.unknownRe.FindStringSubmatchIndex(str); m != nil {
			last := str[m[2]:m[3]]
			space := str[m[4]:m[5]]
			add("unknown", last, row, col)
			col += runes(last)
			str = space + str[m[1]:]
			continue
		}
		// Should be unreachable: the unknown matcher accepts any non-space run.
		break
	}
	return s.tokens
}

// Validate returns the unknown tokens, empty when the source is valid.
func (s *Scanner) Validate() []*Token {
	var out []*Token
	for _, t := range s.Scan() {
		if t.Sym == "unknown" {
			out = append(out, t)
		}
	}
	return out
}

// ValidateOrError raises UnrecognizedTokenError when any token is unknown.
func (s *Scanner) ValidateOrError() error {
	unknown := s.Validate()
	if len(unknown) == 0 {
		return nil
	}
	var b strings.Builder
	for i, t := range unknown {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(s.FormatError(t, fmt.Sprintf("unknown token %q", t.Str)))
	}
	return &UnrecognizedTokenError{Msg: b.String()}
}

// TabWidth is the width tabs expand to in error messages.
const TabWidth = 4

// FormatError renders a source location, the offending line, and carets.
func (s *Scanner) FormatError(tok *Token, msg string) string {
	lines := splitSourceLines(s.Source)
	line := ""
	if tok.Line >= 0 && tok.Line < len(lines) {
		line = lines[tok.Line]
	}
	display := strings.ReplaceAll(line, "\t", strings.Repeat(" ", TabWidth))
	prefixRunes := []rune(line)
	if tok.Col < len(prefixRunes) {
		prefixRunes = prefixRunes[:tok.Col]
	}
	prefix := string(prefixRunes)
	spaces := len([]rune(prefix)) + strings.Count(prefix, "\t")*(TabWidth-1)
	carets := strings.Repeat("^", len([]rune(tok.Str)))
	return fmt.Sprintf("%s:%d:%d %s\n%s\n%s%s\n",
		s.Filename, tok.Line+1, tok.Col+1, msg, display,
		strings.Repeat(" ", spaces), carets)
}

func splitSourceLines(src string) []string {
	var out []string
	for len(src) > 0 {
		i := strings.IndexByte(src, '\n')
		if i < 0 {
			out = append(out, src)
			break
		}
		out = append(out, src[:i])
		src = src[i+1:]
	}
	return out
}

var (
	syscallRegexCache sync.Map // arch -> *regexp.Regexp
	allSyscallOnce    sync.Once
	allSyscallRE      *regexp.Regexp
)

func archSyscallRegexp(arch string) *regexp.Regexp {
	if re, ok := syscallRegexCache.Load(arch); ok {
		return re.(*regexp.Regexp)
	}
	names := consts.SyscallNames(arch)
	re := regexp.MustCompile(`\A\b(` + alt(names) + `)\b`)
	syscallRegexCache.Store(arch, re)
	return re
}

func allSyscallRegexp() *regexp.Regexp {
	allSyscallOnce.Do(func() {
		allSyscallRE = regexp.MustCompile(`\A(` + strings.Join(consts.ABITableOrder, "|") +
			`)\.(` + alt(consts.AllSyscallNames()) + `)\b`)
	})
	return allSyscallRE
}
