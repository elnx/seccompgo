package asm

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/elnx/seccompgo/internal/disasm"
	"github.com/elnx/seccompgo/internal/instruction"
	"github.com/elnx/seccompgo/internal/util"
)

func firstDecompile(t *testing.T, src, arch string) (string, error) {
	t.Helper()
	c := NewCompiler(src, "", arch)
	codes, err := c.Compile()
	if err != nil {
		return "", err
	}
	if len(codes) == 0 {
		return "", nil
	}
	inst, err := instruction.New(codes[0])
	if err != nil {
		return "", err
	}
	return inst.Decompile()
}

func TestScannerValidate(t *testing.T) {
	if got := NewScanner("", "i386", "").Validate(); len(got) != 0 {
		t.Fatalf("empty source has unknown tokens: %v", got)
	}
	s := NewScanner("label1: A == write\n", "amd64", "")
	if got := s.Validate(); len(got) != 0 {
		t.Fatalf("valid source has unknown tokens: %v", got)
	}
	s = NewScanner("      label1: A = open\n      A = openat\n", "aarch64", "")
	got := s.Validate()
	want := []*Token{{Sym: "unknown", Str: "open", Line: 0, Col: 18}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unknown tokens = %#v, want %#v", got, want)
	}
}

func TestScannerErrorMessage(t *testing.T) {
	s := NewScanner("      label1: A = open\n      A = openat\n      A %%% 1\nmeow\n two errors\n", "aarch64", "")
	err := s.ValidateOrError()
	var unrecognized *UnrecognizedTokenError
	if !errors.As(err, &unrecognized) {
		t.Fatalf("error type = %T, want UnrecognizedTokenError", err)
	}
	want := `<inline>:1:19 unknown token "open"
      label1: A = open
                  ^^^^

<inline>:3:9 unknown token "%%%"
      A %%% 1
        ^^^

<inline>:4:1 unknown token "meow"
meow
^^^^

<inline>:5:2 unknown token "two"
 two errors
 ^^^

<inline>:5:6 unknown token "errors"
 two errors
     ^^^^^^
`
	if unrecognized.Msg != want {
		t.Fatalf("message mismatch:\n--- got ---\n%s\n--- want ---\n%s", unrecognized.Msg, want)
	}
}

func TestScannerIfExpressionTokens(t *testing.T) {
	s := NewScanner("if (A <= write) goto   xyz\n  if(A== 0x123 )    goto dead   else goto ok\n", "amd64", "")
	var got []string
	for _, tok := range s.Scan() {
		got = append(got, strings.Join([]string{
			itoa(tok.Line), ":", itoa(tok.Col), " ", tok.Sym, ":", tok.Str,
		}, ""))
	}
	want := []string{
		"0:0 IF:if", "0:3 (:(", "0:4 A:A", "0:6 COMPARE:<=", "0:9 SYSCALL:write",
		"0:14 ):)", "0:16 GOTO:goto", "0:23 GOTO_SYMBOL:xyz", "0:26 NEWLINE:\n",
		"1:2 IF:if", "1:4 (:(", "1:5 A:A", "1:6 COMPARE:==", "1:9 HEX_INT:0x123",
		"1:15 ):)", "1:20 GOTO:goto", "1:25 GOTO_SYMBOL:dead", "1:32 ELSE:else",
		"1:37 GOTO:goto", "1:42 GOTO_SYMBOL:ok", "1:44 NEWLINE:\n",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tokens:\n got %#v\nwant %#v", got, want)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}

func TestScannerCounts(t *testing.T) {
	s := NewScanner("if else A X RETurn\nlen mem ARGS args_h data sYS_NUMBEr aRch instRUCtion_pointer\n", "amd64", "")
	n := 0
	for _, tok := range s.Scan() {
		if tok.Sym != "NEWLINE" {
			n++
		}
	}
	if n != 13 {
		t.Fatalf("keyword token count = %d, want 13", n)
	}
	actions := "KILL_PROCESS\nKILL_THREAD\nKILL\nTRAP\nERRNO\nUSER_NOTIF\nLOG\nTRACE\nALLOW\n"
	s = NewScanner(actions, "amd64", "")
	count := 0
	for _, tok := range s.Scan() {
		if tok.Sym == "ACTION" {
			count++
		}
	}
	if count != 9 {
		t.Fatalf("action token count = %d, want 9", count)
	}
	s = NewScanner("amd64.open i386.open aarch64.open riscv64.open s390x.open", "amd64", "")
	count = 0
	for _, tok := range s.Scan() {
		if tok.Sym == "SYSCALL" {
			count++
		}
	}
	if count != 5 {
		t.Fatalf("arch.syscall count = %d, want 5", count)
	}
	s = NewScanner("abc: 123:\nsymbol:\n", "amd64", "")
	count = 0
	for _, tok := range s.Scan() {
		if tok.Sym == "SYMBOL" {
			count++
		}
	}
	if count != 3 {
		t.Fatalf("symbol count = %d, want 3", count)
	}
	s = NewScanner("0 0x123 -1 -2 1337 -0x1337\n", "amd64", "")
	count = 0
	for _, tok := range s.Scan() {
		if tok.Sym == "HEX_INT" || tok.Sym == "INT" {
			count++
		}
	}
	if count != 6 {
		t.Fatalf("integer count = %d, want 6", count)
	}
	s = NewScanner("() [] =\n", "amd64", "")
	count = 0
	for _, tok := range s.Scan() {
		if len(tok.Sym) == 1 && strings.ContainsRune("()[]=", rune(tok.Sym[0])) {
			count++
		}
	}
	if count != 5 {
		t.Fatalf("punctuation count = %d, want 5", count)
	}
}

func TestScannerCommentsAndEmptyLines(t *testing.T) {
	s := NewScanner("      # a comment\n      A # return\n", "aarch64", "")
	want := []*Token{
		{Sym: "A", Str: "A", Line: 1, Col: 6},
		{Sym: "NEWLINE", Str: "\n", Line: 1, Col: 16},
	}
	if got := s.Scan(); !reflect.DeepEqual(got, want) {
		t.Fatalf("tokens = %#v, want %#v", got, want)
	}
	s = NewScanner("      line0: A = 123\n\n\n      line3: return A\n", "s390x", "")
	found := false
	for _, tok := range s.Scan() {
		if tok.Equal(&Token{Sym: "RETURN", Str: "return", Line: 3, Col: 13}) {
			found = true
		}
	}
	if !found {
		t.Fatalf("RETURN token on line 3 not found")
	}
}

func TestScannerTernary(t *testing.T) {
	s := NewScanner("A == ARCH_X86_64 ? next : dead\n", "aarch64", "")
	want := []*Token{
		{Sym: "A", Str: "A", Line: 0, Col: 0},
		{Sym: "COMPARE", Str: "==", Line: 0, Col: 2},
		{Sym: "ARCH_VAL", Str: "ARCH_X86_64", Line: 0, Col: 5},
		{Sym: "GOTO_SYMBOL", Str: "next", Line: 0, Col: 19},
		{Sym: "GOTO_SYMBOL", Str: "dead", Line: 0, Col: 26},
		{Sym: "NEWLINE", Str: "\n", Line: 0, Col: 30},
	}
	if got := s.Scan(); !reflect.DeepEqual(got, want) {
		t.Fatalf("tokens = %#v, want %#v", got, want)
	}
}

func TestAsmNormal(t *testing.T) {
	src := `# lines starting with '#' are comments
  A = sys_number # here's a comment, too
  A >= 0x40000000 ? dead : next
  A == read ? ok : next
  A == 1 ? ok : next
  return ERRNO(1)
dead:
  return KILL
ok:
  return ALLOW
`
	raw, err := Asm(src, "", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	got, err := disasm.Disasm(raw, "amd64", true, true)
	if err != nil {
		t.Fatal(err)
	}
	want := ` line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x35 0x03 0x00 0x40000000  if (A >= 0x40000000) goto 0005
 0002: 0x15 0x03 0x00 0x00000000  if (A == read) goto 0006
 0003: 0x15 0x02 0x00 0x00000001  if (A == write) goto 0006
 0004: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0005: 0x06 0x00 0x00 0x00000000  return KILL
 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
`
	if got != want {
		t.Fatalf("disasm mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestAsmAssignCases(t *testing.T) {
	src := `A = mem[3]
X= mem[15]
A=    X
X =A
A =arch
A = args[4]
A = data[16]
mem[15] = A
mem[1] = X
`
	raw, err := Asm(src, "", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	got, err := disasm.Disasm(raw, "amd64", false, true)
	if err != nil {
		t.Fatal(err)
	}
	want := `0000: A = mem[3]
0001: X = mem[15]
0002: A = X
0003: X = A
0004: A = arch
0005: A = args[4]
0006: A = args[0]
0007: mem[15] = A
0008: mem[1] = X
`
	if got != want {
		t.Fatalf("disasm mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestAsmReturnsAndALU(t *testing.T) {
	raw, err := Asm("return KILL_PROCESS\nreturn KILL_THREAD\nreturn KILL\nreturn TRAP\nreturn ERRNO(3)\nreturn TRACE\nreturn ALLOW\n", "", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := disasm.Disasm(raw, "amd64", false, true)
	want := `0000: return KILL_PROCESS
0001: return KILL
0002: return KILL
0003: return TRAP
0004: return ERRNO(3)
0005: return TRACE
0006: return ALLOW
`
	if got != want {
		t.Fatalf("returns mismatch:\n%s", got)
	}
	raw, err = Asm("A &= read\nA += write\nA *= 0x1\nA -= X\nA /= 0xf\nA |= 2\nA >>= 1\nA <<= 1\nA = -A\nA ^= 0x1337\n", "", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	got, _ = disasm.Disasm(raw, "amd64", false, true)
	want = `0000: A &= 0x0
0001: A += 0x1
0002: A *= 0x1
0003: A -= X
0004: A /= 0xf
0005: A |= 0x2
0006: A >>= 1
0007: A <<= 1
0008: A = -A
0009: A ^= 0x1337
`
	if got != want {
		t.Fatalf("alu mismatch:\n%s", got)
	}
}

func TestAsmBigEndianWords(t *testing.T) {
	src := `A = args[2]
A = args[2] >> 32
A = args_h[2]
A = instruction_pointer
A = instruction_pointer >> 32
return ALLOW
`
	raw, _ := Asm(src, "", "s390x")
	got, _ := disasm.Disasm(raw, "s390x", false, true)
	want := `0000: A = args[2]
0001: A = args[2] >> 32
0002: A = args[2] >> 32
0003: A = instruction_pointer
0004: A = instruction_pointer >> 32
0005: return ALLOW
`
	if got != want {
		t.Fatalf("s390x mismatch:\n%s", got)
	}
	raw, _ = Asm(src, "", "amd64")
	got, _ = disasm.Disasm(raw, "amd64", false, true)
	want = `0000: A = args[2]
0001: A = args[2] >> 32
0002: A = args[2] >> 32
0003: A = instruction_pointer
0004: A = instruction_pointer >> 32
0005: return ALLOW
`
	if got != want {
		t.Fatalf("amd64 mismatch:\n%s", got)
	}
}

func TestCompilerBasics(t *testing.T) {
	cases := []struct{ src, want string }{
		{"A = X", "A = X"},
		{"X = A", "X = A"},
		{"X=A", "X = A"},
		{"A = 123", "A = 123"},
		{"A = nanosleep", "A = 35"},
		{"X = nanosleep", "X = 35"},
		{"A = mem[0]", "A = mem[0]"},
		{"X = mem[1]", "X = mem[1]"},
		{"A = data[0]", "A = sys_number"},
		{"A = sys_number", "A = sys_number"},
		{"A = arch", "A = arch"},
		{"A = len", "A = 64"},
		{"A = args[0]", "A = args[0]"},
		{"A = args[1]", "A = args[1]"},
		{"A = args_h[0]", "A = args[0] >> 32"},
		{"A = args_h[1]", "A = args[1] >> 32"},
		{"A = instruction_pointer >> 32", "A = instruction_pointer >> 32"},
		{"A = args[0] >> 32", "A = args[0] >> 32"},
		{"return ERRNO(3)", "return ERRNO(3)"},
		{"return ALLOW", "return ALLOW"},
		{"return A", "return A"},
		{"A += 0x31337", "A += 0x31337"},
		{"A &= read", "A &= 0x0"},
		{"A ^= X", "A ^= X"},
		{"A = -A", "A = -A"},
	}
	for _, c := range cases {
		got, err := firstDecompile(t, c.src, "amd64")
		if err != nil {
			t.Fatalf("%q: %v", c.src, err)
		}
		if got != c.want {
			t.Errorf("%q = %q, want %q", c.src, got, c.want)
		}
	}
	got, err := firstDecompile(t, "A = nanosleep", "i386")
	if err != nil || got != "A = 162" {
		t.Fatalf("i386 nanosleep = %q, %v", got, err)
	}
}

func TestCompilerConditionals(t *testing.T) {
	src := `0000: A = sys_number
0001: A == read ? ok : dead
0002: A != read ? ok : 2
0003: A <= 0x1337 ? ok : next
0004: A < 1337 ? ok : dead
0005: A >= read ? ok : dead
ok:
return ALLOW
dead:
return KILL
`
	c := NewCompiler(src, "", "amd64")
	codes, err := c.Compile()
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, code := range codes {
		inst, _ := instruction.New(code)
		text, err := inst.Decompile()
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, text)
	}
	want := `A = sys_number
if (A == 0) goto 0006 else goto 0007
if (A == 0) goto 0005 else goto 0006
if (A <= 4919) goto 0006
if (A >= 1337) goto 0007 else goto 0006
if (A < 0) goto 0007
return ALLOW
return KILL`
	if got := strings.Join(lines, "\n"); got != want {
		t.Fatalf("conditionals mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	c = NewCompiler(`A = args[0]
X = A
if (A == X) goto out
else goto out
A = X
out: return ALLOW
`, "", "amd64")
	codes, err = c.Compile()
	if err != nil {
		t.Fatal(err)
	}
	lines = nil
	for _, code := range codes {
		inst, _ := instruction.New(code)
		text, _ := inst.Decompile()
		lines = append(lines, text)
	}
	if got := strings.Join(lines, "\n"); got != "A = args[0]\nX = A\ngoto 0004\nA = X\nreturn ALLOW" {
		t.Fatalf("jump optimization mismatch:\n%s", got)
	}
}

func TestCompilerErrors(t *testing.T) {
	tests := []struct {
		name string
		src  string
		typ  any
		msg  string
	}{
		{
			name: "data index",
			src:  "A = data[1]\n",
			typ:  &ParseError{},
			msg: `<inline>:1:10 index of data[] must be a multiple of 4 and less than 64, got 1
A = data[1]
         ^
`,
		},
		{
			name: "backward",
			src:  "A = 0\nloop:\nA += 1\nA <= 10 ? loop : next\n",
			typ:  &BackwardJumpError{},
			msg: `<inline>:4:11 Does not support backward jumping to 'loop'
A <= 10 ? loop : next
          ^^^^
`,
		},
		{
			name: "undefined",
			src:  "# a comment\nA = sys_number\n\nA == open ? alow : next\n",
			typ:  &UndefinedLabelError{},
			msg: `<inline>:4:13 Cannot find label 'alow'
A == open ? alow : next
            ^^^^
`,
		},
		{
			name: "duplicate",
			src:  "label: A = X\nX = A\nlabel: A = 123\n",
			typ:  &DuplicateLabelError{},
			msg: `<inline>:3:1 duplicate label 'label'
label: A = 123
^^^^^
<inline>:1:1 previously defined here
label: A = X
^^^^^
`,
		},
		{
			name: "long jump",
			src:  "A = args[0]\nA == 0 ? next : end\n" + strings.Repeat("A = 0\n", 260) + "end:   return ALLOW\n",
			typ:  &LongJumpError{},
			msg: `<inline>:2:17 Does not support jumping farther than 255, got: 260
A == 0 ? next : end
                ^^^
`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewCompiler(tc.src, "", "amd64").Compile()
			if err == nil {
				t.Fatal("expected error")
			}
			switch tc.typ.(type) {
			case *ParseError:
				if _, ok := errors.AsType[*ParseError](err); !ok {
					t.Fatalf("type %T", err)
				}
			case *BackwardJumpError:
				if _, ok := errors.AsType[*BackwardJumpError](err); !ok {
					t.Fatalf("type %T", err)
				}
			case *UndefinedLabelError:
				if _, ok := errors.AsType[*UndefinedLabelError](err); !ok {
					t.Fatalf("type %T", err)
				}
			case *DuplicateLabelError:
				if _, ok := errors.AsType[*DuplicateLabelError](err); !ok {
					t.Fatalf("type %T", err)
				}
			case *LongJumpError:
				if _, ok := errors.AsType[*LongJumpError](err); !ok {
					t.Fatalf("type %T", err)
				}
			}
			if err.Error() != tc.msg {
				t.Fatalf("message:\n--- got ---\n%s\n--- want ---\n%s", err.Error(), tc.msg)
			}
		})
	}
}

func TestCompilerAcceptsJumpWithoutConditions(t *testing.T) {
	src := `goto next
jump jump_a
A = X

jump_a:
A = sys_number
jmp jump_b
X = A

# a comment
jump_b:
A = arch
`
	c := NewCompiler(src, "", "amd64")
	codes, err := c.Compile()
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, code := range codes {
		inst, _ := instruction.New(code)
		text, _ := inst.Decompile()
		lines = append(lines, text)
	}
	want := "goto 0001\ngoto 0003\nA = X\nA = sys_number\ngoto 0006\nX = A\nA = arch"
	if got := strings.Join(lines, "\n"); got != want {
		t.Fatalf("got:\n%s", got)
	}
}

func TestCompilerMultipleLabels(t *testing.T) {
	src := `goto label
goto lll
goto Label
A = X
lll: Label: label:
X = A
`
	c := NewCompiler(src, "", "amd64")
	codes, err := c.Compile()
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, code := range codes {
		inst, _ := instruction.New(code)
		text, _ := inst.Decompile()
		lines = append(lines, text)
	}
	want := "goto 0004\ngoto 0004\ngoto 0004\nA = X\nX = A"
	if got := strings.Join(lines, "\n"); got != want {
		t.Fatalf("got:\n%s", got)
	}
}

func TestParserNewlinesAndNotConditions(t *testing.T) {
	src := "      A     +=\n       # a comment\n       # another comment\n\n       123 # yet another comment\n       # last comment\n"
	got, err := firstDecompile(t, src, "amd64")
	if err != nil || got != "A += 0x7b" {
		t.Fatalf("embedded newline = %q, %v", got, err)
	}
	full := "      if (!(A & 0x123)) goto a else goto b\n      if (! (A != X)) goto c\n      if (!(!(!(!(!(!(A == X))))))) goto d\n"
	c := NewCompiler(full, "", "amd64")
	statements, err := (&parser{sc: c.sc, toks: c.sc.Scan()}).parse()
	if err != nil {
		t.Fatal(err)
	}
	if len(statements) != 3 {
		t.Fatalf("statements = %d", len(statements))
	}
	if statements[0].Cmp.Op != "&" || statements[0].Jt.Str != "b" || statements[0].Jf.Str != "a" {
		t.Fatalf("first = %+v", statements[0])
	}
	if statements[1].Cmp.Op != "!=" || statements[1].Jt != nil || statements[1].Jf.Str != "c" {
		t.Fatalf("second Jt=%v Jf=%v", statements[1].Jt, statements[1].Jf)
	}
	if statements[2].Cmp.Op != "==" || statements[2].Jt.Str != "d" || statements[2].Jf != nil {
		t.Fatalf("third = %+v", statements[2])
	}
}

func TestParserTrailingLabel(t *testing.T) {
	c := NewCompiler("      goto oob\n      oob:\n", "", "amd64")
	_, err := c.Compile()
	if _, ok := errors.AsType[*ParseError](err); !ok {
		t.Fatalf("error = %T", err)
	}
	want := "<inline>:2:11 unexpected string \"\\n\"\n      oob:\n          ^\n"
	if err.Error() != want {
		t.Fatalf("got %q want %q", err.Error(), want)
	}
}

func TestParserArgumentShiftErrors(t *testing.T) {
	c := NewCompiler("      A = args[0] >> 5\n", "", "amd64")
	_, err := c.Compile()
	want := "<inline>:1:22 operator after an argument can only be '>> 32'\n      A = args[0] >> 5\n                     ^\n"
	if err == nil || err.Error() != want {
		t.Fatalf("shift error = %v", err)
	}
	c = NewCompiler("      A = instruction_pointer + 1\n", "", "amd64")
	_, err = c.Compile()
	want = "<inline>:1:31 operator after an argument can only be '>> 32'\n      A = instruction_pointer + 1\n                              ^\n"
	if err == nil || err.Error() != want {
		t.Fatalf("plus error = %v", err)
	}
}

func TestParserCrossArchSyscallsAndErrors(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want string
	}{
		{"A = aarch64.read", "A = 63"},
		{"A = riscv64.riscv_hwprobe", "A = 258"},
	} {
		got, err := firstDecompile(t, tc.src, "amd64")
		if err != nil || got != tc.want {
			t.Fatalf("%s = %q, %v", tc.src, got, err)
		}
	}
	c := NewCompiler("      A = aarch64.open\n", "", "amd64")
	_, err := c.Compile()
	want := "<inline>:1:11 syscall 'open' doesn't exist on aarch64\n      A = aarch64.open\n          ^^^^^^^^^^^^\n"
	if err == nil || err.Error() != want {
		t.Fatalf("got %v", err)
	}
}

func TestParserLabelsAcrossLines(t *testing.T) {
	src := `      line1:
      goto next
      label1: label2: goto next
      multi1:
      multi2: multi3: goto next
`
	c := NewCompiler(src, "", "amd64")
	statements, err := (&parser{sc: c.sc, toks: c.sc.Scan()}).parse()
	if err != nil {
		t.Fatal(err)
	}
	var got [][]string
	for _, st := range statements {
		var names []string
		for _, sym := range st.Symbols {
			names = append(names, sym.Str)
		}
		got = append(got, names)
	}
	want := [][]string{{"line1"}, {"label1", "label2"}, {"multi1", "multi2", "multi3"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("labels = %#v", got)
	}
}

func TestParserErrorMessagesFromGrammar(t *testing.T) {
	cases := []struct{ src, want string }{
		{"      A = +A\n", "<inline>:1:11 do you mean A = -A?\n      A = +A\n          ^\n"},
		{"      mem[16] = A\n", "<inline>:1:11 index of mem[] must between 0 and 15, got 16\n      mem[16] = A\n          ^^\n"},
		{"      A = mem[0xaa]\n", "<inline>:1:15 index of mem[] must between 0 and 15, got 170\n      A = mem[0xaa]\n              ^^^^\n"},
		{"      A = args[8]\n", "<inline>:1:16 index of args[] must between 0 and 5, got 8\n      A = args[8]\n               ^\n"},
		{"      next: A = 1\n", "<inline>:1:7 'next' is a reserved label\n      next: A = 1\n      ^^^^\n"},
	}
	for _, tc := range cases {
		_, err := NewCompiler(tc.src, "", "amd64").Compile()
		if err == nil || err.Error() != tc.want {
			t.Errorf("src %q:\n got %v\nwant %s", tc.src, err, tc.want)
		}
	}
}

func TestAsmAcceptsDisasmOutputForEveryArch(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("..", "..", "testdata", "data", "*.bpf"))
	if len(files) == 0 {
		t.Fatal("no bpf fixtures")
	}
	for _, arch := range util.SupportedArchs() {
		for _, f := range files {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			src, err := disasm.Disasm(raw, arch, false, false)
			if err != nil {
				t.Fatalf("%s/%s disasm: %v", arch, f, err)
			}
			if _, err := Asm(src, f, arch); err != nil {
				t.Fatalf("%s/%s reassemble: %v\n%s", arch, f, err, src)
			}
		}
	}
}
