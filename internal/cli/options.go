package cli

import (
	"fmt"
	"strconv"
	"strings"
)

// Options is the union of option values accepted by the subcommands.
type Options struct {
	Arch     string
	HasArch  bool
	IFile    string
	HasIFile bool
	OFile    string
	HasOFile bool
	Format   string

	Limit      int
	PID        int
	HasPID     bool
	Timeout    float64
	HasTimeout bool
	Command    string
	HasCommand bool

	BPF      bool
	ArgInfer bool

	IP    uint64
	HasIP bool

	Quiet   bool
	Verbose int
}

type optKind int

const (
	optFlag optKind = iota
	optNegatable
	optString
	optInt
	optFloat
	optChoice
)

type option struct {
	short   byte
	long    string
	display string
	kind    optKind
	choices []string
	desc    []string
	apply   func(*Options, string) error
}

// helpLine renders the option summary as OptionParser does.
func (o *option) helpLine() string {
	left := o.display
	if left == "" {
		switch {
		case o.short != 0 && o.kind == optNegatable:
			left = fmt.Sprintf("-%c, --[no-]%s", o.short, o.long)
		case o.short != 0:
			left = fmt.Sprintf("-%c, --%s", o.short, o.long)
		case o.kind == optNegatable:
			left = "    --[no-]" + o.long
		default:
			left = "    --" + o.long
		}
	}
	var b strings.Builder
	b.WriteString("    ")
	b.WriteString(left)
	if len(left) < 32 {
		b.WriteString(strings.Repeat(" ", 32-len(left)))
	}
	b.WriteString(" ")
	if len(o.desc) > 0 {
		b.WriteString(o.desc[0])
	}
	b.WriteByte('\n')
	for _, d := range o.desc[1:] {
		b.WriteString(strings.Repeat(" ", 37))
		b.WriteString(d)
		b.WriteByte('\n')
	}
	return b.String()
}

func formatHelp(banner string, specs []*option) string {
	var b strings.Builder
	b.WriteString(banner)
	b.WriteByte('\n')
	for _, opt := range specs {
		b.WriteString(opt.helpLine())
	}
	return b.String()
}

func (o *option) matchesLong(name string) bool {
	if o.kind == optNegatable {
		return name == o.long || name == "no-"+o.long
	}
	return name == o.long
}

func (o *option) set(opts *Options, val string, negated bool) error {
	if o.kind == optNegatable {
		if negated {
			val = "false"
		} else {
			val = "true"
		}
	}
	switch o.kind {
	case optFlag:
		return o.apply(opts, "true")
	case optNegatable:
		return o.apply(opts, val)
	case optChoice:
		ok := false
		for _, c := range o.choices {
			if c == val {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("invalid argument: %s", val)
		}
	case optInt, optFloat:
		if _, err := parseNumberLike(val, o.kind == optFloat); err != nil {
			return err
		}
	}
	return o.apply(opts, val)
}

func parseNumberLike(s string, isFloat bool) (string, error) {
	if isFloat {
		if _, err := strconv.ParseFloat(s, 64); err != nil {
			return "", err
		}
		return s, nil
	}
	if _, err := rubyInteger(s); err != nil {
		return "", err
	}
	return s, nil
}

// parseOptions permutes options and positionals, like Ruby's OptionParser.
func parseOptions(args []string, specs []*option, opts *Options) ([]string, error) {
	var positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "--") {
			name := arg[2:]
			inline := ""
			hasInline := false
			if j := strings.IndexByte(name, '='); j >= 0 {
				inline = name[j+1:]
				name = name[:j]
				hasInline = true
			}
			var found *option
			for _, s := range specs {
				if s.matchesLong(name) {
					found = s
					break
				}
			}
			if found == nil {
				return nil, fmt.Errorf("invalid option: %s", arg)
			}
			negated := found.kind == optNegatable && name == "no-"+found.long
			if found.kind == optFlag || found.kind == optNegatable {
				if hasInline {
					if err := found.set(opts, inline, negated); err != nil {
						return nil, err
					}
				} else if err := found.set(opts, "", negated); err != nil {
					return nil, err
				}
				continue
			}
			val := inline
			if !hasInline {
				if i+1 >= len(args) {
					return nil, fmt.Errorf("missing argument: %s", arg)
				}
				i++
				val = args[i]
			}
			if err := found.set(opts, val, false); err != nil {
				return nil, err
			}
			continue
		}
		if len(arg) > 1 && arg[0] == '-' && arg != "-" {
			ch := arg[1]
			var found *option
			for _, s := range specs {
				if s.short != 0 && s.short == ch {
					found = s
					break
				}
			}
			if found == nil {
				return nil, fmt.Errorf("invalid option: %s", arg)
			}
			if found.kind == optFlag || found.kind == optNegatable {
				if err := found.set(opts, "", false); err != nil {
					return nil, err
				}
				continue
			}
			val := arg[2:]
			if val == "" {
				if i+1 >= len(args) {
					return nil, fmt.Errorf("missing argument: %s", arg)
				}
				i++
				val = args[i]
			}
			if err := found.set(opts, val, false); err != nil {
				return nil, err
			}
			continue
		}
		positional = append(positional, arg)
	}
	return positional, nil
}

// rubyInteger parses an integer the way Ruby's Integer() does for the forms the CLI
// accepts: optional sign, 0x/0b/0o prefixes, leading-zero octal, and underscores.
func rubyInteger(s string) (int64, error) {
	orig := s
	neg := false
	if strings.HasPrefix(s, "-") {
		neg = true
		s = s[1:]
	} else if strings.HasPrefix(s, "+") {
		s = s[1:]
	}
	s = strings.ReplaceAll(s, "_", "")
	if s == "" {
		return 0, fmt.Errorf("invalid value for Integer(): %q", orig)
	}
	base := 10
	switch {
	case strings.HasPrefix(s, "0x"), strings.HasPrefix(s, "0X"):
		base, s = 16, s[2:]
	case strings.HasPrefix(s, "0b"), strings.HasPrefix(s, "0B"):
		base, s = 2, s[2:]
	case strings.HasPrefix(s, "0o"), strings.HasPrefix(s, "0O"):
		base, s = 8, s[2:]
	case len(s) > 1 && s[0] == '0':
		base, s = 8, s[1:]
	}
	if s == "" {
		return 0, fmt.Errorf("invalid value for Integer(): %q", orig)
	}
	u, err := strconv.ParseUint(s, base, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid value for Integer(): %q", orig)
	}
	if neg {
		return -int64(u), nil
	}
	if u > uint64(^uint64(0)>>1) {
		return 0, fmt.Errorf("invalid value for Integer(): %q", orig)
	}
	return int64(u), nil
}
