// Package cli implements the seccomp-tools command line interface.
package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"seccompgo/internal/dumper"
	"seccompgo/internal/logger"
	"seccompgo/internal/util"
)

// Version is the tool version.
const Version = "1.7.1"

// Command summaries and usage banners.
type commandInfo struct {
	summary string
	usage   string
}

var commands = map[string]commandInfo{
	"asm":        {"Seccomp bpf assembler.", "asm - Seccomp bpf assembler.\n\nUsage: seccomp-tools asm IN_FILE [options]"},
	"audit":      {"Assess a seccomp filter for weaknesses and escape routes.", "audit - Assess a seccomp filter for weaknesses and escape routes.\n\nUsage: seccomp-tools audit [options] [BPF_FILE|EXEC]"},
	"completion": {"Print a shell completion script.", "completion - Print a shell completion script.\n\nUsage: seccomp-tools completion <bash|zsh|fish>"},
	"disasm":     {"Disassemble seccomp bpf.", "disasm - Disassemble seccomp bpf.\n\nUsage: seccomp-tools disasm BPF_FILE [options]"},
	"dump":       {"Automatically dump seccomp bpf from executable(s).", "dump - Automatically dump seccomp bpf from executable(s).\nNOTE: This command is only available on Linux.\n\nUsage: seccomp-tools dump [EXEC] [options]"},
	"emu":        {"Emulate seccomp rules.", "emu - Emulate seccomp rules.\n\nUsage: seccomp-tools emu [options] BPF_FILE [sys_nr [arg0 [arg1 ... arg5]]]"},
	"explain":    {"Summarize a seccomp filter as a per-action policy.", "explain - Summarize a seccomp filter as a per-action policy.\n\nUsage: seccomp-tools explain [options] [BPF_FILE|EXEC]"},
}

var commandOrder = []string{"asm", "audit", "completion", "disasm", "dump", "emu", "explain"}

func usage() string {
	var b strings.Builder
	b.WriteString("Usage: seccomp-tools [--version] [--help] <command> [<options>]\n\nList of commands:\n\n")
	for _, name := range commandOrder {
		fmt.Fprintf(&b, "\t%s\t%s\n", name, commands[name].summary)
	}
	b.WriteString("\nSee 'seccomp-tools <command> --help' to read about a specific subcommand.\n")
	return b.String()
}

func show(msg string) {
	io.WriteString(util.Stdout, msg)
	if !strings.HasSuffix(msg, "\n") {
		io.WriteString(util.Stdout, "\n")
	}
}

// Run executes the CLI and returns the process exit code.
func Run(argv []string) int {
	mapped := make([]string, len(argv))
	for i, a := range argv {
		if a == "-h" {
			mapped[i] = "--help"
		} else {
			mapped[i] = a
		}
	}
	idx := -1
	for i, a := range mapped {
		if !strings.HasPrefix(a, "-") {
			idx = i
			break
		}
	}
	var pre []string
	rest := mapped
	if idx < 0 {
		pre = mapped
		rest = nil
	} else {
		pre = mapped[:idx]
		rest = mapped[idx:]
	}
	for _, a := range pre {
		if a == "--version" {
			show("SeccompTools Version " + Version)
			return 0
		}
	}
	if idx < 0 {
		show(usage())
		return 0
	}
	cmd := rest[0]
	rest = rest[1:]
	for _, a := range pre {
		if a == "--help" {
			rest = []string{"--help"}
			break
		}
	}
	info, ok := commands[cmd]
	if !ok {
		show(fmt.Sprintf("Invalid command '%s'\n\nSee 'seccomp-tools --help' for list of valid commands", cmd))
		return 0
	}
	switch cmd {
	case "asm":
		return runAsm(rest, info)
	case "audit":
		return runAudit(rest, info)
	case "completion":
		return runCompletion(rest, info)
	case "disasm":
		return runDisasm(rest, info)
	case "dump":
		return runDump(rest, info)
	case "emu":
		return runEmu(rest, info)
	case "explain":
		return runExplain(rest, info)
	}
	return 0
}

type base struct {
	opts        Options
	argv        []string
	info        commandInfo
	specs       []*option
	archOffered bool

	acceptsRawBPF bool
	exitCode      int
}

func newBase(info commandInfo, specs []*option, defaults func(*Options)) *base {
	b := &base{info: info, specs: specs}
	if defaults != nil {
		defaults(&b.opts)
	}
	return b
}

func (b *base) help() string { return formatHelp(b.info.usage, b.specs) }

// handle processes help, options and architecture defaulting.
func (b *base) handle() bool {
	if len(b.argv) == 0 || hasHelp(b.argv) {
		show(b.help())
		return false
	}
	rest, err := parseOptions(b.argv, b.specs, &b.opts)
	if err != nil {
		logger.Error(err.Error())
		b.exitCode = 1
		return false
	}
	b.argv = rest
	if !b.opts.HasArch {
		arch := util.SystemArch()
		if arch == "unknown" && b.archOffered {
			logger.Error("Could not detect the host architecture; specify one with " +
				"--arch <" + strings.Join(util.SupportedArchs(), "|") + ">.")
			return false
		}
		b.opts.Arch = arch
	}
	return true
}

func hasHelp(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "--help" {
			return true
		}
	}
	return false
}

func (b *base) warnIgnoredArguments() {
	if len(b.argv) == 0 {
		return
	}
	word := "argument"
	if len(b.argv) > 1 {
		word = "arguments"
	}
	logger.Warn(fmt.Sprintf("ignoring unused %s: %s", word, strings.Join(b.argv, " ")))
}

// input reads "-" from stdin, otherwise from the file.
func (b *base) input() ([]byte, error) {
	if b.opts.IFile == "-" {
		return io.ReadAll(util.Stdin)
	}
	return os.ReadFile(b.opts.IFile)
}

func fileOf(file string, serial int) string {
	suffix := ""
	if serial != 0 {
		suffix = fmt.Sprintf("_%d", serial)
	}
	ext := rubyExtname(file)
	base := strings.TrimSuffix(filepath.Base(file), ext)
	return filepath.Join(filepath.Dir(file), base+suffix) + ext
}

// rubyExtname matches Ruby's File.extname, which differs from Go's for dotfiles.
func rubyExtname(file string) string {
	base := filepath.Base(file)
	i := strings.LastIndexByte(base, '.')
	if i <= 0 {
		return ""
	}
	return base[i:]
}

// writeOutput renders gen and writes it to stdout or the next serial output file.
func (b *base) writeOutput(serial *int, gen func() ([]byte, error)) error {
	if !b.opts.HasOFile {
		data, err := gen()
		if err != nil {
			return err
		}
		_, err = util.Stdout.Write(data)
		return err
	}
	enabled := util.ColorizeEnabled()
	if enabled {
		util.DisableColor()
	}
	data, err := gen()
	if enabled {
		util.EnableColor()
	}
	if err != nil {
		return err
	}
	if err := os.WriteFile(fileOf(b.opts.OFile, *serial), data, 0o666); err != nil {
		return err
	}
	*serial++
	return nil
}

func (b *base) writeString(serial *int, text string) error {
	return b.writeOutput(serial, func() ([]byte, error) { return []byte(text), nil })
}

// filterTuple is one raw filter plus its architecture and display source.
type filterTuple struct {
	Raw    []byte
	Arch   string
	Source string
}

// collectFilters resolves the positional argument, -c and --pid into filters.
func (b *base) collectFilters() []filterTuple {
	if !b.opts.HasCommand && !b.opts.HasPID && len(b.argv) > 0 {
		b.opts.IFile = b.argv[0]
		b.argv = b.argv[1:]
	}
	b.warnIgnoredArguments()

	if b.opts.HasPID {
		return b.dumpFilters("", b.opts.PID, fmt.Sprintf("pid %d", b.opts.PID))
	}
	command := b.opts.Command
	if !b.opts.HasCommand {
		command = b.opts.IFile
	}
	if command == "" {
		show(b.help())
		return nil
	}
	raw := b.acceptsRawBPF && !b.opts.HasCommand && !b.executable(b.opts.IFile)
	if raw {
		return b.readRawBPF()
	}
	return b.dumpFilters(command, 0, command)
}

func (b *base) readRawBPF() []filterTuple {
	raw, err := b.input()
	if err != nil {
		logger.Error(rubySysError(err, b.opts.IFile))
		return nil
	}
	source := b.opts.IFile
	if source == "-" {
		source = "<STDIN>"
	}
	return []filterTuple{{Raw: raw, Arch: b.opts.Arch, Source: source}}
}

func (b *base) executable(file string) bool {
	return file != "" && file != "-" && util.Elf(file)
}

func (b *base) dumpFilters(command string, pid int, source string) []filterTuple {
	if !b.dumpingSupported() {
		return nil
	}
	results := b.dumpSeccomp(command, pid)
	out := make([]filterTuple, 0, len(results))
	for _, r := range results {
		arch := r.Arch
		if arch == "" {
			arch = b.opts.Arch
		}
		out = append(out, filterTuple{Raw: r.BPF, Arch: arch, Source: source})
	}
	return out
}

func (b *base) dumpSeccomp(command string, pid int) []dumper.Result {
	if b.opts.HasPID {
		results, err := dumper.DumpByPID(b.opts.PID, b.opts.Limit)
		if err != nil {
			if errors.Is(err, fs.ErrPermission) || isPermission(err) {
				b.dumpPermissionError(err)
				return nil
			}
			logger.Error(err.Error())
			b.exitCode = 1
			return nil
		}
		return results
	}
	var timeout *float64
	if b.opts.HasTimeout {
		t := b.opts.Timeout
		timeout = &t
	}
	results := dumper.Dump([]string{"/bin/sh", "-c", command}, b.opts.Limit, timeout)
	if len(results) == 0 {
		logger.Warn("No seccomp filter was installed.")
	}
	return results
}

func isPermission(err error) bool {
	return errors.Is(err, os.ErrPermission) || strings.Contains(strings.ToLower(err.Error()), "operation not permitted") ||
		strings.Contains(strings.ToLower(err.Error()), "permission denied")
}

func (b *base) dumpPermissionError(err error) {
	args := append([]string{"seccomp-tools"}, os.Args[1:]...)
	msg := fmt.Sprintf("%s\nPTRACE_SECCOMP_GET_FILTER requires CAP_SYS_ADMIN\nTry:\n    sudo env \"PATH=$PATH\" %s",
		err, shellJoin(args))
	logger.Error(msg)
	b.exitCode = 1
}

func (b *base) dumpingSupported() bool {
	if dumper.Supported {
		return true
	}
	logger.Error("Dumping a filter from an executable or process is only available on Linux.")
	return false
}

func shellJoin(args []string) string {
	var out []string
	for _, a := range args {
		out = append(out, shellEscape(a))
	}
	return strings.Join(out, " ")
}

func shellEscape(s string) string {
	if s == "" {
		return "''"
	}
	var b strings.Builder
	for _, r := range s {
		safe := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			strings.ContainsRune("_-.,:+/@", r)
		if safe {
			b.WriteRune(r)
		} else {
			b.WriteByte('\\')
			b.WriteRune(r)
		}
	}
	return b.String()
}

func rubySysError(err error, path string) string {
	if errors.Is(err, fs.ErrNotExist) {
		return "No such file or directory @ rb_sysopen - " + path
	}
	if errors.Is(err, fs.ErrPermission) {
		return "Permission denied @ rb_sysopen - " + path
	}
	return err.Error()
}

// filterOptionSpecs builds the shared -c/-l/-p/-t options.
func filterOptionSpecs(action string) []*option {
	return []*option{
		{
			short: 'c', long: "sh-exec", kind: optString,
			display: "-c, --sh-exec <command>",
			desc: []string{
				fmt.Sprintf("Executes the given command (via sh) and %ss its seccomp.", action),
				"Use this to pass arguments or pipe things to the executable.",
				"e.g. use `-c \"./bin > /dev/null\"` to keep the program output out of the result.",
				"Takes precedence over the positional argument.",
			},
			apply: func(o *Options, v string) error {
				o.Command, o.HasCommand = v, true
				return nil
			},
		},
		{
			short: 'l', long: "limit", kind: optInt, display: "-l, --limit LIMIT",
			desc: []string{
				fmt.Sprintf("%s only the first LIMIT installed filters.", titleCase(action)),
				"Only meaningful when the input is an executable or --pid. Default: 1",
				"An executable is killed once it reaches LIMIT.",
			},
			apply: func(o *Options, v string) error {
				n, err := rubyInteger(v)
				if err != nil {
					return err
				}
				o.Limit = int(n)
				return nil
			},
		},
		{
			short: 'p', long: "pid", kind: optInt, display: "-p, --pid PID",
			desc: []string{
				fmt.Sprintf("%s the seccomp filters installed on an existing process.", titleCase(action)),
				"You must have CAP_SYS_ADMIN (e.g. be root) to use this option.",
			},
			apply: func(o *Options, v string) error {
				n, err := rubyInteger(v)
				if err != nil {
					return err
				}
				o.PID, o.HasPID = int(n), true
				return nil
			},
		},
		{
			short: 't', long: "timeout", kind: optFloat, display: "-t, --timeout SEC",
			desc: []string{
				"Timeout (seconds) for the execution. Default: no timeout",
				"This option is ignored when --pid is given.",
			},
			apply: func(o *Options, v string) error {
				f, err := parseFloat(v)
				if err != nil {
					return err
				}
				o.Timeout, o.HasTimeout = f, true
				return nil
			},
		},
	}
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	if s == "dump" {
		return "Dump"
	}
	if s == "audit" {
		return "Audit"
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func archOption(extra ...string) *option {
	desc := []string{
		"Specify architecture.",
		"Supported architectures are <" + strings.Join(util.SupportedArchs(), "|") + ">.",
		"Default: auto-detected from the host machine.",
		"Set it when the filter targets an architecture other than the host.",
	}
	desc = append(desc, extra...)
	return &option{
		short: 'a', long: "arch", kind: optChoice, choices: util.SupportedArchs(),
		display: "-a, --arch ARCH", desc: desc,
		apply: func(o *Options, v string) error {
			o.Arch, o.HasArch = v, true
			return nil
		},
	}
}
