package cli

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"seccompgo/internal/asm"
	"seccompgo/internal/audit"
	"seccompgo/internal/consts"
	"seccompgo/internal/disasm"
	"seccompgo/internal/emulator"
	"seccompgo/internal/explain"
	"seccompgo/internal/instruction"
	"seccompgo/internal/logger"
	"seccompgo/internal/util"
)

func parseFloat(s string) (float64, error) {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid value for Float(): %q", s)
	}
	return f, nil
}

func runAsm(argv []string, info commandInfo) int {
	specs := []*option{
		{
			short: 'o', long: "output", kind: optString, display: "-o, --output FILE",
			desc:  []string{"Write output to FILE instead of stdout."},
			apply: func(o *Options, v string) error { o.OFile, o.HasOFile = v, true; return nil },
		},
		{
			short: 'f', long: "format", kind: optChoice,
			choices: []string{"inspect", "raw", "c_array", "carray", "c_source", "assembly"},
			display: "-f, --format FORMAT",
			desc: []string{
				"Output format. FORMAT can only be one of <inspect|raw|c_array|c_source|assembly>.",
				"Default: inspect",
			},
			apply: func(o *Options, v string) error { o.Format = v; return nil },
		},
		archOption(),
	}
	b := newBase(info, specs, func(o *Options) { o.Format = "inspect" })
	b.archOffered = true
	b.argv = argv
	if !b.handle() {
		return b.exitCode
	}
	if len(b.argv) == 0 {
		show(b.help())
		return 0
	}
	b.opts.IFile = b.argv[0]
	raw, err := b.input()
	if err != nil {
		logger.Error(rubySysError(err, b.opts.IFile))
		return 1
	}
	compiled, err := asm.Asm(string(raw), b.opts.IFile, b.opts.Arch)
	if err != nil {
		logger.Error(err.Error())
		return 1
	}
	serial := 0
	err = b.writeOutput(&serial, func() ([]byte, error) {
		switch b.opts.Format {
		case "inspect":
			return []byte(rubyInspect(compiled) + "\n"), nil
		case "raw":
			return compiled, nil
		case "c_array", "carray":
			return []byte("unsigned char bpf[] = {" + byteList(compiled) + "};\n"), nil
		case "c_source":
			tpl, err := util.Template("asm.c")
			if err != nil {
				return nil, err
			}
			return []byte(strings.Replace(tpl, "<TO_BE_REPLACED>", byteList(compiled), 1)), nil
		case "assembly":
			tpl, err := util.Template("asm." + b.opts.Arch + ".asm")
			if err != nil {
				return nil, err
			}
			var octal strings.Builder
			for _, c := range compiled {
				fmt.Fprintf(&octal, "\\%03o", c)
			}
			return []byte(strings.Replace(tpl, "<TO_BE_REPLACED>", octal.String(), 1)), nil
		}
		return nil, nil
	})
	if err != nil {
		logger.Error(err.Error())
		return 1
	}
	return 0
}

func byteList(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = strconv.Itoa(int(c))
	}
	return strings.Join(parts, ",")
}

func rubyInspect(b []byte) string {
	var out strings.Builder
	out.WriteByte('"')
	for i, c := range b {
		switch c {
		case '"':
			out.WriteString("\\\"")
		case '\\':
			out.WriteString("\\\\")
		case 0x07:
			out.WriteString("\\a")
		case 0x08:
			out.WriteString("\\b")
		case 0x09:
			out.WriteString("\\t")
		case 0x0a:
			out.WriteString("\\n")
		case 0x0b:
			out.WriteString("\\v")
		case 0x0c:
			out.WriteString("\\f")
		case 0x0d:
			out.WriteString("\\r")
		case 0x1b:
			out.WriteString("\\e")
		case '#':
			if i+1 < len(b) && (b[i+1] == '{' || b[i+1] == '$' || b[i+1] == '@') {
				out.WriteString("\\#")
			} else {
				out.WriteByte('#')
			}
		default:
			if c >= 0x20 && c <= 0x7e {
				out.WriteByte(c)
			} else {
				fmt.Fprintf(&out, "\\x%02X", c)
			}
		}
	}
	out.WriteByte('"')
	return out.String()
}

func runDisasm(argv []string, info commandInfo) int {
	specs := []*option{
		{
			short: 'o', long: "output", kind: optString, display: "-o, --output FILE",
			desc:  []string{"Write output to FILE instead of stdout."},
			apply: func(o *Options, v string) error { o.OFile, o.HasOFile = v, true; return nil },
		},
		archOption(),
		{
			long: "bpf", kind: optNegatable, display: "    --[no-]bpf",
			desc:  []string{"Display BPF bytes (code, jt, etc.).", "Default: true"},
			apply: func(o *Options, v string) error { o.BPF = v == "true"; return nil },
		},
		{
			long: "arg-infer", kind: optNegatable, display: "    --[no-]arg-infer",
			desc: []string{
				"Display syscall arguments with parameter names when possible.",
				"Default: true",
			},
			apply: func(o *Options, v string) error { o.ArgInfer = v == "true"; return nil },
		},
		{
			long: "asm-able", kind: optFlag, display: "    --asm-able",
			desc: []string{
				`Make the output valid input for "seccomp-tools asm".`,
				`By default, "seccomp-tools disasm" outputs a human-readable format meant for analysis.`,
				`With this flag the output is simplified so it can be fed back to "seccomp-tools asm".`,
				`This flag implies "--no-bpf --no-arg-infer".`,
				"Default: false",
			},
			apply: func(o *Options, _ string) error {
				o.BPF, o.ArgInfer = false, false
				return nil
			},
		},
	}
	b := newBase(info, specs, func(o *Options) { o.BPF, o.ArgInfer = true, true })
	b.archOffered = true
	b.argv = argv
	if !b.handle() {
		return b.exitCode
	}
	if len(b.argv) == 0 {
		show(b.help())
		return 0
	}
	b.opts.IFile = b.argv[0]
	raw, err := b.input()
	if err != nil {
		logger.Error(rubySysError(err, b.opts.IFile))
		return 1
	}
	serial := 0
	err = b.writeOutput(&serial, func() ([]byte, error) {
		out, err := disasm.Disasm(raw, b.opts.Arch, b.opts.BPF, b.opts.ArgInfer)
		return []byte(out), err
	})
	if err != nil {
		logger.Error(err.Error())
		return 1
	}
	return 0
}

func runDump(argv []string, info commandInfo) int {
	specs := append(filterOptionSpecs("dump"),
		&option{
			short: 'f', long: "format", kind: optChoice,
			choices: []string{"disasm", "raw", "inspect"},
			display: "-f, --format FORMAT",
			desc: []string{
				"Output format. FORMAT can only be one of <disasm|raw|inspect>.",
				"Default: disasm",
			},
			apply: func(o *Options, v string) error { o.Format = v; return nil },
		},
		&option{
			short: 'o', long: "output", kind: optString, display: "-o, --output FILE",
			desc: []string{
				"Write output to FILE instead of stdout.",
				"If multiple seccomp syscalls have been invoked (see --limit),",
				"results are written to FILE, FILE_1, FILE_2, etc.",
				`For example, with "--output out.bpf" the output files are out.bpf, out_1.bpf, ...`,
			},
			apply: func(o *Options, v string) error { o.OFile, o.HasOFile = v, true; return nil },
		},
	)
	b := newBase(info, specs, func(o *Options) { o.Format = "disasm"; o.Limit = 1 })
	b.argv = argv
	b.acceptsRawBPF = false
	if !b.dumpingSupported() {
		return 0
	}
	if !b.handle() {
		return b.exitCode
	}
	serial := 0
	for _, f := range b.collectFilters() {
		err := b.writeOutput(&serial, func() ([]byte, error) {
			switch b.opts.Format {
			case "inspect":
				var out strings.Builder
				out.WriteByte('"')
				for _, c := range f.Raw {
					fmt.Fprintf(&out, "\\x%02X", c)
				}
				out.WriteString("\"\n")
				return []byte(out.String()), nil
			case "raw":
				return f.Raw, nil
			default:
				out, err := disasm.Disasm(f.Raw, f.Arch, true, true)
				return []byte(out), err
			}
		})
		if err != nil {
			logger.Error(err.Error())
			return 1
		}
	}
	return b.exitCode
}

func runEmu(argv []string, info commandInfo) int {
	specs := []*option{
		archOption(),
		{
			short: 'q', long: "quiet", kind: optNegatable, display: "-q, --[no-]quiet",
			desc: []string{"Run quietly, only show emulation result."},
			apply: func(o *Options, v string) error {
				if v == "true" {
					o.Verbose = 0
				}
				return nil
			},
		},
		{
			short: 'i', long: "ip", kind: optInt, display: "-i, --ip=VAL",
			desc: []string{"Set instruction pointer."},
			apply: func(o *Options, v string) error {
				n, err := rubyInteger(v)
				if err != nil {
					return err
				}
				o.IP, o.HasIP = uint64(n), true
				return nil
			},
		},
	}
	b := newBase(info, specs, func(o *Options) { o.Verbose = 1 })
	b.archOffered = true
	b.argv = argv
	if !b.handle() {
		return b.exitCode
	}
	if len(b.argv) == 0 {
		show(b.help())
		return 0
	}
	b.opts.IFile = b.argv[0]
	raw, err := b.input()
	if err != nil {
		logger.Error(rubySysError(err, b.opts.IFile))
		return 1
	}
	codes, err := disasm.ToBPF(raw, b.opts.Arch)
	if err != nil {
		logger.Error(err.Error())
		return 1
	}
	insts := make([]instruction.Inst, 0, len(codes))
	for _, code := range codes {
		inst, err := instruction.New(code)
		if err != nil {
			logger.Error(err.Error())
			return 1
		}
		insts = append(insts, inst)
	}
	args := b.argv[1:]
	var sysNr *uint64
	if len(args) > 0 {
		n, err := evaluateSysNr(b.opts.Arch, args[0])
		if err != nil {
			logger.Error(err.Error())
			return 1
		}
		sysNr = &n
		args = args[1:]
	}
	emuArgs := make([]uint64, 0, len(args))
	for _, a := range args {
		n, err := rubyInteger(a)
		if err != nil {
			logger.Error(err.Error())
			return 1
		}
		emuArgs = append(emuArgs, uint64(n))
	}
	var ip *uint64
	if b.opts.HasIP {
		v := b.opts.IP
		ip = &v
	}
	res, err := emulator.New(insts, sysNr, emuArgs, ip, b.opts.Arch).Run()
	if err != nil {
		logger.Error(err.Error())
		return 1
	}
	if b.opts.Verbose >= 1 {
		out, err := disasm.Disasm(raw, b.opts.Arch, true, true)
		if err != nil {
			logger.Error(err.Error())
			return 1
		}
		outputEmulatePath(out, res)
	}
	actionName := ""
	if res.HasRet {
		if name, ok := consts.ActionName(res.Ret); ok {
			actionName = name
		}
	}
	errno := ""
	if actionName == "ERRNO" {
		errno = fmt.Sprintf("(%d)", res.Ret&consts.RetData)
	}
	fmt.Fprintf(util.Stdout, "return %s%s at line %04d\n", actionName, errno, res.PC)
	return 0
}

func evaluateSysNr(arch, s string) (uint64, error) {
	if n, ok := consts.SyscallNum(arch, s); ok {
		return uint64(n), nil
	}
	n, err := rubyInteger(s)
	if err != nil {
		return 0, err
	}
	return uint64(n), nil
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n")
}

func outputEmulatePath(dis string, res *emulator.Result) {
	lines := splitLines(dis)
	if len(lines) < 2 {
		return
	}
	fmt.Fprintln(util.Stdout, lines[0])
	fmt.Fprintln(util.Stdout, lines[1])
	instrs := lines[2:]
	for idx, line := range instrs {
		fmt.Fprintln(util.Stdout, util.Colorize(line, "gray"))
		rem := len(instrs) - idx - 1
		if rem > 3 && idx > int(res.PC)+4 {
			msg := util.Colorize(fmt.Sprintf("... (omitting %d lines)", rem), "gray")
			fmt.Fprintln(util.Stdout, msg)
			break
		}
	}
	fmt.Fprintln(util.Stdout)
}

func runExplain(argv []string, info commandInfo) int {
	specs := append(filterOptionSpecs("explain"),
		archOption("With an executable or --pid the architecture is auto-detected instead."),
	)
	b := newBase(info, specs, func(o *Options) { o.Limit = 1 })
	b.archOffered = true
	b.argv = argv
	b.acceptsRawBPF = true
	if !b.handle() {
		return b.exitCode
	}
	filters := b.collectFilters()
	if b.exitCode != 0 {
		return b.exitCode
	}
	if len(filters) > 1 {
		logger.Warn(fmt.Sprintf("%d filters are installed; they stack, so a syscall must pass every one "+
			"(most restrictive wins). Each is explained separately below.", len(filters)))
	}
	for idx, f := range filters {
		label := f.Source
		if len(filters) > 1 {
			label = fmt.Sprintf("%s (filter #%d)", f.Source, idx)
		}
		codes, err := disasm.ToBPF(f.Raw, f.Arch)
		if err != nil {
			logger.Error(err.Error())
			return 1
		}
		insts := make([]instruction.Inst, 0, len(codes))
		for _, code := range codes {
			inst, err := instruction.New(code)
			if err != nil {
				logger.Error(err.Error())
				return 1
			}
			insts = append(insts, inst)
		}
		summary, err := explain.NewExplain(insts, f.Arch, &label).Summarize()
		if err != nil {
			logger.Error(err.Error())
			return 1
		}
		if _, err := util.Stdout.Write([]byte(summary.String())); err != nil {
			logger.Error(err.Error())
			return 1
		}
	}
	return 0
}

type auditDocument struct {
	StackedFilters int                `json:"stacked_filters"`
	Reports        []audit.ReportJSON `json:"reports"`
}

func runAudit(argv []string, info commandInfo) int {
	specs := append(filterOptionSpecs("audit"),
		archOption("With an executable or --pid the architecture is auto-detected instead."),
		&option{
			short: 'f', long: "format", kind: optChoice,
			choices: []string{"human", "json"},
			display: "-f, --format FORMAT",
			desc:    []string{"Output format, one of <human|json>.", "Default: human"},
			apply:   func(o *Options, v string) error { o.Format = v; return nil },
		},
	)
	b := newBase(info, specs, func(o *Options) { o.Format = "human"; o.Limit = 1 })
	b.archOffered = true
	b.argv = argv
	b.acceptsRawBPF = true
	if !b.handle() {
		return b.exitCode
	}
	filters := b.collectFilters()
	if b.exitCode != 0 {
		return b.exitCode
	}
	if len(filters) == 0 {
		return 0
	}
	reports := make([]*audit.Report, 0, len(filters))
	for idx, f := range filters {
		label := f.Source
		if len(filters) > 1 {
			label = fmt.Sprintf("%s (filter #%d)", f.Source, idx)
		}
		codes, err := disasm.ToBPF(f.Raw, f.Arch)
		if err != nil {
			logger.Error(err.Error())
			return 1
		}
		insts := make([]instruction.Inst, 0, len(codes))
		for _, code := range codes {
			inst, err := instruction.New(code)
			if err != nil {
				logger.Error(err.Error())
				return 1
			}
			insts = append(insts, inst)
		}
		report, err := audit.NewAudit(insts, f.Arch, &label).Run()
		if err != nil {
			logger.Error(err.Error())
			return 1
		}
		reports = append(reports, report)
	}
	if b.opts.Format == "json" {
		doc := auditDocument{StackedFilters: len(filters), Reports: make([]audit.ReportJSON, 0, len(reports))}
		for _, r := range reports {
			doc.Reports = append(doc.Reports, r.JSON())
		}
		enc := json.NewEncoder(util.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(doc); err != nil {
			logger.Error(err.Error())
			return 1
		}
		return 0
	}
	if len(filters) > 1 {
		logger.Warn(fmt.Sprintf("%d filters are installed; they stack, so a syscall must pass every one "+
			"(most restrictive wins). Each is audited separately below.", len(filters)))
	}
	for _, r := range reports {
		ioWriteString(r.String())
	}
	return 0
}

func ioWriteString(s string) {
	util.Stdout.Write([]byte(s))
}

func runCompletion(argv []string, info commandInfo) int {
	specs := []*option{}
	b := newBase(info, specs, nil)
	b.argv = argv
	if !b.handle() {
		return b.exitCode
	}
	if len(b.argv) == 0 {
		show(b.help())
		return 0
	}
	files := map[string]string{
		"bash": "seccomp-tools.bash",
		"zsh":  "_seccomp-tools",
		"fish": "seccomp-tools.fish",
	}
	name, ok := files[b.argv[0]]
	if !ok {
		show(b.help())
		return 0
	}
	script, err := util.Completion(name)
	if err != nil {
		logger.Error(err.Error())
		return 1
	}
	util.Stdout.Write([]byte(script))
	return 0
}
