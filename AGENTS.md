# AGENTS.md

## Project

Pure-Go port of `david942j/seccomp-tools` (upstream Ruby version 1.7.1), targeting
Linux only. The CLI, output text, exit statuses, help screens and analysis results
are meant to stay byte-for-byte compatible with the upstream implementation in
`../seccomp-tools`.

Hard constraint: **no cgo**. All ptrace work uses raw `SYS_PTRACE` syscalls, and
`CGO_ENABLED=0` must keep building a static binary.

## Commands

```bash
make            # build bin/seccomp-tools
make test       # go test ./...
make vet        # go vet ./...
make fmt        # gofmt every package
make generate   # regenerate internal/consts/tables_generated.go from ../seccomp-tools
```

Run a single package or test:

```bash
go test ./internal/asm -run TestParserErrorMessagesFromGrammar -v
```

`make generate` requires the upstream Ruby sources at `../seccomp-tools` (override
with `make generate RUBY_SRC=/path/to/seccomp-tools`). The generated file is
committed; do not edit it by hand.

## Layout

- `cmd/seccomp-tools` — entry point.
- `internal/cli` — command parsing, help text, filter input, output files.
- `internal/asm` — scanner, recursive-descent parser, compiler.
- `internal/bpf`, `internal/instruction` — BPF instruction model and per-opcode logic.
- `internal/disasm` — state-propagation disassembler.
- `internal/emulator` — concrete one-path emulator.
- `internal/symbolic` — immutable expressions, constraints, states; `symbolic/executor` walks every path.
- `internal/explain` — path facts, qword fusion, renderer, policy summary.
- `internal/audit` — catalog, policies, checks, human/JSON reports.
- `internal/dumper` — pure-Go ptrace filter capture.
- `internal/assets` — embedded asm templates and shell completion scripts.
- `internal/consts` — BPF constants plus generated syscall tables.
- `testdata/data` — upstream BPF/asm fixtures and test executables.
- `testdata/golden` — expected outputs copied from upstream specs/README.
- `testdata/asm` — additional assembly fixtures used by explain/audit tests.

## Compatibility rules

- Before changing observable behavior, check the matching upstream spec under
  `../seccomp-tools/spec`; goldens in `testdata/golden` usually encode the answer.
- Preserve help text formatting (4-space indent, description column 37, tabs in the
  command list), error-message source locations, and exit codes.
- Scanner token columns/lines and parser error offsets are tested; keep them exact.
- Architecture handling is endianness-aware: s390x stores the high word of a 64-bit
  `seccomp_data` field first. Use the helpers in `internal/consts`, not ad-hoc logic.
- Syscall reverse lookups intentionally keep the last name for a duplicate number
  (Ruby `Hash#invert`), and amd64 appends `x32_*` aliases in table order.

## Implementation cautions

- Symbolic values (`Expr`, `Constraint`, `State`) are immutable; equality/identity is
  based on their string `Key`. Never mutate shared path/mem/state data.
- Ptrace callers must `runtime.LockOSThread()` before starting/attaching to the
  tracee and keep all ptrace operations on that thread.
- Raw `PTRACE_PEEKDATA` writes its result through the `data` pointer, not as the
  syscall return value.
- `PTRACE_GET_SYSCALL_INFO` supplies reliable entry/exit identification; keep the
  old-kernel alternating fallback working when touching trace logic.
- Dumper tests execute real seccomp binaries and therefore need Linux with ptrace
  allowed. `--pid` success additionally needs `CAP_SYS_ADMIN`; the regular tests
  cover its error path, and privileged integration checks should be run manually.

## Testing expectations

- Bug fixes should add a regression test that would fail before the fix; prefer
  table-driven tests next to the package.
- Golden files come from upstream outputs. Updating one requires confirming the
  upstream behavior actually changed, not merely that our output moved.
- `internal/dumper` tests are integration tests: verify exact filter bytes for the
  diary fixture, multi-filter limits, strict mode, timeout, and exec failures.
- Do not weaken ptrace/timeout tests to make a sandbox pass; report the environment
  limitation instead.

## Style

- Standard library only; no external modules unless unavoidable and discussed.
- Keep the existing Go style, `gofmt`, and package boundaries. Go 1.27 is the module
  baseline (`new(expr)` is available).
- Delete dead helpers rather than leaving compatibility shims; this is a full port,
  not a wrapper around the Ruby gem.
