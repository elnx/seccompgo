// Package util holds process, terminal and presentation helpers shared by the library.
package util

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"seccompgo/internal/assets"
)

// SupportedArchs returns the architectures with a syscall table, sorted.
func SupportedArchs() []string {
	return []string{"aarch64", "amd64", "i386", "riscv64", "s390x"}
}

// SystemArch detects the host architecture, returning "unknown" when unsupported.
// It is a variable so tests can simulate an unrecognized host.
var SystemArch = func() string {
	switch runtime.GOARCH {
	case "amd64":
		return "amd64"
	case "386":
		return "i386"
	case "arm64":
		return "aarch64"
	case "riscv64":
		return "riscv64"
	case "s390x":
		return "s390x"
	default:
		return "unknown"
	}
}

// ELFMachine maps the two e_machine bytes of an ELF header to an architecture.
var ELFMachine = map[string]string{
	"\x03\x00": "i386",
	"\x3e\x00": "amd64",
	"\xb7\x00": "aarch64",
	"\xf3\x00": "riscv64",
	"\x00\x16": "s390x",
}

// ProcessArch reads the architecture of a running process from its executable's ELF
// header. It returns "" when the header cannot be read or is not a known machine.
func ProcessArch(pid int) string {
	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	defer f.Close()
	if _, err := f.Seek(18, 0); err != nil {
		return ""
	}
	buf := make([]byte, 2)
	if _, err := f.Read(buf); err != nil {
		return ""
	}
	return ELFMachine[string(buf)]
}

// Stdout is the destination of command output and logs.
var Stdout io.Writer = os.Stdout

// Stdin is the source read by commands given "-".
var Stdin io.Reader = os.Stdin

var disableColor bool

// EnableColor re-enables color output (still gated on a tty).
func EnableColor() { disableColor = false }

// DisableColor makes Colorize a no-op regardless of the output being a tty.
func DisableColor() { disableColor = true }

// ColorizeEnabled reports whether colors will be emitted.
func ColorizeEnabled() bool {
	return !disableColor && isatty(os.Stdout.Fd())
}

func isatty(fd uintptr) bool {
	var termios syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS,
		uintptr(unsafe.Pointer(&termios)))
	return errno == 0
}

// Color codes for pretty printing.
const (
	LightYellow = "\x1b[38;5;230m"

	ColorReset   = "\x1b[0m"
	ColorSyscall = "\x1b[38;5;120m"
	ColorArch    = LightYellow
	ColorArgs    = LightYellow
	ColorGray    = "\x1b[2m"
	ColorError   = "\x1b[38;5;196m"
	ColorWarn    = LightYellow
	ColorInfo    = "\x1b[38;5;110m"
)

// ColorCode maps a theme name to its escape code.
var ColorCode = map[string]string{
	"syscall": ColorSyscall,
	"arch":    ColorArch,
	"args":    ColorArgs,
	"gray":    ColorGray,
	"error":   ColorError,
	"warn":    ColorWarn,
	"info":    ColorInfo,
}

// Colorize wraps s in the requested color. It is a no-op when colors are disabled.
func Colorize(s, theme string) string {
	if !ColorizeEnabled() {
		return s
	}
	color := ColorCode[theme]
	// Re-apply the color after a nested reset, as upstream does.
	s = strings.Replace(s, ColorReset, ColorReset+color, 1)
	return color + s + ColorReset
}

// Elf reports whether path starts with the ELF magic bytes.
func Elf(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 4)
	if _, err := f.Read(buf); err != nil {
		return false
	}
	return string(buf) == "\x7fELF"
}

// Template returns one of the embedded asm templates.
func Template(name string) (string, error) {
	b, err := fs.ReadFile(assets.Files, "templates/"+name)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Completion returns one of the embedded shell completion scripts.
func Completion(name string) (string, error) {
	b, err := fs.ReadFile(assets.Files, "completions/"+name)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
