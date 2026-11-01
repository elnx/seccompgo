// Package logger implements the small stdout logger the CLI uses.
package logger

import (
	"fmt"
	"strings"

	"github.com/elnx/seccompgo/internal/util"
)

// rubyLines splits s the way Ruby's String#lines does: each line keeps its newline,
// and a trailing newline does not produce an empty final element.
func rubyLines(s string) []string {
	var out []string
	for len(s) > 0 {
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			out = append(out, s)
			break
		}
		out = append(out, s[:i+1])
		s = s[i+1:]
	}
	return out
}

func log(severity, msg string) {
	prep := strings.Repeat(" ", len(severity)+3)
	lines := rubyLines(msg)
	var b strings.Builder
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			b.WriteString(line)
		} else {
			b.WriteString(prep)
			b.WriteString(line)
		}
	}
	out := "[" + util.Colorize(severity, strings.ToLower(severity)) + "] " + b.String()
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	fmt.Fprint(util.Stdout, out)
}

// Error logs at the ERROR level.
func Error(msg string) { log("ERROR", msg) }

// Warn logs at the WARN level.
func Warn(msg string) { log("WARN", msg) }
