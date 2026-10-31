// Package assets embeds the templates and completion scripts so the binary is standalone.
package assets

import "embed"

// Files contains templates/ (asm sources) and completions/ (shell scripts).
//
//go:embed templates/*
//go:embed completions/*
var Files embed.FS
