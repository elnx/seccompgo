package main

import (
	"os"

	"seccompgo/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
