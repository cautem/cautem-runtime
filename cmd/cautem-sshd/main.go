package main

import (
	"fmt"
	"os"

	"github.com/cautem/quarshell-runtime/internal/app/sshd"
)

func main() {
	if err := sshd.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
