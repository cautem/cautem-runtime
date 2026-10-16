package main

import (
	"fmt"
	"os"

	"github.com/cautem/quarshell-runtime/internal/app/agent"
)

func main() {
	if err := agent.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
