package main

import (
	"fmt"
	"os"

	"github.com/cautem/quarshell-runtime/internal/app/supervisor"
)

func main() {
	argv, err := supervisor.ParseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	code, err := supervisor.Run(argv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(code)
}
