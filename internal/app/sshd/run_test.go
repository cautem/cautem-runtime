package sshd

import (
	"testing"

	"github.com/cautem/quarshell-core/defaults"
)

func TestParseArgsAllowsTrustedInitOverride(t *testing.T) {
	options, err := parseArgs([]string{"--init", "/.openshell/runtime/cautem-init", "--workdir", "/sandbox"})
	if err != nil {
		t.Fatal(err)
	}
	if options.server.InitPath != "/.openshell/runtime/cautem-init" || options.server.WorkDir != "/sandbox" || options.socket != defaults.GuestSSHSocket {
		t.Fatalf("parsed sshd options = %#v", options)
	}
}

func TestParseArgsRejectsNonCanonicalInitPath(t *testing.T) {
	for _, path := range []string{"relative/init", "/sandbox/../init", ""} {
		t.Run(path, func(t *testing.T) {
			if _, err := parseArgs([]string{"--init", path}); err == nil {
				t.Fatalf("parseArgs accepted init path %q", path)
			}
		})
	}
}
