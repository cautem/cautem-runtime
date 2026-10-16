// SPDX-FileCopyrightText: Copyright (c) 2026 cautem
// SPDX-License-Identifier: Apache-2.0

package agentconfig

import (
	"os"
	"strings"
	"testing"
)

type recordingGuest struct {
	execArgs [][]string
	copies   [][2]string
}

func (g *recordingGuest) ExecRaw(argv []string) error {
	g.execArgs = append(g.execArgs, argv)
	return nil
}

func (g *recordingGuest) CopyTo(src, dst string) error {
	g.copies = append(g.copies, [2]string{src, dst})
	return nil
}

func TestInstallPreservesImageAgentsFile(t *testing.T) {
	st, err := Stage(DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(st.Dir)
	guest := &recordingGuest{}
	if err := Install(guest, st); err != nil {
		t.Fatal(err)
	}
	if len(guest.copies) != 1 || guest.copies[0][1] != "/etc" {
		t.Fatalf("copies = %#v, want only staged supervisor tree at /etc", guest.copies)
	}
	if len(guest.execArgs) != 1 || len(guest.execArgs[0]) != 3 {
		t.Fatalf("exec calls = %#v, want one shell guard", guest.execArgs)
	}
	if guest.execArgs[0][0] != "/bin/sh" || guest.execArgs[0][1] != "-c" {
		t.Fatalf("shell command = %#v, want portable POSIX /bin/sh", guest.execArgs[0][:2])
	}
	script := guest.execArgs[0][2]
	if !strings.Contains(script, "[ ! -e /AGENTS.md ]") || !strings.Contains(script, "[ ! -L /AGENTS.md ]") {
		t.Fatalf("root guidance lacks no-overwrite guard: %s", script)
	}
}
