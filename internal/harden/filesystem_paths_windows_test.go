package harden

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cautem/quarshell-core/policy"
)

func TestPrepareReadWritePathsCreatesMissingDirectoryOnWindows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "created", "writable")
	doc := policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{ReadWrite: []string{path}}}
	if err := prepareReadWritePaths(doc); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || !info.IsDir() {
		t.Fatalf("read_write path: info=%v err=%v", info, err)
	}
}
