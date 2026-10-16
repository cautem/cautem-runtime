//go:build !windows

package harden

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/cautem/quarshell-core/policy"
)

func TestPrepareReadWritePathsCreatesAndOwnsMissingDirectory(t *testing.T) {
	setWritableTestIdentity(t)
	path := filepath.Join(t.TempDir(), "created", "writable")
	doc := policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{ReadWrite: []string{path}}}
	if err := prepareReadWritePaths(doc); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatalf("read_write path type = %s, want directory", info.Mode())
	}
}

func TestPrepareReadWritePathsPreservesExistingDirectory(t *testing.T) {
	setWritableTestIdentity(t)
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.Mkdir(path, 0o711); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	doc := policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{ReadWrite: []string{path}}}
	if err := prepareReadWritePaths(doc); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || before.Mode().Perm() != after.Mode().Perm() {
		t.Fatalf("existing directory changed: before=%v after=%v", before, after)
	}
}

func TestReconcileDataOwnershipWalksDedicatedDataTree(t *testing.T) {
	setWritableTestIdentity(t)
	root := t.TempDir()
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(nested, "state.db")
	if err := os.WriteFile(file, []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reconcileDataOwnershipAt(root, policy.Document{}); err != nil {
		t.Fatalf("reconcile dedicated data tree: %v", err)
	}
	uid, gid, err := targetFilesystemIDs(policy.Document{})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, nested, file} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatalf("stat type for %s = %T", path, info.Sys())
		}
		if int(stat.Uid) != uid || int(stat.Gid) != gid {
			t.Errorf("owner for %s = %d:%d, want %d:%d", path, stat.Uid, stat.Gid, uid, gid)
		}
	}
}

func TestReconcileDataOwnershipRejectsSymlinkRoot(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "data")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := reconcileDataOwnershipAt(link, policy.Document{}); err == nil {
		t.Fatal("reconciliation accepted a symlink root")
	}
}

func TestReconcilePersistentDataOwnershipIsOptIn(t *testing.T) {
	t.Setenv("CAUTEM_RECONCILE_DATA_OWNERSHIP", "0")
	if err := reconcilePersistentDataOwnership(policy.Document{}); err != nil {
		t.Fatalf("disabled reconciliation returned error: %v", err)
	}
}

func setWritableTestIdentity(t *testing.T) {
	t.Helper()
	uid, gid := os.Getuid(), os.Getgid()
	if uid == 0 {
		uid, gid = 65534, 65534
	}
	t.Setenv("OPENSHELL_SANDBOX_UID", strconv.Itoa(uid))
	t.Setenv("OPENSHELL_SANDBOX_GID", strconv.Itoa(gid))
}
