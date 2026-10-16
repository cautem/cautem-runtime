package harden

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/cautem/quarshell-core/policy"
)

// filesystemPaths translates OpenShell filesystem_policy defaults and explicit
// grants. OpenShell defaults to no system-path grants and includes /workspace.
func filesystemPaths(doc policy.Document, workdir string) (reads, writes []string) {
	if doc.FilesystemPolicy == nil {
		return nil, []string{workdir}
	}
	reads = slices.Clone(doc.FilesystemPolicy.ReadOnly)
	writes = slices.Clone(doc.FilesystemPolicy.ReadWrite)
	if doc.FilesystemPolicy.IncludeWorkdirEnabled() {
		writes = append(writes, workdir)
	}
	return reads, writes
}

// prepareReadWritePaths matches the supervisor's startup behavior: create
// missing writable directories and chown only directories created by us.
// Existing image/workspace paths retain their configured ownership.
func prepareReadWritePaths(doc policy.Document) error {
	if doc.FilesystemPolicy == nil {
		return nil
	}
	owner := newFilesystemPathOwner(doc)
	for _, p := range doc.FilesystemPolicy.ReadWrite {
		info, err := os.Lstat(p)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("read_write path %q is a symlink; refusing to change ownership", p)
			}
			continue
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("inspect read_write path %q: %w", p, err)
		}
		if err := owner.resolve(); err != nil {
			return err
		}
		if err := os.MkdirAll(p, 0o755); err != nil {
			return fmt.Errorf("create read_write path %q: %w", p, err)
		}
		if err := owner.apply(p); err != nil {
			return fmt.Errorf("set owner on new read_write path %q: %w", p, err)
		}
	}
	return nil
}

// reconcilePersistentDataOwnership repairs UID/GID drift in the dedicated
// persistent data volume. It is opt-in because chown changes host-visible
// ownership through the container's user namespace mapping. The workspace
// bind mount is deliberately excluded.
func reconcilePersistentDataOwnership(doc policy.Document) error {
	if os.Getenv("CAUTEM_RECONCILE_DATA_OWNERSHIP") != "1" {
		return nil
	}
	if !filesystemOwnerCanReconcile() {
		return fmt.Errorf("ownership reconciliation requires the privileged init process")
	}
	return reconcileDataOwnershipAt("/cautem/data", doc)
}

func reconcileDataOwnershipAt(dataPath string, doc policy.Document) error {
	info, err := os.Lstat(dataPath)
	if err != nil {
		return fmt.Errorf("inspect persistent data path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("persistent data path must be a real directory")
	}
	owner := newFilesystemPathOwner(doc)
	if err := owner.resolve(); err != nil {
		return fmt.Errorf("resolve persistent data owner: %w", err)
	}
	return filepath.WalkDir(dataPath, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		return owner.apply(path)
	})
}
