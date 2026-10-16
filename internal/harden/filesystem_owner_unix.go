//go:build !windows

package harden

import (
	"os"

	"github.com/cautem/quarshell-core/policy"
)

type filesystemPathOwner struct {
	doc      policy.Document
	uid, gid int
	resolved bool
}

func newFilesystemPathOwner(doc policy.Document) *filesystemPathOwner {
	return &filesystemPathOwner{doc: doc}
}

func (o *filesystemPathOwner) resolve() error {
	if o.resolved {
		return nil
	}
	uid, gid, err := targetFilesystemIDs(o.doc)
	if err != nil {
		return err
	}
	o.uid, o.gid, o.resolved = uid, gid, true
	return nil
}

func (o *filesystemPathOwner) apply(path string) error {
	return os.Chown(path, o.uid, o.gid)
}

func filesystemOwnerCanReconcile() bool { return os.Geteuid() == 0 }
