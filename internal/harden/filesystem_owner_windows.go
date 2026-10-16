package harden

import "github.com/cautem/quarshell-core/policy"

type filesystemPathOwner struct{}

func newFilesystemPathOwner(policy.Document) *filesystemPathOwner {
	return &filesystemPathOwner{}
}

func (*filesystemPathOwner) resolve() error     { return nil }
func (*filesystemPathOwner) apply(string) error { return nil }

func filesystemOwnerCanReconcile() bool { return false }
