package harden

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cautem/quarshell-core/policy"
)

func TestPrepareReadWritePathsRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}
	doc := policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{ReadWrite: []string{link}}}
	if err := prepareReadWritePaths(doc); err == nil {
		t.Fatal("symlink read_write path accepted")
	}
}

func TestFilesystemPathsPreservesExplicitCompatGrants(t *testing.T) {
	doc := policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{
		IncludeWorkdirSet: true,
		ReadOnly:          []string{"/opt/tools"},
		ReadWrite:         []string{"/workspace/cache"},
	}}
	reads, writes := filesystemPaths(doc, "/workspace")
	if !reflect.DeepEqual(reads, []string{"/opt/tools"}) {
		t.Fatalf("read grants = %v, want only explicit read_only paths", reads)
	}
	if !reflect.DeepEqual(writes, []string{"/workspace/cache"}) {
		t.Fatalf("write grants = %v, want only explicit read_write paths", writes)
	}
}

func TestFilesystemPathsIncludesWorkdirOnlyWhenRequested(t *testing.T) {
	doc := policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{IncludeWorkdir: true}}
	reads, writes := filesystemPaths(doc, "/workspace")
	if len(reads) != 0 || !reflect.DeepEqual(writes, []string{"/workspace"}) {
		t.Fatalf("paths = reads %v, writes %v; want no reads and writable /workspace", reads, writes)
	}
}

func TestFilesystemPathsEmptySectionUsesCompatWorkdirDefault(t *testing.T) {
	reads, writes := filesystemPaths(policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{}}, "/workspace")
	if len(reads) != 0 || !reflect.DeepEqual(writes, []string{"/workspace"}) {
		t.Fatalf("empty filesystem_policy paths: reads=%v writes=%v, want default /workspace", reads, writes)
	}
}

func TestFilesystemPathsOmittedSectionUsesCompatDefaults(t *testing.T) {
	reads, writes := filesystemPaths(policy.Document{}, "/workspace")
	if len(reads) != 0 || !reflect.DeepEqual(writes, []string{"/workspace"}) {
		t.Fatalf("omitted filesystem_policy paths: reads=%v writes=%v, want default /workspace", reads, writes)
	}
}

func TestFilesystemPathsExplicitFalseOmitsWorkdir(t *testing.T) {
	reads, writes := filesystemPaths(policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{
		IncludeWorkdirSet: true,
	}}, "/workspace")
	if len(reads) != 0 || len(writes) != 0 {
		t.Fatalf("explicit include_workdir=false paths: reads=%v writes=%v", reads, writes)
	}
}

func TestFilesystemPathsUsesActiveNonDefaultWorkdir(t *testing.T) {
	for _, doc := range []policy.Document{
		{},
		{FilesystemPolicy: &policy.FilesystemPolicy{}},
		{FilesystemPolicy: &policy.FilesystemPolicy{IncludeWorkdir: true}},
	} {
		reads, writes := filesystemPaths(doc, "/workspaces/project")
		if len(reads) != 0 || !reflect.DeepEqual(writes, []string{"/workspaces/project"}) {
			t.Fatalf("active workdir paths: reads=%v writes=%v", reads, writes)
		}
	}
}

func TestPrivateCredentialDirectoryRejectsOverlappingFilesystemGrants(t *testing.T) {
	root := t.TempDir()
	privateDir := filepath.Join(root, "control")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "credential-alias")
	if err := os.Symlink(privateDir, alias); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}
	tests := []struct {
		name  string
		grant string
	}{
		{name: "parent directory", grant: root},
		{name: "credential directory", grant: privateDir},
		{name: "nested directory", grant: filepath.Join(privateDir, "nested")},
		{name: "symlink alias", grant: alias},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{ReadOnly: []string{tt.grant}}}
			if err := rejectFilesystemGrantsOverlapping(privateDir, doc); err == nil {
				t.Fatalf("filesystem grant %q overlaps the private directory but was accepted", tt.grant)
			}
		})
	}

	workdir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := rejectFilesystemGrantsOverlapping(filepath.Dir(workdir), policy.Document{}); err == nil {
		t.Fatal("implicit workdir grant overlapping the private directory was accepted")
	}
}

func TestPrivateCredentialDirectoryForcesRequiredLandlock(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	privateDir, err := os.MkdirTemp(home, ".cautem-control-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(privateDir) })
	opts, err := requirePrivateCredentialIsolation(Options{
		Doc:                  policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{}},
		Mode:                 ModeBestEffort,
		PrivateCredentialDir: privateDir,
	})
	if err != nil {
		t.Fatalf("requirePrivateCredentialIsolation() error = %v", err)
	}
	if opts.Mode != ModeRequired {
		t.Fatalf("mode = %q, want required", opts.Mode)
	}
	if opts.Doc.FilesystemPolicy != nil {
		t.Fatalf("empty filesystem policy = %+v, want runtime baseline under required Landlock", opts.Doc.FilesystemPolicy)
	}
}

func TestPrivateCredentialDirectoryRejectsRuntimeTemporaryGrant(t *testing.T) {
	privateDir, err := os.MkdirTemp("/tmp", "cautem-private-control-")
	if err != nil {
		t.Skipf("create temporary private directory under /tmp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(privateDir) })
	if err := rejectFilesystemGrantsOverlapping(privateDir, policy.Document{}); err == nil {
		t.Fatal("runtime /tmp baseline grant overlaps the private directory but was accepted")
	}
}
