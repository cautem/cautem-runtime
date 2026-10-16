//go:build linux

package harden

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cautem/quarshell-core/policy"
)

func TestLandlockDefaultRuntimeBaseline(t *testing.T) {
	const childEnv = "CAUTEM_LANDLOCK_DEFAULT_BASELINE_CHILD"
	if os.Getenv(childEnv) == "1" {
		if err := applyLandlock(policy.Document{}); err != nil {
			t.Fatal(err)
		}
		probe := filepath.Join(os.TempDir(), "cautem-landlock-default-baseline")
		defer os.Remove(probe)
		cmd := exec.Command("/bin/sh", "-c", `printf baseline > "$1" && test -r /proc/self/cmdline`, "sh", probe)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("default runtime baseline blocked image userland: %v\n%s", err, output)
		}
		return
	}
	if _, err := landlockABI(); err != nil {
		t.Skipf("Landlock unavailable in test environment: %v", err)
	}
	coverageDir := t.TempDir()
	cmd := exec.Command(os.Args[0], landlockChildArgs("TestLandlockDefaultRuntimeBaseline", coverageDir)...)
	cmd.Env = landlockChildEnv(childEnv + "=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("default runtime baseline child failed: %v\n%s", err, strings.TrimSpace(string(output)))
	}
}

func TestPrivateCredentialDirectoryLandlockEnforcement(t *testing.T) {
	const childEnv = "CAUTEM_LANDLOCK_PRIVATE_CREDENTIAL_CHILD"
	if os.Getenv(childEnv) == "1" {
		privateDir := os.Getenv("CAUTEM_LANDLOCK_PRIVATE_CREDENTIAL_DIR")
		secretPath := os.Getenv("CAUTEM_LANDLOCK_PRIVATE_CREDENTIAL_FILE")
		result, err := Apply(t.Context(), Options{
			Doc:                  policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{}},
			Mode:                 ModeRequired,
			PrivateCredentialDir: privateDir,
			NoDrop:               true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !result.LandlockApplied {
			t.Fatalf("private credential isolation result = %+v, want Landlock applied", result)
		}
		if _, err := os.ReadFile(secretPath); err == nil {
			t.Fatal("workload process read a supervisor private credential")
		}
		if output, err := exec.Command("/bin/true").CombinedOutput(); err != nil {
			t.Fatalf("runtime baseline could not execute /bin/true: %v\n%s", err, output)
		}
		return
	}
	if _, err := landlockABI(); err != nil {
		t.Skipf("Landlock unavailable in test environment: %v", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	privateDir, err := os.MkdirTemp(home, ".cautem-private-control-")
	if err != nil {
		t.Skipf("create private credential directory under home: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(privateDir) })
	secretPath := filepath.Join(privateDir, "client.key")
	if err := os.WriteFile(secretPath, []byte("test-private-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestPrivateCredentialDirectoryLandlockEnforcement$")
	cmd.Env = landlockChildEnv(
		childEnv+"=1",
		"CAUTEM_LANDLOCK_PRIVATE_CREDENTIAL_DIR="+privateDir,
		"CAUTEM_LANDLOCK_PRIVATE_CREDENTIAL_FILE="+secretPath,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("private credential Landlock child failed: %v\n%s", err, output)
	}
}

func TestLandlockExplicitPolicyEnforcement(t *testing.T) {
	const childEnv = "CAUTEM_LANDLOCK_TEST_CHILD"
	if os.Getenv(childEnv) == "1" {
		allowed := os.Getenv("CAUTEM_LANDLOCK_TEST_ALLOWED")
		coverageDir := os.Getenv("CAUTEM_LANDLOCK_TEST_COVERAGE_DIR")
		doc := policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{
			ReadOnly:          []string{filepath.Dir(allowed)},
			ReadWrite:         []string{coverageDir},
			IncludeWorkdir:    false,
			IncludeWorkdirSet: true,
		}}
		if err := applyLandlock(doc); err != nil {
			t.Fatal(err)
		}
		if _, err := os.ReadFile(allowed); err != nil {
			t.Fatalf("explicitly allowed file is not readable: %v", err)
		}
		if _, err := os.ReadFile("/etc/passwd"); err == nil {
			t.Fatal("unlisted /etc/passwd remained readable under explicit filesystem policy")
		}
		return
	}
	if _, err := landlockABI(); err != nil {
		t.Skipf("Landlock unavailable in test environment: %v", err)
	}
	allowed := filepath.Join(t.TempDir(), "allowed.txt")
	if err := os.WriteFile(allowed, []byte("allowed"), 0o600); err != nil {
		t.Fatal(err)
	}
	coverageDir := filepath.Join(t.TempDir(), "coverage")
	if err := os.Mkdir(coverageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], landlockChildArgs("TestLandlockExplicitPolicyEnforcement", coverageDir)...)
	cmd.Env = landlockChildEnv(childEnv+"=1", "CAUTEM_LANDLOCK_TEST_ALLOWED="+allowed, "CAUTEM_LANDLOCK_TEST_COVERAGE_DIR="+coverageDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Landlock child failed: %v\n%s", err, output)
	}
}

func TestLandlockFilesystemWriteGrantsEnforcement(t *testing.T) {
	const childEnv = "CAUTEM_LANDLOCK_WRITE_TEST_CHILD"
	if os.Getenv(childEnv) == "1" {
		mode := os.Getenv("CAUTEM_LANDLOCK_WRITE_TEST_MODE")
		root := os.Getenv("CAUTEM_LANDLOCK_WRITE_TEST_ROOT")
		workdir := filepath.Join(root, "work")
		outside := filepath.Join(root, "outside")
		var doc policy.Document
		switch mode {
		case "active-workdir":
			if err := os.Chdir(workdir); err != nil {
				t.Fatal(err)
			}
			doc.FilesystemPolicy = &policy.FilesystemPolicy{}
		case "explicit-read-write":
			doc.FilesystemPolicy = &policy.FilesystemPolicy{
				IncludeWorkdir:    false,
				IncludeWorkdirSet: true,
				ReadWrite:         []string{workdir},
			}
		default:
			t.Fatalf("unknown write test mode %q", mode)
		}
		if err := applyLandlock(doc); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(workdir, "allowed.txt"), []byte("allowed"), 0o600); err != nil {
			t.Fatalf("write inside granted path: %v", err)
		}
		if err := os.WriteFile(filepath.Join(outside, "denied.txt"), []byte("denied"), 0o600); err == nil {
			t.Fatal("write outside filesystem grants unexpectedly succeeded")
		}
		return
	}
	if _, err := landlockABI(); err != nil {
		t.Skipf("Landlock unavailable in test environment: %v", err)
	}
	for _, mode := range []string{"active-workdir", "explicit-read-write"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			for _, dir := range []string{"work", "outside"} {
				if err := os.Mkdir(filepath.Join(root, dir), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			coverageDir := filepath.Join(root, "work")
			cmd := exec.Command(os.Args[0], landlockChildArgs("TestLandlockFilesystemWriteGrantsEnforcement", coverageDir)...)
			cmd.Env = landlockChildEnv(childEnv+"=1", "CAUTEM_LANDLOCK_WRITE_TEST_MODE="+mode, "CAUTEM_LANDLOCK_WRITE_TEST_ROOT="+root)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("Landlock %s child failed: %v\n%s", mode, err, output)
			}
		})
	}
}

func landlockChildEnv(values ...string) []string {
	keys := make(map[string]struct{}, len(values)+1)
	keys["GOCOVERDIR"] = struct{}{}
	for _, value := range values {
		key, _, _ := strings.Cut(value, "=")
		keys[key] = struct{}{}
	}
	env := make([]string, 0, len(os.Environ())+len(values))
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		if _, replace := keys[key]; !replace {
			env = append(env, value)
		}
	}
	return append(env, values...)
}

func landlockChildArgs(testName, coverageDir string) []string {
	args := []string{"-test.run=^" + testName + "$"}
	if testing.CoverMode() != "" {
		args = append(args, "-test.gocoverdir="+coverageDir)
	}
	return args
}

func TestLandlockCompatDefaultGrantsOnlyWorkdir(t *testing.T) {
	reads, writes := filesystemPaths(policy.Document{}, "/workspace")
	if len(reads) != 0 || len(writes) != 1 || writes[0] != "/workspace" {
		t.Fatalf("default Landlock paths = reads %v, writes %v; want only /workspace", reads, writes)
	}
}

func TestLandlockCompatibilityModesWithNoFilesystemGrants(t *testing.T) {
	doc := policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{
		IncludeWorkdir:    false,
		IncludeWorkdirSet: true,
	}}
	if err := applyLandlock(doc); err != nil {
		t.Fatalf("best_effort with no configured paths: %v", err)
	}
	doc.Landlock = &policy.Landlock{Compatibility: "hard_requirement"}
	if err := applyLandlock(doc); err == nil {
		t.Fatal("hard_requirement with no configured paths unexpectedly succeeded")
	}
}
