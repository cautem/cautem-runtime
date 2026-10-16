//go:build linux

package harden

import (
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"testing"

	"github.com/cautem/cautem-core/policy"
)

func TestTargetIDsUsesCompatDriverIdentityBeforePolicy(t *testing.T) {
	t.Setenv(sandboxUIDEnv, "1201")
	t.Setenv(sandboxGIDEnv, "1202")
	doc := policy.Document{Process: &policy.Process{RunAsUser: "2201", RunAsGroup: "2202"}}
	uid, gid, _, err := targetIDs(doc)
	if err != nil {
		t.Fatal(err)
	}
	if uid != 1201 || gid != 1202 {
		t.Fatalf("resolved identity = %d:%d, want driver identity 1201:1202", uid, gid)
	}
}

func TestTargetIDsUsesNumericPolicyIdentity(t *testing.T) {
	t.Setenv(sandboxUIDEnv, "")
	t.Setenv(sandboxGIDEnv, "")
	t.Setenv(ociImageUserEnv, "")
	doc := policy.Document{Process: &policy.Process{RunAsUser: "2201", RunAsGroup: "2202"}}
	uid, gid, _, err := targetIDs(doc)
	if err != nil {
		t.Fatal(err)
	}
	if uid != 2201 || gid != 2202 {
		t.Fatalf("resolved identity = %d:%d, want policy identity 2201:2202", uid, gid)
	}
}

func TestTargetIDsUsesOCIImageUserForOmittedPolicyFields(t *testing.T) {
	t.Setenv(sandboxUIDEnv, "")
	t.Setenv(sandboxGIDEnv, "")
	t.Setenv(ociImageUserEnv, "1234:1235")
	uid, gid, _, err := targetIDs(policy.Document{})
	if err != nil {
		t.Fatal(err)
	}
	if uid != 1234 || gid != 1235 {
		t.Fatalf("resolved identity = %d:%d, want OCI 1234:1235", uid, gid)
	}
}

func TestTargetIDsTreatsEmptyOCIImageUserAsUnset(t *testing.T) {
	t.Setenv(sandboxUIDEnv, "")
	t.Setenv(sandboxGIDEnv, "")
	t.Setenv(ociImageUserEnv, "")
	if os.Geteuid() != 0 {
		t.Skip("root fallback only applies to root supervisor")
	}
	expected, err := user.Lookup("sandbox")
	if err != nil {
		t.Skipf("sandbox account unavailable: %v", err)
	}
	wantUID, _ := strconv.Atoi(expected.Uid)
	wantGID, _ := strconv.Atoi(expected.Gid)
	uid, gid, _, err := targetIDs(policy.Document{})
	if err != nil {
		t.Fatal(err)
	}
	if uid != wantUID || gid != wantGID {
		t.Fatalf("resolved identity = %d:%d, want sandbox %d:%d", uid, gid, wantUID, wantGID)
	}
}

func TestTargetIDsPolicyFieldsOverrideOCIComponents(t *testing.T) {
	t.Setenv(sandboxUIDEnv, "")
	t.Setenv(sandboxGIDEnv, "")
	t.Setenv(ociImageUserEnv, "malformed!:1235")
	doc := policy.Document{Process: &policy.Process{RunAsUser: "2201"}}
	uid, gid, _, err := targetIDs(doc)
	if err != nil {
		t.Fatal(err)
	}
	if uid != 2201 || gid != 1235 {
		t.Fatalf("resolved identity = %d:%d, want policy UID and OCI GID", uid, gid)
	}
}

func TestTargetIDsRejectsInvalidDriverIdentityRange(t *testing.T) {
	for _, ids := range [][2]string{{"4294967295", "1"}, {"1", "0"}} {
		t.Run(ids[0]+"_"+ids[1], func(t *testing.T) {
			t.Setenv(sandboxUIDEnv, ids[0])
			t.Setenv(sandboxGIDEnv, ids[1])
			t.Setenv(ociImageUserEnv, "")
			if _, _, _, err := targetIDs(policy.Document{}); err == nil {
				t.Fatal("out-of-range driver identity unexpectedly accepted")
			}
		})
	}
}

func TestTargetIDsResolvesSandboxPolicyUser(t *testing.T) {
	t.Setenv(sandboxUIDEnv, "")
	t.Setenv(sandboxGIDEnv, "")
	expected, err := user.Lookup("sandbox")
	if err != nil {
		t.Skipf("sandbox account unavailable: %v", err)
	}
	wantUID, _ := strconv.Atoi(expected.Uid)
	wantGID, _ := strconv.Atoi(expected.Gid)
	uid, gid, _, err := targetIDs(policy.Document{Process: &policy.Process{RunAsUser: "sandbox"}})
	if err != nil {
		t.Fatal(err)
	}
	if uid != wantUID || gid != wantGID {
		t.Fatalf("resolved identity = %d:%d, want sandbox %d:%d", uid, gid, wantUID, wantGID)
	}
}

func TestTargetIDsDefaultsRootToSandbox(t *testing.T) {
	t.Setenv(sandboxUIDEnv, "")
	t.Setenv(sandboxGIDEnv, "")
	if os.Geteuid() != 0 {
		t.Skip("root fallback only applies to root supervisor")
	}
	sandbox, err := user.Lookup("sandbox")
	if err != nil {
		t.Skipf("sandbox account unavailable: %v", err)
	}
	wantUID, _ := strconv.Atoi(sandbox.Uid)
	wantGID, _ := strconv.Atoi(sandbox.Gid)
	uid, gid, _, err := targetIDs(policy.Document{})
	if err != nil {
		t.Fatal(err)
	}
	if uid != wantUID || gid != wantGID {
		t.Fatalf("root fallback = %d:%d, want sandbox %d:%d", uid, gid, wantUID, wantGID)
	}
}

func TestDropPrivilegesUsesPolicyIdentity(t *testing.T) {
	const childEnv = "CAUTEM_IDENTITY_TEST_CHILD"
	t.Setenv(sandboxUIDEnv, "")
	t.Setenv(sandboxGIDEnv, "")
	if os.Getenv(childEnv) == "1" {
		doc := policy.Document{Process: &policy.Process{RunAsUser: "65534", RunAsGroup: "65534"}}
		if err := dropPrivileges(doc); err != nil {
			t.Fatal(err)
		}
		if os.Geteuid() != 65534 || os.Getegid() != 65534 {
			t.Fatalf("effective identity = %d:%d, want 65534:65534", os.Geteuid(), os.Getegid())
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("identity drop test needs a root test container")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestDropPrivilegesUsesPolicyIdentity$")
	cmd.Env = append(os.Environ(), childEnv+"=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("identity drop child failed: %v\n%s", err, output)
	}
}

func TestDropPrivilegesAcceptsAlreadySelectedNonRootIdentity(t *testing.T) {
	const childEnv = "CAUTEM_NONROOT_IDENTITY_TEST_CHILD"
	if os.Getenv(childEnv) == "1" {
		uid, gid := os.Getuid(), os.Getgid()
		doc := policy.Document{Process: &policy.Process{
			RunAsUser:  strconv.Itoa(uid),
			RunAsGroup: strconv.Itoa(gid),
		}}
		if err := dropPrivileges(doc); err != nil {
			t.Fatal(err)
		}
		if os.Geteuid() != uid || os.Getegid() != gid {
			t.Fatalf("effective identity = %d:%d, want existing non-root identity %d:%d", os.Geteuid(), os.Getegid(), uid, gid)
		}
		return
	}
	if os.Geteuid() == 0 {
		t.Skip("non-root identity test must run outside a root test container")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestDropPrivilegesAcceptsAlreadySelectedNonRootIdentity$")
	cmd.Env = append(os.Environ(), childEnv+"=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("non-root identity child failed: %v\n%s", err, output)
	}
}
