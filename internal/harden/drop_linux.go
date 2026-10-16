//go:build linux

package harden

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"github.com/cautem/quarshell-core/policy"
	"golang.org/x/sys/unix"
)

const (
	sandboxUIDEnv      = "OPENSHELL_SANDBOX_UID"
	sandboxGIDEnv      = "OPENSHELL_SANDBOX_GID"
	ociImageUserEnv    = "OPENSHELL_OCI_IMAGE_USER"
	maxProcessIdentity = uint64(4294967294)
)

func dropPrivileges(doc policy.Document) error {
	uid, gid, groups, err := targetIDs(doc)
	if err != nil {
		return err
	}
	if uid == 0 {
		return fmt.Errorf("process identity resolves to root; refusing to run sandbox as root")
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", err)
	}
	if os.Geteuid() == 0 {
		if err := syscall.Setgroups(groups); err != nil {
			return fmt.Errorf("set supplementary groups: %w", err)
		}
		if err := syscall.Setgid(gid); err != nil {
			return fmt.Errorf("setgid %d: %w", gid, err)
		}
		if err := syscall.Setuid(uid); err != nil {
			return fmt.Errorf("setuid %d: %w", uid, err)
		}
	} else if os.Geteuid() != uid || os.Getegid() != gid {
		return fmt.Errorf("cannot switch process identity from %d:%d to %d:%d without root", os.Geteuid(), os.Getegid(), uid, gid)
	}
	if os.Geteuid() != uid || os.Getegid() != gid {
		return fmt.Errorf("privilege drop verification failed: got %d:%d, want %d:%d", os.Geteuid(), os.Getegid(), uid, gid)
	}
	return nil
}

// targetIDs resolves the same inputs used by process launch and filesystem
// preflight: driver-resolved OpenShell IDs take precedence over policy names.
func targetIDs(doc policy.Document) (uid, gid int, groups []int, err error) {
	userSpec := strings.TrimSpace(doc.ProcessUser())
	groupSpec := strings.TrimSpace(doc.ProcessGroup())
	uidRaw := strings.TrimSpace(os.Getenv(sandboxUIDEnv))
	gidRaw := strings.TrimSpace(os.Getenv(sandboxGIDEnv))
	var resolvedUser *user.User
	ociUserForGroups := ""
	needOCIUser := userSpec == "" && uidRaw == ""
	needOCIGroup := groupSpec == "" && gidRaw == ""
	if ociRaw, hasOCIIdentity := os.LookupEnv(ociImageUserEnv); hasOCIIdentity && ociRaw != "" && (needOCIUser || needOCIGroup) {
		ociUID, ociGID, err := resolveOCIImageUser(ociRaw, needOCIUser, needOCIGroup)
		if err != nil {
			return 0, 0, nil, err
		}
		if needOCIUser {
			userSpec = strconv.Itoa(ociUID)
			ociUserForGroups, _, _ = strings.Cut(ociRaw, ":")
		}
		if needOCIGroup {
			groupSpec = strconv.Itoa(ociGID)
		}
	}

	if userSpec == "" && groupSpec == "" && uidRaw == "" && gidRaw == "" && os.Geteuid() == 0 {
		userSpec, groupSpec = "sandbox", "sandbox"
	}
	if userSpec != "" {
		if _, parseErr := strconv.Atoi(userSpec); parseErr != nil && userSpec != "sandbox" {
			return 0, 0, nil, fmt.Errorf("process user %q is unsupported; expected sandbox or a numeric UID", userSpec)
		}
	}
	if groupSpec != "" {
		if _, parseErr := strconv.Atoi(groupSpec); parseErr != nil && groupSpec != "sandbox" {
			return 0, 0, nil, fmt.Errorf("process group %q is unsupported; expected sandbox or a numeric GID", groupSpec)
		}
	}

	if uidRaw != "" {
		uid, err = strconv.Atoi(uidRaw)
		if err != nil {
			return 0, 0, nil, fmt.Errorf("%s: invalid numeric UID %q", sandboxUIDEnv, uidRaw)
		}
	} else if userSpec == "" {
		uid = os.Geteuid()
	} else if n, parseErr := strconv.Atoi(userSpec); parseErr == nil {
		uid = n
	} else {
		resolvedUser, err = user.Lookup(userSpec)
		if err != nil {
			return 0, 0, nil, fmt.Errorf("process user %q: %w", userSpec, err)
		}
		uid, err = strconv.Atoi(resolvedUser.Uid)
		if err != nil {
			return 0, 0, nil, fmt.Errorf("process user %q has invalid UID: %w", userSpec, err)
		}
	}

	if gidRaw != "" {
		gid, err = strconv.Atoi(gidRaw)
		if err != nil {
			return 0, 0, nil, fmt.Errorf("%s: invalid numeric GID %q", sandboxGIDEnv, gidRaw)
		}
	} else if groupSpec != "" {
		if n, parseErr := strconv.Atoi(groupSpec); parseErr == nil {
			gid = n
		} else {
			resolvedGroup, lookupErr := user.LookupGroup(groupSpec)
			if lookupErr != nil {
				return 0, 0, nil, fmt.Errorf("process group %q: %w", groupSpec, lookupErr)
			}
			gid, err = strconv.Atoi(resolvedGroup.Gid)
			if err != nil {
				return 0, 0, nil, fmt.Errorf("process group %q has invalid GID: %w", groupSpec, err)
			}
		}
	} else if resolvedUser != nil {
		gid, err = strconv.Atoi(resolvedUser.Gid)
		if err != nil {
			return 0, 0, nil, fmt.Errorf("process user %q has invalid primary GID: %w", userSpec, err)
		}
	} else if userSpec != "" || uid != os.Geteuid() {
		lookup, lookupErr := user.LookupId(strconv.Itoa(uid))
		if lookupErr == nil {
			gid, err = strconv.Atoi(lookup.Gid)
			if err != nil {
				return 0, 0, nil, fmt.Errorf("process UID %d has invalid primary GID: %w", uid, err)
			}
		} else {
			gid = os.Getegid()
		}
	} else {
		gid = os.Getegid()
	}
	if uid < 1 || uint64(uid) > maxProcessIdentity {
		return 0, 0, nil, fmt.Errorf("process UID must be in [1, 4294967294]")
	}
	if gid < 1 || uint64(gid) > maxProcessIdentity {
		return 0, 0, nil, fmt.Errorf("process GID must be in [1, 4294967294]")
	}

	if resolvedUser != nil {
		groupIDs, groupErr := resolvedUser.GroupIds()
		if groupErr != nil {
			return 0, 0, nil, fmt.Errorf("process user %q supplementary groups: %w", userSpec, groupErr)
		}
		for _, raw := range groupIDs {
			id, parseErr := strconv.Atoi(raw)
			if parseErr != nil {
				return 0, 0, nil, fmt.Errorf("process user %q has invalid supplementary GID %q", userSpec, raw)
			}
			groups = append(groups, id)
		}
	}
	if ociUserForGroups != "" {
		groupIDs, groupErr := resolveOCISupplementaryGIDs(ociUserForGroups, gid)
		if groupErr != nil {
			return 0, 0, nil, groupErr
		}
		groups = append(groups, groupIDs...)
	}
	if gidRaw != "" || groupSpec != "" {
		groups = append(groups, gid)
	}
	return uid, gid, uniqueInts(groups), nil
}

func targetFilesystemIDs(doc policy.Document) (int, int, error) {
	uid, gid, _, err := targetIDs(doc)
	return uid, gid, err
}

func runningAsRoot() bool { return os.Geteuid() == 0 }

func uniqueInts(values []int) []int {
	seen := make(map[int]struct{}, len(values))
	out := make([]int, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
