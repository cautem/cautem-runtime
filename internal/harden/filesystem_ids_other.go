//go:build !linux

package harden

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/cautem/quarshell-core/policy"
)

func targetFilesystemIDs(doc policy.Document) (int, int, error) {
	u, err := user.Current()
	if err != nil {
		return 0, 0, err
	}
	uid, err := resolveUserID(os.Getenv("OPENSHELL_SANDBOX_UID"), doc.ProcessUser(), u.Uid)
	if err != nil {
		return 0, 0, err
	}
	fallbackGID := u.Gid
	if os.Getenv("OPENSHELL_SANDBOX_GID") == "" && doc.ProcessGroup() == "" && doc.ProcessUser() != "" {
		entry, lookupErr := lookupProcessUser(doc.ProcessUser())
		if lookupErr != nil {
			if _, parseErr := strconv.Atoi(doc.ProcessUser()); parseErr != nil {
				return 0, 0, lookupErr
			}
		} else {
			fallbackGID = entry.Gid
		}
	}
	gid, err := resolveGroupID(os.Getenv("OPENSHELL_SANDBOX_GID"), doc.ProcessGroup(), fallbackGID)
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

func lookupProcessUser(identity string) (*user.User, error) {
	if _, err := strconv.Atoi(identity); err == nil {
		entry, err := user.LookupId(identity)
		if err != nil {
			return nil, fmt.Errorf("process user UID %q: %w", identity, err)
		}
		return entry, nil
	}
	entry, err := user.Lookup(identity)
	if err != nil {
		return nil, fmt.Errorf("process user %q: %w", identity, err)
	}
	return entry, nil
}

func resolveUserID(override, configured, fallback string) (int, error) {
	if raw := strings.TrimSpace(override); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			return 0, fmt.Errorf("invalid resolved identity %q: %w", raw, err)
		}
		return value, nil
	}
	if raw := strings.TrimSpace(configured); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil {
			return value, nil
		}
		if configured != "sandbox" {
			return 0, fmt.Errorf("process user %q is unsupported; expected sandbox or a numeric UID", configured)
		}
		entry, err := user.Lookup(configured)
		if err != nil {
			return 0, fmt.Errorf("process user %q: %w", configured, err)
		}
		return strconv.Atoi(entry.Uid)
	}
	value, err := strconv.Atoi(fallback)
	if err != nil {
		return 0, err
	}
	return value, nil
}

func resolveGroupID(override, configured, fallback string) (int, error) {
	if raw := strings.TrimSpace(override); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			return 0, fmt.Errorf("invalid resolved GID %q: %w", raw, err)
		}
		return value, nil
	}
	if raw := strings.TrimSpace(configured); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil {
			return value, nil
		}
		if configured != "sandbox" {
			return 0, fmt.Errorf("process group %q is unsupported; expected sandbox or a numeric GID", configured)
		}
		entry, err := user.LookupGroup(raw)
		if err != nil {
			return 0, fmt.Errorf("process group %q: %w", raw, err)
		}
		return strconv.Atoi(entry.Gid)
	}
	return strconv.Atoi(fallback)
}

func runningAsRoot() bool { return false }
