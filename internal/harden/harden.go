// Package harden applies Landlock, privilege drop, and related guest restrictions.
package harden

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cautem/cautem-core/policy"
)

// Mode controls fail-closed vs loud best-effort.
type Mode string

const (
	ModeBestEffort Mode = "best_effort"
	ModeRequired   Mode = "required"
)

// Options configure one harden pass before exec.
type Options struct {
	Doc                  policy.Document
	Mode                 Mode
	Log                  io.Writer // default stderr
	NoDrop               bool      // skip uid/gid drop (debug)
	PrivateCredentialDir string    // Landlock-protect this supervisor-only directory before launching workload code
}

// Result describes what was applied (for probes / health).
type Result struct {
	LandlockABI                        int
	LandlockFilesystemRulesAvailable   bool
	LandlockDeniedAccessAuditAvailable bool
	LandlockDeniedAccessAuditEnabled   bool
	LandlockProfileMaxABI              int
	LandlockApplied                    bool
	LandlockError                      string
	DropApplied                        bool
	DropError                          string
	SeccompNote                        string
}

// SeccompNote documents the MVP seccomp / capability posture.
func SeccompNote() string {
	return "docker-default + no-new-privileges + CapDrop=NET_RAW (in-process filter later)"
}

// ModeFromPolicy maps filesystem.mode to harden Mode.
func ModeFromPolicy(doc policy.Document) Mode {
	switch doc.HardenMode() {
	case "required":
		return ModeRequired
	default:
		return ModeBestEffort
	}
}

// Apply runs Landlock + drop privileges according to opts.
func Apply(_ context.Context, opts Options) (Result, error) {
	var err error
	opts, err = requirePrivateCredentialIsolation(opts)
	if err != nil {
		return Result{}, fmt.Errorf("harden: supervisor control credentials: %w", err)
	}
	if opts.Log == nil {
		opts.Log = os.Stderr
	}
	// A policy hard_requirement is a security floor. An explicit CLI mode may
	// request stricter handling, but must never downgrade the policy to
	// best_effort.
	if opts.Mode == "" || ModeFromPolicy(opts.Doc) == ModeRequired {
		opts.Mode = ModeFromPolicy(opts.Doc)
	}
	res := Result{
		SeccompNote: SeccompNote(),
	}
	if err := reconcilePersistentDataOwnership(opts.Doc); err != nil {
		return res, fmt.Errorf("harden: reconcile persistent data ownership: %w", err)
	}
	if err := prepareReadWritePaths(opts.Doc); err != nil {
		return res, fmt.Errorf("harden: prepare filesystem policy: %w", err)
	}
	privateIsolationUsesBaseline := strings.TrimSpace(opts.PrivateCredentialDir) != "" && opts.Doc.FilesystemPolicy == nil
	noFS := noFilesystemGrants(opts.Doc) && !privateIsolationUsesBaseline
	if noFS {
		if opts.Mode == ModeRequired {
			return res, fmt.Errorf("harden: landlock.compatibility is hard_requirement but no filesystem paths are configured")
		}
	}

	// Resolve and drop identity before Landlock restricts reads from account
	// files such as /etc/passwd and /etc/group. Writable path preflight above
	// still runs while the supervisor has the privileges needed to prepare them.
	if !opts.NoDrop && shouldDrop(opts.Doc) {
		if err := dropPrivileges(opts.Doc); err != nil {
			res.DropError = err.Error()
			msg := fmt.Sprintf("cautem-init: privilege drop failed: %v", err)
			fmt.Fprintln(opts.Log, msg+" (refusing to launch with the wrong process identity)")
			return res, fmt.Errorf("harden: drop: %w", err)
		}
		res.DropApplied = true
		if os.Getenv("CAUTEM_HARDEN_VERBOSE") == "1" {
			fmt.Fprintln(opts.Log, "cautem-init: privileges dropped")
		}
	}
	if noFS {
		return res, nil
	}

	abi, err := landlockABI()
	res.LandlockABI = abi
	res.LandlockFilesystemRulesAvailable = abi >= 1
	res.LandlockDeniedAccessAuditAvailable = abi >= 7
	res.LandlockProfileMaxABI = landlockProfileMaxABI(abi)
	verbose := os.Getenv("CAUTEM_HARDEN_VERBOSE") == "1"
	if err != nil {
		res.LandlockError = err.Error()
		msg := fmt.Sprintf("cautem-init: landlock unavailable: %v", err)
		if opts.Mode == ModeRequired {
			fmt.Fprintln(opts.Log, msg+" (mode=required → fail)")
			return res, fmt.Errorf("harden: landlock required: %w", err)
		}
		fmt.Fprintln(opts.Log, msg+" (mode=best_effort → continue)")
	} else {
		if err := applyLandlockWithABI(opts.Doc, abi); err != nil {
			res.LandlockError = err.Error()
			msg := fmt.Sprintf("cautem-init: landlock apply failed: %v", err)
			if opts.Mode == ModeRequired {
				fmt.Fprintln(opts.Log, msg+" (mode=required → fail)")
				return res, fmt.Errorf("harden: landlock: %w", err)
			}
			fmt.Fprintln(opts.Log, msg+" (mode=best_effort → continue)")
		} else {
			res.LandlockApplied = true
			res.LandlockDeniedAccessAuditEnabled = abi >= 7
			if verbose {
				fmt.Fprintf(opts.Log, "cautem-init: landlock applied (kernel abi=%d, profile up to v%d, denied-access audit=%t)\n", abi, res.LandlockProfileMaxABI, res.LandlockDeniedAccessAuditEnabled)
			}
		}
	}

	return res, nil
}

func requirePrivateCredentialIsolation(opts Options) (Options, error) {
	dir := strings.TrimSpace(opts.PrivateCredentialDir)
	if dir == "" {
		return opts, nil
	}
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return opts, fmt.Errorf("private credential directory must be absolute and clean")
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return opts, fmt.Errorf("inspect private credential directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return opts, fmt.Errorf("private credential path must be a real directory")
	}
	if err := rejectFilesystemGrantsOverlapping(dir, opts.Doc); err != nil {
		return opts, err
	}
	opts.Mode = ModeRequired
	if hasOnlyImplicitWorkdirGrant(opts.Doc) {
		// Apply the default runtime baseline so Landlock can still permit normal
		// command execution while denying access to the mounted credentials.
		opts.Doc.FilesystemPolicy = nil
	}
	return opts, nil
}

func rejectFilesystemGrantsOverlapping(privateDir string, doc policy.Document) error {
	fs := doc.FilesystemPolicy
	privateDir, err := canonicalExistingPath(privateDir)
	if err != nil {
		return fmt.Errorf("resolve private credential directory: %w", err)
	}
	var grants []string
	usesRuntimeBaseline := fs == nil || hasOnlyImplicitWorkdirGrant(doc)
	if usesRuntimeBaseline {
		grants = append(grants, "/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc", "/proc", "/dev/null", "/tmp")
	}
	if fs == nil || fs.IncludeWorkdirEnabled() {
		workdir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("resolve implicit workdir grant: %w", err)
		}
		grants = append(grants, workdir)
	}
	if fs != nil {
		grants = append(grants, fs.ReadOnly...)
		grants = append(grants, fs.ReadWrite...)
	}
	if doc.Display != nil && strings.EqualFold(doc.Display.Mode, "novnc") {
		grants = append(grants, "/tmp/.X11-unix", "/usr/share", "/usr/lib", "/etc/chromium", "/usr/lib/chromium", "/usr/bin/chromium", "/tmp/cautem-display", "/home", "/run/user")
	}
	for _, grant := range grants {
		resolved, err := canonicalExistingPath(grant)
		if err != nil {
			return fmt.Errorf("resolve filesystem grant %q: %w", grant, err)
		}
		if pathsOverlap(resolved, privateDir) {
			return fmt.Errorf("filesystem grant %q overlaps private credential directory", grant)
		}
	}
	return nil
}

func hasOnlyImplicitWorkdirGrant(doc policy.Document) bool {
	fs := doc.FilesystemPolicy
	return fs != nil && len(fs.ReadOnly) == 0 && len(fs.ReadWrite) == 0 &&
		fs.IncludeWorkdirEnabled()
}

func canonicalExistingPath(path string) (string, error) {
	path = filepath.Clean(path)
	var missing []string
	for candidate := path; ; candidate = filepath.Dir(candidate) {
		resolved, err := filepath.EvalSymlinks(candidate)
		if err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return filepath.Clean(resolved), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return path, nil
		}
		missing = append(missing, filepath.Base(candidate))
	}
}

func pathsOverlap(left, right string) bool {
	return pathContains(left, right) || pathContains(right, left)
}

func pathContains(root, path string) bool {
	root, path = filepath.Clean(root), filepath.Clean(path)
	if root == string(filepath.Separator) {
		return true
	}
	return root == path || strings.HasPrefix(path, root+string(filepath.Separator))
}

func noFilesystemGrants(doc policy.Document) bool {
	fs := doc.FilesystemPolicy
	if fs == nil || fs.IncludeWorkdirEnabled() || len(fs.ReadOnly) != 0 || len(fs.ReadWrite) != 0 {
		return false
	}
	return doc.Display == nil || !strings.EqualFold(doc.Display.Mode, "novnc")
}

func shouldDrop(doc policy.Document) bool {
	return doc.ProcessUser() != "" || doc.ProcessGroup() != "" ||
		os.Getenv("OPENSHELL_SANDBOX_UID") != "" || os.Getenv("OPENSHELL_SANDBOX_GID") != "" || runningAsRoot()
}

// Probe reports Landlock ABI without applying a full policy.
func Probe() Result {
	res := Result{SeccompNote: SeccompNote()}
	abi, err := landlockABI()
	res.LandlockABI = abi
	res.LandlockFilesystemRulesAvailable = abi >= 1
	res.LandlockDeniedAccessAuditAvailable = abi >= 7
	res.LandlockProfileMaxABI = landlockProfileMaxABI(abi)
	if err != nil {
		res.LandlockError = err.Error()
	}
	return res
}

func landlockProfileMaxABI(kernelABI int) int {
	if kernelABI >= 7 {
		return 7
	}
	if kernelABI >= 5 {
		return 5
	}
	return max(kernelABI, 0)
}
