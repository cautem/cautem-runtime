// Package wsinit is the composition root for cautem-init.
package wsinit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cautem/cautem-core/policy"
	"github.com/cautem/quarshell-runtime/internal/harden"
	"github.com/cautem/quarshell-runtime/supervisorcontrol"
)

func Run(args []string) error {
	policyPath := os.Getenv("CAUTEM_POLICY")
	mode := harden.Mode("")
	probe := false
	noDrop := false
	var cmd []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--policy":
			i++
			if i >= len(args) {
				return fmt.Errorf("cautem-init: --policy needs a value")
			}
			policyPath = args[i]
		case "--mode":
			i++
			if i >= len(args) {
				return fmt.Errorf("cautem-init: --mode needs a value")
			}
			mode = harden.Mode(args[i])
		case "--probe":
			probe = true
		case "--no-drop":
			noDrop = true
		case "--":
			cmd = args[i+1:]
			i = len(args)
		case "-h", "--help":
			fmt.Fprintf(os.Stderr, "usage: cautem-init [--probe] [--policy PATH] [--mode best_effort|required] [--no-drop] -- <cmd>...\n")
			return nil
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("cautem-init: unknown flag %q", args[i])
			}
			cmd = args[i:]
			i = len(args)
		}
	}

	if probe {
		res := harden.Probe()
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		if res.LandlockABI == 0 && res.LandlockError != "" {
			os.Exit(2)
		}
		return nil
	}

	var doc policy.Document
	if policyPath != "" {
		abs, err := filepath.Abs(policyPath)
		if err != nil {
			return err
		}
		doc, err = policy.Load(abs)
		if err != nil {
			return fmt.Errorf("cautem-init: policy: %w", err)
		}
		if err := doc.Validate(); err != nil {
			return fmt.Errorf("cautem-init: policy: %w", err)
		}
	} else {
		doc = policy.Document{Version: 1}
	}
	if mode == "" {
		mode = harden.ModeFromPolicy(doc)
	}
	privateCredentialDir := strings.TrimSpace(os.Getenv(supervisorcontrol.EnvPrivateDir))
	if strings.TrimSpace(os.Getenv(supervisorcontrol.EnvEndpoint)) != "" {
		client, err := supervisorcontrol.NewClientFromEnvironment()
		if err != nil {
			return fmt.Errorf("cautem-init: supervisor control credentials: %w", err)
		}
		if privateCredentialDir == "" {
			privateCredentialDir = client.PrivateCredentialDir()
		}
	}

	res, err := harden.Apply(context.Background(), harden.Options{
		Doc:                  doc,
		Mode:                 mode,
		Log:                  os.Stderr,
		NoDrop:               noDrop,
		PrivateCredentialDir: privateCredentialDir,
	})
	if err != nil {
		return err
	}
	_ = res

	if len(cmd) == 0 {
		return fmt.Errorf("cautem-init: missing command (use -- <cmd>...)")
	}
	bin, err := exec.LookPath(cmd[0])
	if err != nil {
		bin = cmd[0]
	}
	return syscall.Exec(bin, cmd, workloadEnvironment(os.Environ()))
}
