// Package sandbox orchestrates create → proxy/harden → run → destroy.
package sandbox

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/cautem/quarshell-core"
	"github.com/cautem/quarshell-core/policy"
	"github.com/cautem/quarshell-driver/driver"
)

const rollbackTimeout = 30 * time.Second

// policyApplier is the policy operation required by the lifecycle manager.
type policyApplier interface {
	Apply(context.Context, policy.Document) error
}

// Manager owns sandbox lifecycle for one host.
type Manager struct {
	Driver driver.ComputeDriver
	Proxy  policyApplier
}

// CreateOptions are host-side inputs for a new sandbox.
type CreateOptions struct {
	Spec   driver.Spec
	Policy policy.Document // optional; validated if Version != 0
}

// Create validates policy (if set), applies proxy policy, creates and starts the sandbox.
func (m *Manager) Create(ctx context.Context, opt CreateOptions) (driver.Handle, error) {
	if m.Driver == nil {
		return driver.Handle{}, fmt.Errorf("sandbox: driver not configured")
	}
	if opt.Policy.Version != 0 {
		if err := opt.Policy.Validate(); err != nil {
			return driver.Handle{}, err
		}
		if m.Proxy != nil {
			if err := m.Proxy.Apply(ctx, opt.Policy); err != nil {
				return driver.Handle{}, err
			}
		}
	}
	if opt.Spec.Name == "" {
		opt.Spec.Name = filepath.Base(opt.Spec.Workspace)
		if opt.Spec.Name == "." || opt.Spec.Name == "/" || opt.Spec.Name == "" {
			opt.Spec.Name = "default"
		}
	}
	h, err := m.Driver.Create(ctx, opt.Spec)
	if err != nil {
		return driver.Handle{}, err
	}
	if err := m.Driver.Start(ctx, h.ID); err != nil {
		// Rollback must still run when starting the sandbox cancels the request.
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
		defer cancel()
		cleanupErr := m.Driver.Delete(cleanupCtx, h.ID)
		if cleanupErr != nil {
			return driver.Handle{}, errors.Join(err, fmt.Errorf("sandbox: rollback create: %w", cleanupErr))
		}
		return driver.Handle{}, err
	}
	return h, nil
}

// Remove stops and deletes a sandbox by name or id.
func (m *Manager) Remove(ctx context.Context, nameOrID string) error {
	if m.Driver == nil {
		return fmt.Errorf("sandbox: %w", core.ErrNotImplemented)
	}
	info, err := m.Driver.Inspect(ctx, nameOrID)
	if err != nil {
		return err
	}
	// Delete remains authoritative: Stop can fail for an already stopped sandbox.
	_ = m.Driver.Stop(ctx, info.ID)
	return m.Driver.Delete(ctx, info.ID)
}

// List returns known sandboxes.
func (m *Manager) List(ctx context.Context) ([]driver.Info, error) {
	if m.Driver == nil {
		return nil, fmt.Errorf("sandbox: driver not configured")
	}
	return m.Driver.List(ctx)
}

// Exec runs a command inside a named sandbox.
func (m *Manager) Exec(ctx context.Context, nameOrID string, req driver.ExecRequest) (driver.ExecResult, error) {
	if m.Driver == nil {
		return driver.ExecResult{}, fmt.Errorf("sandbox: driver not configured")
	}
	info, err := m.Driver.Inspect(ctx, nameOrID)
	if err != nil {
		return driver.ExecResult{}, err
	}
	return m.Driver.Exec(ctx, info.ID, req)
}
