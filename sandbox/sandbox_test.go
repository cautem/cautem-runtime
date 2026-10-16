package sandbox

import (
	"context"
	"errors"
	"testing"

	"github.com/cautem/quarshell-core"
	"github.com/cautem/quarshell-driver/driver"
)

type failingStartDriver struct {
	driver.ComputeDriver
	startErr     error
	deleteErr    error
	deleted      bool
	cancelStart  context.CancelFunc
	deleteCtxErr error
}

func (d *failingStartDriver) Create(context.Context, driver.Spec) (driver.Handle, error) {
	return driver.Handle{ID: core.ID("test")}, nil
}
func (d *failingStartDriver) Start(context.Context, core.ID) error {
	if d.cancelStart != nil {
		d.cancelStart()
	}
	return d.startErr
}
func (d *failingStartDriver) Delete(ctx context.Context, _ core.ID) error {
	d.deleteCtxErr = ctx.Err()
	d.deleted = true
	return d.deleteErr
}
func TestCreateReportsRollbackFailure(t *testing.T) {
	startErr := errors.New("start failed")
	deleteErr := errors.New("delete failed")
	d := &failingStartDriver{startErr: startErr, deleteErr: deleteErr}
	m := Manager{Driver: d}
	_, err := m.Create(context.Background(), CreateOptions{Spec: driver.Spec{Name: "test"}})
	if !d.deleted || !errors.Is(err, startErr) || !errors.Is(err, deleteErr) {
		t.Fatalf("deleted=%v error=%v; want both start and rollback errors", d.deleted, err)
	}
}

func TestCreateRollsBackAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &failingStartDriver{startErr: context.Canceled, cancelStart: cancel}
	m := Manager{Driver: d}
	_, err := m.Create(ctx, CreateOptions{Spec: driver.Spec{Name: "test"}})
	if !errors.Is(err, context.Canceled) || !d.deleted || d.deleteCtxErr != nil {
		t.Fatalf("error=%v deleted=%v cleanup context=%v", err, d.deleted, d.deleteCtxErr)
	}
}
