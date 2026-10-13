//go:build !windows

package supervisor

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cautem/cautem-runtime/supervisorcontrol"
)

func workloadArgs(args ...string) []string { return args }

func exitCommand(code int) []string {
	return []string{"sh", "-c", fmt.Sprintf("exit %d", code)}
}

func TestRunReportsAndFinalizesNaturalMainProcessExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir, err := os.MkdirTemp(os.TempDir(), "sc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "c.sock")
	var operations []string
	var operationsMu sync.Mutex
	server, err := supervisorcontrol.Start(ctx, path, func(_ context.Context, request supervisorcontrol.Request) supervisorcontrol.Response {
		switch request.Operation {
		case supervisorcontrol.OperationBegin:
			operationsMu.Lock()
			operations = append(operations, request.Operation)
			operationsMu.Unlock()
			return supervisorcontrol.Response{InstanceID: "process-instance"}
		case supervisorcontrol.OperationReport:
			operationsMu.Lock()
			operations = append(operations, request.Operation)
			operationsMu.Unlock()
			if request.InstanceID != "process-instance" || request.ExitCode != 7 {
				return supervisorcontrol.Response{Error: "incorrect report"}
			}
		case supervisorcontrol.OperationFinalize:
			operationsMu.Lock()
			operations = append(operations, request.Operation)
			defer operationsMu.Unlock()
			if len(operations) < 3 || operations[1] != supervisorcontrol.OperationReport {
				return supervisorcontrol.Response{Error: "finalized before report"}
			}
		case supervisorcontrol.OperationProcess:
			if request.InstanceID != "process-instance" || request.Process == nil {
				return supervisorcontrol.Response{Error: "invalid process event"}
			}
			return supervisorcontrol.Response{InstanceID: "process-instance"}
		case supervisorcontrol.OperationFlush:
			return supervisorcontrol.Response{InstanceID: "process-instance"}
		default:
			return supervisorcontrol.Response{Error: "unexpected operation"}
		}
		return supervisorcontrol.Response{InstanceID: "process-instance"}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	t.Setenv("CAUTEM_SUPERVISOR_CONTROL_SOCKET", path)
	code, err := Run(workloadArgs(exitCommand(7)...))
	if err != nil || code != 7 {
		t.Fatalf("Run=(%d,%v), want (7,nil)", code, err)
	}
	want := []string{supervisorcontrol.OperationBegin, supervisorcontrol.OperationReport, supervisorcontrol.OperationFinalize}
	operationsMu.Lock()
	defer operationsMu.Unlock()
	if !slices.Equal(operations, want) {
		t.Fatalf("lifecycle operations=%v, want %v", operations, want)
	}
}

func TestRunForwardsTerminationSignal(t *testing.T) {
	done := make(chan struct {
		code int
		err  error
	}, 1)
	go func() {
		code, err := Run([]string{"sh", "-c", "trap 'exit 0' TERM; while :; do sleep 1; done"})
		done <- struct {
			code int
			err  error
		}{code, err}
	}()
	time.Sleep(100 * time.Millisecond)
	if err := terminateSupervisorProcess(); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result.err != nil || result.code != 0 {
			t.Fatalf("Run()=(%d,%v), want graceful child exit", result.code, result.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("workload did not exit after supervisor received SIGTERM")
	}
}

func TestRunKillsOrphanedWorkloadDescendants(t *testing.T) {
	enableTestSubreaper(t)
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	done := make(chan struct {
		code int
		err  error
	}, 1)
	command := fmt.Sprintf("(trap '' TERM; exec sleep 30) & echo $! > %q; trap 'exit 0' TERM; wait", pidFile)
	go func() {
		code, err := Run([]string{"sh", "-c", command})
		done <- struct {
			code int
			err  error
		}{code, err}
	}()
	var childPID int
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(pidFile); err == nil {
			childPID, _ = strconv.Atoi(string(bytes.TrimSpace(data)))
			if childPID > 0 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if childPID <= 0 {
		t.Fatal("workload child did not publish its pid")
	}
	if err := terminateSupervisorProcess(); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result.err != nil || result.code != 0 {
			t.Fatalf("Run()=(%d,%v), want graceful main process exit", result.code, result.err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("Run did not finish after terminating the workload process group")
	}
	if err := checkProcessGone(childPID); err != nil {
		t.Fatalf("orphaned workload child pid %d remains: %v", childPID, err)
	}
}

func terminateSupervisorProcess() error {
	return syscall.Kill(os.Getpid(), syscall.SIGTERM)
}

func checkProcessGone(pid int) error {
	err := syscall.Kill(pid, 0)
	if err == syscall.ESRCH {
		return nil
	}
	if err == nil {
		return syscall.EEXIST
	}
	return err
}
