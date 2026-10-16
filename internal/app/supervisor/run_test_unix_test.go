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
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cautem/quarshell-runtime/supervisorcontrol"
)

func workloadArgs(args ...string) []string { return args }

func exitCommand(code int) []string {
	return []string{"sh", "-c", fmt.Sprintf("exit %d", code)}
}

func TestRunPublishesReadinessAfterStartingWorkloadAndDoesNotLeakMarkerPath(t *testing.T) {
	readyPath := filepath.Join(t.TempDir(), "supervisor.ready")
	childOutput := filepath.Join(t.TempDir(), "child-env")
	attemptsPath := filepath.Join(t.TempDir(), "attempts")
	t.Setenv(envSupervisorReadyFile, readyPath)
	t.Setenv("CAUTEM_MAIN_PROCESS_RESTART_POLICY", "on-failure")
	command := `printf '%s' "${CAUTEM_VM_SUPERVISOR_READY_FILE-unset}" > "$1"; n=0; test ! -f "$2" || n=$(cat "$2"); n=$((n + 1)); printf '%s' "$n" > "$2"; test "$n" -ge 2`
	code, err := Run([]string{"sh", "-c", command, "sh", childOutput, attemptsPath})
	if err != nil || code != 0 {
		t.Fatalf("Run()=(%d,%v), want success after retry", code, err)
	}
	ready, err := os.ReadFile(readyPath)
	if err != nil || string(ready) != supervisorReadyContents {
		t.Fatalf("readiness marker=%q err=%v", ready, err)
	}
	info, err := os.Stat(readyPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("readiness marker mode=(%v,%v), want 0600", info, err)
	}
	childValue, err := os.ReadFile(childOutput)
	if err != nil || string(childValue) != "unset" {
		t.Fatalf("workload readiness path=%q err=%v, want unset", childValue, err)
	}
	if attempts, err := os.ReadFile(attemptsPath); err != nil || string(attempts) != "2" {
		t.Fatalf("workload attempts=%q err=%v, want 2", attempts, err)
	}
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

func TestRunRestartsMainProcessOnFailureUntilItExitsSuccessfully(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "attempts")
	controlDir, err := os.MkdirTemp(os.TempDir(), "sc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(controlDir) })
	controlPath := filepath.Join(controlDir, "control.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var attempts, reports, finalizes atomic.Int32
	server, err := supervisorcontrol.Start(ctx, controlPath, func(_ context.Context, request supervisorcontrol.Request) supervisorcontrol.Response {
		switch request.Operation {
		case supervisorcontrol.OperationBegin:
			attempt := attempts.Add(1)
			return supervisorcontrol.Response{InstanceID: fmt.Sprintf("process-%d", attempt)}
		case supervisorcontrol.OperationProcess, supervisorcontrol.OperationFlush:
			return supervisorcontrol.Response{InstanceID: request.InstanceID}
		case supervisorcontrol.OperationReport:
			if request.InstanceID != "process-3" || request.ExitCode != 0 {
				return supervisorcontrol.Response{Error: "nonterminal process exit was reported"}
			}
			reports.Add(1)
		case supervisorcontrol.OperationFinalize:
			finalizes.Add(1)
		default:
			return supervisorcontrol.Response{Error: "unexpected supervisor operation"}
		}
		return supervisorcontrol.Response{InstanceID: request.InstanceID}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	t.Setenv("CAUTEM_SUPERVISOR_CONTROL_SOCKET", controlPath)
	t.Setenv("CAUTEM_MAIN_PROCESS_RESTART_POLICY", "on-failure")
	command := fmt.Sprintf(`n=0; test ! -f %q || n=$(cat %q); n=$((n + 1)); printf '%%s' "$n" > %q; test "$n" -ge 3`, marker, marker, marker)
	code, err := Run([]string{"sh", "-c", command})
	if err != nil || code != 0 {
		t.Fatalf("Run()=(%d,%v), want success after restart", code, err)
	}
	if got, readErr := os.ReadFile(marker); readErr != nil || string(got) != "3" {
		t.Fatalf("main process attempts=%q err=%v, want 3", got, readErr)
	}
	if attempts.Load() != 3 || reports.Load() != 1 || finalizes.Load() != 1 {
		t.Fatalf("lifecycle attempts/reports/finalizes=%d/%d/%d, want 3/1/1", attempts.Load(), reports.Load(), finalizes.Load())
	}
}

func TestRunRestartPolicyValidationAndFailureSemantics(t *testing.T) {
	for raw, want := range map[string]mainProcessRestartPolicy{
		"":           mainProcessRestartNever,
		"never":      mainProcessRestartNever,
		"on-failure": mainProcessRestartOnFailure,
		"always":     mainProcessRestartAlways,
	} {
		got, err := parseRestartPolicy(raw)
		if err != nil || got != want {
			t.Errorf("parseRestartPolicy(%q)=(%v,%v), want %v", raw, got, err, want)
		}
	}
	if _, err := parseRestartPolicy("sometimes"); err == nil {
		t.Fatal("unknown restart policy accepted")
	}
	if shouldRestartMainProcess(mainProcessRestartOnFailure, 0, nil, false) || !shouldRestartMainProcess(mainProcessRestartOnFailure, 1, nil, false) {
		t.Fatal("on-failure policy did not follow exit status")
	}
	if shouldRestartMainProcess(mainProcessRestartAlways, 0, nil, false) == false || shouldRestartMainProcess(mainProcessRestartAlways, 1, nil, true) {
		t.Fatal("always policy did not respect shutdown")
	}
	for restart, want := range map[int]time.Duration{0: 100 * time.Millisecond, 1: 200 * time.Millisecond, 2: 400 * time.Millisecond, 3: 800 * time.Millisecond, 6: 5 * time.Second, 20: 5 * time.Second} {
		if got := restartBackoff(restart); got != want {
			t.Errorf("restartBackoff(%d)=%s, want %s", restart, got, want)
		}
	}
}

func TestRunForwardsTerminationSignal(t *testing.T) {
	t.Setenv("CAUTEM_MAIN_PROCESS_RESTART_POLICY", "always")
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

func TestRunAlwaysRestartsSuccessfulExitAndStopsAfterSignal(t *testing.T) {
	t.Setenv("CAUTEM_MAIN_PROCESS_RESTART_POLICY", "always")
	marker := filepath.Join(t.TempDir(), "attempts")
	command := fmt.Sprintf(`n=0; test ! -f %q || n=$(cat %q); n=$((n + 1)); printf '%%s' "$n" > %q; if test "$n" -lt 3; then exit 0; fi; sleep 30`, marker, marker, marker)
	done := make(chan struct {
		code int
		err  error
	}, 1)
	go func() {
		code, err := Run([]string{"sh", "-c", command})
		done <- struct {
			code int
			err  error
		}{code, err}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(marker); err == nil && string(data) == "3" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "3" {
		t.Fatalf("always policy attempts=%q err=%v, want 3 before signal", data, err)
	}
	if err := terminateSupervisorProcess(); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result.err != nil || result.code != 128+int(syscall.SIGTERM) {
			t.Fatalf("Run()=(%d,%v), want SIGTERM exit without restarting", result.code, result.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("always policy did not stop after supervisor received SIGTERM")
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
