//go:build linux

package supervisor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cautem/quarshell-runtime/supervisorcontrol"
)

func enableTestSubreaper(t *testing.T) {
	t.Helper()
	const prSetChildSubreaper = 36
	_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetChildSubreaper, 1, 0, 0, 0, 0)
	if errno != 0 {
		t.Fatalf("enable test child subreaper: %v", errno)
	}
}

const (
	processEventHelperModeEnv  = "CAUTEM_TEST_PROCESS_HELPER_MODE"
	processEventHelperPIDEnv   = "CAUTEM_TEST_PROCESS_HELPER_PID_FILE"
	processEventHelperExitEnv  = "CAUTEM_TEST_PROCESS_HELPER_EXIT_FILE"
	processEventHelperDelayEnv = "CAUTEM_TEST_PROCESS_HELPER_DELAY_MS"
)

func TestProtectSupervisorMemoryDisablesPtraceDumpability(t *testing.T) {
	const child = "CAUTEM_TEST_DUMPABLE_PROTECTION_CHILD"
	if os.Getenv(child) == "1" {
		if err := protectSupervisorMemory(); err != nil {
			t.Fatalf("protectSupervisorMemory() error = %v", err)
		}
		const prGetDumpable = 3
		value, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prGetDumpable, 0, 0, 0, 0, 0)
		if errno != 0 {
			t.Fatalf("PR_GET_DUMPABLE error = %v", errno)
		}
		if value != 0 {
			t.Fatalf("dumpable = %d, want 0", value)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestProtectSupervisorMemoryDisablesPtraceDumpability$")
	cmd.Env = append(os.Environ(), child+"=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("protected child failed: %v\n%s", err, output)
	}
}

// TestProcessEventLinuxChildHelper is invoked as a separate test binary by the
// Linux process lifecycle tests below.
func TestProcessEventLinuxChildHelper(t *testing.T) {
	switch os.Getenv(processEventHelperModeEnv) {
	case "":
		return
	case "spawn-orphan", "spawn-orphan-long":
		child := exec.Command("sleep", "0.25")
		if os.Getenv(processEventHelperModeEnv) == "spawn-orphan-long" {
			child = exec.Command("sleep", "30")
		}
		if err := child.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if err := os.WriteFile(os.Getenv(processEventHelperPIDEnv), []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		os.Exit(0)
	case "subreaper-adoption":
		if os.Getpid() == 1 {
			t.Fatal("fixture must exercise a supervisor process that is not PID 1")
		}
		if err := enableChildSubreaper(); err != nil {
			t.Fatalf("enable child subreaper: %v", err)
		}
		pidFile := os.Getenv(processEventHelperPIDEnv)
		child := exec.Command(os.Args[0], "-test.run=^TestProcessEventLinuxChildHelper$")
		child.Env = processEventHelperEnv("spawn-orphan-long", processEventHelperPIDEnv, pidFile)
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("spawn orphan fixture: %v\n%s", err, output)
		}
		pid := readPIDFile(t, pidFile)
		defer func() {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			var status syscall.WaitStatus
			_, _ = syscall.Wait4(pid, &status, 0, nil)
		}()
		waitForLinuxProcess(t, pid, func(process linuxProcessInfo) bool {
			return process.ParentPID == os.Getpid() && process.State != "Z"
		})
	case "timed-exit":
		delay, err := strconv.Atoi(os.Getenv(processEventHelperDelayEnv))
		if err != nil || delay < 0 {
			fmt.Fprintln(os.Stderr, "invalid helper delay")
			os.Exit(2)
		}
		time.Sleep(time.Duration(delay) * time.Millisecond)
		if err := os.WriteFile(os.Getenv(processEventHelperExitEnv), []byte(strconv.FormatInt(time.Now().UnixNano(), 10)), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		os.Exit(0)
	default:
		fmt.Fprintln(os.Stderr, "unknown helper mode")
		os.Exit(2)
	}
}

func TestEnableChildSubreaperAdoptsDescendantsWithoutPIDOne(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	helper := exec.Command(os.Args[0], "-test.run=^TestProcessEventLinuxChildHelper$")
	helper.Env = processEventHelperEnv("subreaper-adoption", processEventHelperPIDEnv, pidFile)
	if output, err := helper.CombinedOutput(); err != nil {
		t.Fatalf("non-PID-1 supervisor did not adopt its orphaned descendant: %v\n%s", err, output)
	}
}

func TestReapAdoptedChildrenReportsReapedPID(t *testing.T) {
	enableTestSubreaper(t)
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	helper := exec.Command(os.Args[0], "-test.run=^TestProcessEventLinuxChildHelper$")
	helper.Env = processEventHelperEnv("spawn-orphan", processEventHelperPIDEnv, pidFile)
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	helperPID := helper.Process.Pid
	if err := helper.Wait(); err != nil {
		t.Fatalf("helper exit: %v", err)
	}

	childPID := readPIDFile(t, pidFile)
	defer func() {
		_ = syscall.Kill(childPID, syscall.SIGKILL)
		var status syscall.WaitStatus
		_, _ = syscall.Wait4(childPID, &status, syscall.WNOHANG, nil)
	}()
	waitForLinuxProcess(t, childPID, func(process linuxProcessInfo) bool {
		return process.ParentPID == os.Getpid() && process.State == "Z"
	})

	var reapedPID int
	reapAdoptedChildren(helperPID, func(pid int) { reapedPID = pid })
	if reapedPID != childPID {
		t.Fatalf("reaped pid=%d, want adopted child %d", reapedPID, childPID)
	}
	if _, ok := readProcessInfo(childPID); ok {
		t.Fatalf("reaped child %d remains in /proc", childPID)
	}
}

func TestReapAdoptedChildrenDoesNotStealMainProcessWait(t *testing.T) {
	main := exec.Command("sh", "-c", "sleep 0.1; exit 23")
	if err := main.Start(); err != nil {
		t.Fatal(err)
	}
	mainPID := main.Process.Pid
	waitForLinuxProcess(t, mainPID, func(process linuxProcessInfo) bool {
		return process.ParentPID == os.Getpid() && process.State == "Z"
	})

	var callbackCalled bool
	reapAdoptedChildren(mainPID, func(int) { callbackCalled = true })
	if callbackCalled {
		t.Fatal("reaper consumed the direct workload process owned by exec.Cmd.Wait")
	}
	if err := main.Wait(); err == nil {
		t.Fatal("main.Wait() succeeded, want exit status 23")
	} else if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 23 {
		t.Fatalf("main.Wait() error=%v, want exit code 23", err)
	}
}

type processEventReceipt struct {
	event      supervisorcontrol.ProcessEvent
	receivedAt time.Time
}

func TestWorkloadProcessTreeIncludesAdoptedChildrenOutsideMainProcessGroup(t *testing.T) {
	const (
		supervisorPID = 1
		mainPID       = 10
	)
	tests := []struct {
		name          string
		process       linuxProcessInfo
		parentTracked bool
		want          bool
	}{
		{
			name:    "adopted child with separate process group",
			process: linuxProcessInfo{PID: 42, ParentPID: supervisorPID, GroupID: 41},
			want:    true,
		},
		{
			name:          "child of tracked workload descendant",
			process:       linuxProcessInfo{PID: 43, ParentPID: 42, GroupID: 41},
			parentTracked: true,
			want:          true,
		},
		{
			name:    "unrelated process",
			process: linuxProcessInfo{PID: 44, ParentPID: 2, GroupID: 3},
			want:    false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := isWorkloadDescendant(test.process, mainPID, supervisorPID, test.parentTracked)
			if got != test.want {
				t.Fatalf("isWorkloadDescendant(%+v) = %t, want %t", test.process, got, test.want)
			}
		})
	}
}

func TestRunCollectsCoalescedAdoptedChildExits(t *testing.T) {
	enableTestSubreaper(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socketPath := filepath.Join(t.TempDir(), "supervisor.sock")
	receipts := make(chan processEventReceipt, 128)
	server, err := supervisorcontrol.Start(ctx, socketPath, func(_ context.Context, request supervisorcontrol.Request) supervisorcontrol.Response {
		switch request.Operation {
		case supervisorcontrol.OperationBegin:
			return supervisorcontrol.Response{InstanceID: "test-instance"}
		case supervisorcontrol.OperationProcess:
			if request.Process == nil || request.Process.InstanceID != "test-instance" {
				return supervisorcontrol.Response{Error: "process event has no current instance id"}
			}
			receipts <- processEventReceipt{event: *request.Process, receivedAt: time.Now()}
		case supervisorcontrol.OperationReport:
			if request.ExitCode != 17 {
				return supervisorcontrol.Response{Error: "incorrect workload exit code"}
			}
		case supervisorcontrol.OperationFlush, supervisorcontrol.OperationFinalize:
		default:
			return supervisorcontrol.Response{Error: "unexpected operation"}
		}
		return supervisorcontrol.Response{InstanceID: "test-instance"}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	t.Setenv("CAUTEM_SUPERVISOR_CONTROL_SOCKET", socketPath)

	const childCount = 4
	pidFiles := make([]string, childCount)
	exitFiles := make([]string, childCount)
	launches := make([]string, childCount)
	for i := 0; i < childCount; i++ {
		pidFiles[i] = filepath.Join(t.TempDir(), fmt.Sprintf("child-%d.pid", i))
		exitFiles[i] = filepath.Join(t.TempDir(), fmt.Sprintf("child-%d.exit", i))
		delay := 500
		helper := helperShellCommand("timed-exit", processEventHelperExitEnv, exitFiles[i], processEventHelperDelayEnv, strconv.Itoa(delay))
		launches[i] = fmt.Sprintf("(%s & echo $! > %s)", helper, shellQuote(pidFiles[i]))
	}
	// The short-lived launcher reparents all helpers to this test process
	// (configured as a subreaper) while the main workload remains alive.
	script := "( " + strings.Join(launches, "; ") + "; exit 0 ) & sleep 1.4; exit 17"
	code, err := Run([]string{"sh", "-c", script})
	if err != nil || code != 17 {
		t.Fatalf("Run()=(%d,%v), want (17,nil)", code, err)
	}

	childPIDs := make(map[int]time.Time, childCount)
	for i := range pidFiles {
		pid := readPIDFile(t, pidFiles[i])
		stamp := readUnixNanoFile(t, exitFiles[i])
		childPIDs[pid] = stamp
	}
	seen := make(map[int]map[string]processEventReceipt, childCount)
	for len(seenExits(seen, childPIDs)) < childCount {
		select {
		case receipt := <-receipts:
			if _, expected := childPIDs[receipt.event.PID]; !expected {
				continue
			}
			if seen[receipt.event.PID] == nil {
				seen[receipt.event.PID] = make(map[string]processEventReceipt)
			}
			seen[receipt.event.PID][receipt.event.Activity] = receipt
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for child EXIT events; received=%v", seenExits(seen, childPIDs))
		}
	}

	latencies := make([]time.Duration, 0, childCount)
	for pid, exitedAt := range childPIDs {
		if _, ok := seen[pid]["LAUNCH"]; !ok {
			t.Errorf("child %d has no LAUNCH event", pid)
		}
		exit, ok := seen[pid]["EXIT"]
		if !ok {
			t.Errorf("child %d has no EXIT event", pid)
			continue
		}
		latencies = append(latencies, exit.receivedAt.Sub(exitedAt))
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	if len(latencies) > 0 {
		t.Logf("adopted-child exit to local supervisor socket: p50=%s p95=%s max=%s (n=%d)", latencies[len(latencies)/2], latencies[len(latencies)-1], latencies[len(latencies)-1], len(latencies))
	}
}

func processEventHelperEnv(mode string, values ...string) []string {
	env := make([]string, 0, len(os.Environ())+1+len(values)/2)
	managed := []string{processEventHelperModeEnv, processEventHelperPIDEnv, processEventHelperExitEnv, processEventHelperDelayEnv}
	for _, item := range os.Environ() {
		remove := false
		for _, key := range managed {
			if strings.HasPrefix(item, key+"=") {
				remove = true
				break
			}
		}
		if remove {
			continue
		}
		env = append(env, item)
	}
	env = append(env, processEventHelperModeEnv+"="+mode)
	for i := 0; i+1 < len(values); i += 2 {
		env = append(env, values[i]+"="+values[i+1])
	}
	return env
}

func helperShellCommand(mode string, values ...string) string {
	parts := []string{processEventHelperModeEnv + "=" + shellQuote(mode)}
	for i := 0; i+1 < len(values); i += 2 {
		parts = append(parts, values[i]+"="+shellQuote(values[i+1]))
	}
	parts = append(parts, shellQuote(os.Args[0]), "-test.run="+shellQuote("^TestProcessEventLinuxChildHelper$"))
	return strings.Join(parts, " ")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func readPIDFile(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pid file %q: %v", path, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		t.Fatalf("invalid pid in %q: %q", path, data)
	}
	return pid
}

func readUnixNanoFile(t *testing.T, path string) time.Time {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read timestamp file %q: %v", path, err)
	}
	nanos, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		t.Fatalf("invalid timestamp in %q: %q", path, data)
	}
	return time.Unix(0, nanos)
}

func waitForLinuxProcess(t *testing.T, pid int, predicate func(linuxProcessInfo) bool) linuxProcessInfo {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if process, ok := readProcessInfo(pid); ok && predicate(process) {
			return process
		}
		time.Sleep(5 * time.Millisecond)
	}
	process, ok := readProcessInfo(pid)
	t.Fatalf("process %d did not reach expected state (last=%+v, present=%t)", pid, process, ok)
	return linuxProcessInfo{}
}

func seenExits(seen map[int]map[string]processEventReceipt, expected map[int]time.Time) map[int]bool {
	exits := make(map[int]bool, len(expected))
	for pid := range expected {
		if _, ok := seen[pid]["EXIT"]; ok {
			exits[pid] = true
		}
	}
	return exits
}
