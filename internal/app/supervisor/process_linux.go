//go:build linux

package supervisor

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

func enableChildSubreaper() error {
	if os.Getpid() != 1 {
		return nil
	}
	const prSetChildSubreaper = 36
	_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetChildSubreaper, 1, 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func protectSupervisorMemory() error {
	const prSetDumpable = 4
	_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetDumpable, 0, 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func signalWorkloadGroup(pid int, signal os.Signal) error {
	sig, ok := signal.(syscall.Signal)
	if !ok {
		return syscall.EINVAL
	}
	return syscall.Kill(-pid, sig)
}

func processGroupExists(pid int) bool {
	err := syscall.Kill(-pid, 0)
	return err == nil || err == syscall.EPERM
}

// Reap adopted descendants without racing exec.Cmd.Wait for the direct child.
// onReaped receives each child that wait4 successfully reaped.
func reapAdoptedChildren(mainPID int, onReaped func(int)) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	self := os.Getpid()
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == self || pid == mainPID {
			continue
		}
		stat, err := os.ReadFile("/proc/" + entry.Name() + "/stat")
		if err != nil {
			continue
		}
		closeParen := strings.LastIndexByte(string(stat), ')')
		if closeParen < 0 {
			continue
		}
		fields := strings.Fields(string(stat[closeParen+1:]))
		// stat fields after comm start with state (field 3), then ppid (field 4).
		if len(fields) < 2 || fields[1] != strconv.Itoa(self) {
			continue
		}
		var status syscall.WaitStatus
		reapedPID, err := syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
		if err == nil && reapedPID > 0 && onReaped != nil {
			onReaped(reapedPID)
		}
	}
}
