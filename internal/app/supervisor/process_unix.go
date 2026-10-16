//go:build darwin || freebsd || openbsd || netbsd || dragonfly

package supervisor

import (
	"errors"
	"os"
	"syscall"

	"github.com/cautem/quarshell-runtime/supervisorcontrol"
)

func enableChildSubreaper() error { return nil }

func protectSupervisorMemory() error {
	return errors.New("private supervisor control credentials require Linux process isolation")
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

func reapAdoptedChildren(int, func(int)) {}

type noopProcessEventMonitor struct{}

func (noopProcessEventMonitor) MainExit()     {}
func (noopProcessEventMonitor) Scan()         {}
func (noopProcessEventMonitor) ChildExit(int) {}
func (noopProcessEventMonitor) Close()        {}

func startProcessMonitor(*supervisorcontrol.Client, string, int, string) processEventMonitor {
	return noopProcessEventMonitor{}
}
