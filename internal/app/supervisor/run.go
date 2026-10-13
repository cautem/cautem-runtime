// Package supervisor runs a sandbox workload as the container's PID 1.
//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package supervisor

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cautem/cautem-core/defaults"
	"github.com/cautem/cautem-runtime/relaytarget"
	"github.com/cautem/cautem-runtime/supervisorcontrol"
)

type processEventMonitor interface {
	MainExit()
	Scan()
	ChildExit(pid int)
	Close()
}

// Run starts a parsed workload argv, forwards termination signals to its
// process group, reaps adopted children, and returns the workload exit code.
func Run(args []string) (int, error) {
	if len(args) == 0 {
		return 2, fmt.Errorf("usage: cautem-supervisor -- <command> [args...]")
	}
	controlClient, err := supervisorcontrol.NewClientFromEnvironment()
	if err != nil {
		return 125, fmt.Errorf("cautem-supervisor: configure lifecycle control: %w", err)
	}
	privateCredentialDir := controlClient.PrivateCredentialDir()
	targetSocket := strings.TrimSpace(os.Getenv("CAUTEM_RELAY_TARGET_SOCKET"))
	targetListen := strings.TrimSpace(os.Getenv(relaytarget.EnvListen))
	if targetSocket != "" && targetListen != "" {
		return 125, errors.New("cautem-supervisor: configure either a Unix target socket or an mTLS target listener")
	}
	var targetTLS *tls.Config
	if targetListen != "" {
		var targetCredentialDir string
		targetTLS, targetCredentialDir, err = relaytarget.ServerTLSConfigFromEnvironment()
		if err != nil {
			return 125, fmt.Errorf("cautem-supervisor: configure mTLS target bridge: %w", err)
		}
		if privateCredentialDir == "" || privateCredentialDir != targetCredentialDir {
			return 125, errors.New("cautem-supervisor: target bridge credentials must share the private lifecycle credential directory")
		}
	} else if strings.TrimSpace(os.Getenv(relaytarget.EnvClientCA)) != "" || strings.TrimSpace(os.Getenv(relaytarget.EnvServerCert)) != "" || strings.TrimSpace(os.Getenv(relaytarget.EnvServerKey)) != "" {
		return 125, errors.New("cautem-supervisor: target bridge server credentials require an mTLS listener")
	}
	if privateCredentialDir != "" {
		if err := protectSupervisorMemory(); err != nil {
			return 125, fmt.Errorf("cautem-supervisor: protect private runtime credentials: %w", err)
		}
	}
	var targetServer *relaytarget.Server
	if targetListen != "" {
		sshSocket := strings.TrimSpace(os.Getenv(relaytarget.EnvSSHSock))
		if sshSocket == "" {
			sshSocket = defaults.GuestSSHSocket
		}
		targetServer, err = relaytarget.ListenTLS(targetListen, targetTLS, sshSocket)
	} else if targetSocket != "" {
		targetServer, err = relaytarget.Listen(targetSocket)
	}
	if err != nil {
		return 125, fmt.Errorf("cautem-supervisor: start relay target listener: %w", err)
	}
	if targetServer != nil {
		defer func() {
			if err := targetServer.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "cautem-supervisor: stop relay target listener: %v\n", err)
			}
		}()
	}
	instanceID := ""
	if controlClient != nil {
		instanceID, err = beginProcessInstance(controlClient)
		if err != nil {
			return 125, fmt.Errorf("cautem-supervisor: begin OpenShell process instance: %w", err)
		}
	}
	command := exec.Command(args[0], args[1:]...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	command.Env = workloadEnvironment(privateCredentialDir)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	signals := make(chan os.Signal, 16)
	signal.Notify(signals, syscall.SIGCHLD, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(signals)
	if err := enableChildSubreaper(); err != nil {
		return 125, fmt.Errorf("cautem-supervisor: enable child reaping: %w", err)
	}
	if err := command.Start(); err != nil {
		return 127, fmt.Errorf("cautem-supervisor: start workload: %w", err)
	}
	processMonitor := startProcessMonitor(controlClient, instanceID, command.Process.Pid, command.Path)

	result := make(chan error, 1)
	go func() { result <- command.Wait() }()
	shutdownRequested := false

	for {
		select {
		case signal := <-signals:
			if signal == syscall.SIGCHLD {
				reapWorkloadChildren(command.Process.Pid, processMonitor)
				continue
			}
			shutdownRequested = true
			if err := signalWorkloadGroup(command.Process.Pid, signal); err != nil && !errors.Is(err, syscall.ESRCH) {
				fmt.Fprintf(os.Stderr, "cautem-supervisor: forward %s: %v\n", signal, err)
			}
		case err := <-result:
			code, waitErr := workloadExitCode(err)
			if processMonitor != nil {
				processMonitor.MainExit()
			}
			stopWorkloadGroup(command.Process.Pid, processMonitor)
			if processMonitor != nil {
				processMonitor.Close()
				flushProcessEvents(controlClient, instanceID)
			}
			for {
				select {
				case signal := <-signals:
					if signal != syscall.SIGCHLD {
						shutdownRequested = true
					}
				default:
					goto signalsDrained
				}
			}
		signalsDrained:
			if controlClient != nil && instanceID != "" && !shutdownRequested && waitErr == nil {
				if err := reportProcessExitUntilAck(controlClient, instanceID, int32(code)); err != nil {
					return 125, err
				}
				if err := finalizeProcessExitUntilAck(controlClient, instanceID); err != nil {
					return 125, err
				}
			}
			return code, waitErr
		}
	}
}

func flushProcessEvents(controlClient *supervisorcontrol.Client, instanceID string) {
	if controlClient == nil || strings.TrimSpace(instanceID) == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	_, err := controlClient.Call(ctx, supervisorcontrol.Request{
		Operation: supervisorcontrol.OperationFlush, InstanceID: instanceID,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cautem-supervisor: final process events may not have reached the gateway: %v\n", err)
	}
}

func workloadExitCode(err error) (int, error) {
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			status, ok := exitErr.Sys().(syscall.WaitStatus)
			if ok {
				if status.Signaled() {
					return 128 + int(status.Signal()), nil
				}
				return status.ExitStatus(), nil
			}
		}
		return 125, fmt.Errorf("cautem-supervisor: wait for workload: %w", err)
	}
	return 0, nil
}

func beginProcessInstance(controlClient *supervisorcontrol.Client) (string, error) {
	deadline := time.Now().Add(30 * time.Second)
	delay := 100 * time.Millisecond
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		response, err := controlClient.Call(ctx, supervisorcontrol.Request{Operation: supervisorcontrol.OperationBegin})
		cancel()
		if err == nil && response.InstanceID != "" {
			return response.InstanceID, nil
		}
		if time.Now().After(deadline) {
			if err == nil {
				err = errors.New("sidecar returned an empty instance id")
			}
			return "", err
		}
		time.Sleep(delay)
		if delay < time.Second {
			delay *= 2
		}
	}
}

func reportProcessExitUntilAck(controlClient *supervisorcontrol.Client, instanceID string, exitCode int32) error {
	return lifecycleUntilAck(controlClient, supervisorcontrol.Request{Operation: supervisorcontrol.OperationReport, InstanceID: instanceID, ExitCode: exitCode}, "report main process exit")
}

func finalizeProcessExitUntilAck(controlClient *supervisorcontrol.Client, instanceID string) error {
	return lifecycleUntilAck(controlClient, supervisorcontrol.Request{Operation: supervisorcontrol.OperationFinalize, InstanceID: instanceID}, "finalize main process exit")
}

func lifecycleUntilAck(controlClient *supervisorcontrol.Client, request supervisorcontrol.Request, operation string) error {
	delay := 250 * time.Millisecond
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 16*time.Second)
		_, err := controlClient.Call(ctx, request)
		cancel()
		if err == nil {
			return nil
		}
		fmt.Fprintf(os.Stderr, "cautem-supervisor: %s failed; retrying: %v\n", operation, err)
		time.Sleep(delay)
		if delay < 2*time.Second {
			delay *= 2
		}
	}
}

func workloadEnvironment(privateCredentialDir string) []string {
	privateControlEnv := map[string]struct{}{
		supervisorcontrol.EnvSocket: {}, supervisorcontrol.EnvEndpoint: {}, supervisorcontrol.EnvListen: {},
		supervisorcontrol.EnvClientCA: {}, supervisorcontrol.EnvClientCert: {}, supervisorcontrol.EnvClientKey: {},
		supervisorcontrol.EnvPrivateDir: {},
		supervisorcontrol.EnvServerCA:   {}, supervisorcontrol.EnvServerCert: {}, supervisorcontrol.EnvServerKey: {},
		relaytarget.EnvEndpoint: {}, relaytarget.EnvListen: {}, relaytarget.EnvClientCA: {},
		relaytarget.EnvServerCert: {}, relaytarget.EnvServerKey: {}, relaytarget.EnvSSHSock: {},
		relaytarget.EnvServerCA: {}, relaytarget.EnvClientCert: {}, relaytarget.EnvClientKey: {},
		"CAUTEM_RELAY_TARGET_SOCKET": {},
	}
	environment := os.Environ()
	filtered := make([]string, 0, len(environment))
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		if _, private := privateControlEnv[key]; !private {
			filtered = append(filtered, entry)
		}
	}
	if privateCredentialDir != "" {
		filtered = append(filtered, supervisorcontrol.EnvPrivateDir+"="+privateCredentialDir)
	}
	return filtered
}

// ParseArgs accepts only an explicit separator, preserving workload argv
// boundaries and ensuring supervisor flags cannot be confused with payload.
func ParseArgs(args []string) ([]string, error) {
	for i, arg := range args {
		if arg == "--" {
			if i+1 == len(args) {
				return nil, fmt.Errorf("cautem-supervisor: command after -- is empty")
			}
			return args[i+1:], nil
		}
	}
	return nil, fmt.Errorf("cautem-supervisor: expected -- before workload command")
}

const shutdownGrace = 2 * time.Second

func stopWorkloadGroup(pid int, monitor processEventMonitor) {
	_ = signalWorkloadGroup(pid, syscall.SIGTERM)
	deadline := time.NewTimer(shutdownGrace)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for processGroupExists(pid) {
		select {
		case <-ticker.C:
			reapWorkloadChildren(pid, monitor)
		case <-deadline.C:
			_ = signalWorkloadGroup(pid, syscall.SIGKILL)
			for processGroupExists(pid) {
				reapWorkloadChildren(pid, monitor)
				time.Sleep(10 * time.Millisecond)
			}
			return
		}
	}
}

// reapWorkloadChildren reconciles /proc before wait4 removes child entries.
// The wait4 callback lets the monitor emit EXIT for tracked adopted children
// immediately instead of waiting for the next periodic /proc scan.
func reapWorkloadChildren(pid int, monitor processEventMonitor) {
	if monitor != nil {
		monitor.Scan()
	}
	reapAdoptedChildren(pid, func(childPID int) {
		if monitor != nil {
			monitor.ChildExit(childPID)
		}
	})
}
