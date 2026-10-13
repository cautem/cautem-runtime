//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package supervisor

import (
	"slices"
	"strings"
	"testing"

	"github.com/cautem/cautem-runtime/relaytarget"
	"github.com/cautem/cautem-runtime/supervisorcontrol"
)

func TestParseArgsRequiresSeparatorAndPreservesArgv(t *testing.T) {
	if _, err := ParseArgs([]string{"sh", "-c", "echo unsafe"}); err == nil {
		t.Fatal("command without explicit separator was accepted")
	}
	got, err := ParseArgs([]string{"--", "sh", "-c", "printf '%s'", "a b"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"sh", "-c", "printf '%s'", "a b"}
	if !slices.Equal(got, want) {
		t.Fatalf("argv=%q, want %q", got, want)
	}
}

func TestRunReturnsWorkloadExitCode(t *testing.T) {
	code, err := Run(workloadArgs(exitCommand(17)...))
	if err != nil || code != 17 {
		t.Fatalf("Run()=(%d,%v), want (17,nil)", code, err)
	}
}

func TestRunRejectsEmptyCommand(t *testing.T) {
	if code, err := Run(nil); err == nil || code != 2 {
		t.Fatalf("Run(nil)=(%d,%v), want usage error", code, err)
	}
}

func TestWorkloadEnvironmentDropsSupervisorControlCredentials(t *testing.T) {
	privateValues := map[string]string{
		supervisorcontrol.EnvSocket:     "/run/cautem/control.sock",
		supervisorcontrol.EnvEndpoint:   "supervisor.default.svc:5502",
		supervisorcontrol.EnvClientCA:   "/run/cautem/control/ca.pem",
		supervisorcontrol.EnvClientCert: "/run/cautem/control/tls.crt",
		supervisorcontrol.EnvClientKey:  "/run/cautem/control/tls.key",
		supervisorcontrol.EnvPrivateDir: "/untrusted/workload/override",
		supervisorcontrol.EnvListen:     "0.0.0.0:5502",
		supervisorcontrol.EnvServerCA:   "/run/cautem/control/server-ca.pem",
		supervisorcontrol.EnvServerCert: "/run/cautem/control/server.crt",
		supervisorcontrol.EnvServerKey:  "/run/cautem/control/server.key",
		relaytarget.EnvListen:           "0.0.0.0:5503",
		relaytarget.EnvClientCA:         "/run/cautem/control/target-client-ca.pem",
		relaytarget.EnvServerCert:       "/run/cautem/control/target-server.crt",
		relaytarget.EnvServerKey:        "/run/cautem/control/target-server.key",
		relaytarget.EnvSSHSock:          "/cautem/ssh/sshd.sock",
		relaytarget.EnvServerCA:         "/run/cautem/control/target-server-ca.pem",
		relaytarget.EnvClientCert:       "/run/cautem/control/target-client.crt",
		relaytarget.EnvClientKey:        "/run/cautem/control/target-client.key",
		"CAUTEM_RELAY_TARGET_SOCKET":    "/run/cautem/target.sock",
		"CAUTEM_TEST_WORKLOAD_VALUE":    "visible",
	}
	for name, value := range privateValues {
		t.Setenv(name, value)
	}

	privateDir := "/run/cautem/control"
	got := workloadEnvironment(privateDir)
	joined := strings.Join(got, "\n")
	for _, name := range []string{
		supervisorcontrol.EnvSocket,
		supervisorcontrol.EnvEndpoint,
		supervisorcontrol.EnvListen,
		supervisorcontrol.EnvClientCA,
		supervisorcontrol.EnvClientCert,
		supervisorcontrol.EnvClientKey,
		supervisorcontrol.EnvServerCA,
		supervisorcontrol.EnvServerCert,
		supervisorcontrol.EnvServerKey,
		relaytarget.EnvListen,
		relaytarget.EnvClientCA,
		relaytarget.EnvServerCert,
		relaytarget.EnvServerKey,
		relaytarget.EnvSSHSock,
		relaytarget.EnvServerCA,
		relaytarget.EnvClientCert,
		relaytarget.EnvClientKey,
		"CAUTEM_RELAY_TARGET_SOCKET",
	} {
		if strings.Contains(joined, name+"=") {
			t.Errorf("workload environment leaked %s", name)
		}
	}
	if !strings.Contains(joined, "CAUTEM_TEST_WORKLOAD_VALUE=visible") {
		t.Fatal("ordinary workload environment variable was removed")
	}
	if !strings.Contains(joined, supervisorcontrol.EnvPrivateDir+"="+privateDir) {
		t.Fatal("workload init did not receive the supervisor control credential isolation marker")
	}
}
