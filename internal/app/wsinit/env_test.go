package wsinit

import (
	"reflect"
	"testing"
)

func TestWorkloadEnvironmentStripsSupervisorOnlyControlAndOpenShellVariables(t *testing.T) {
	in := []string{
		"PATH=/usr/bin",
		"CAUTEM_SUPERVISOR_CONTROL_SOCKET=/run/control.sock",
		"CAUTEM_SUPERVISOR_CONTROL_ENDPOINT=supervisor.default.svc:5502",
		"CAUTEM_SUPERVISOR_CONTROL_CLIENT_CA=/run/control/ca.pem",
		"CAUTEM_SUPERVISOR_CONTROL_CLIENT_CERT=/run/control/client.crt",
		"CAUTEM_SUPERVISOR_CONTROL_CLIENT_KEY=/run/control/client.key",
		"CAUTEM_SUPERVISOR_CONTROL_PRIVATE_DIR=/run/control",
		"CAUTEM_SUPERVISOR_CONTROL_SERVER_CA=/run/control/server-ca.pem",
		"CAUTEM_SUPERVISOR_CONTROL_SERVER_CERT=/run/control/server.crt",
		"CAUTEM_SUPERVISOR_CONTROL_SERVER_KEY=/run/control/server.key",
		"CAUTEM_RELAY_TARGET_LISTEN=0.0.0.0:5503",
		"CAUTEM_RELAY_TARGET_CLIENT_CA=/run/control/client-ca.pem",
		"CAUTEM_RELAY_TARGET_SERVER_CERT=/run/control/server.crt",
		"CAUTEM_RELAY_TARGET_SERVER_KEY=/run/control/server.key",
		"CAUTEM_RELAY_TARGET_SSH_SOCKET=/cautem/ssh/sshd.sock",
		"CAUTEM_RELAY_TARGET_ENDPOINT=workload.default.svc:5503",
		"CAUTEM_RELAY_TARGET_SERVER_CA=/run/control/target-ca.pem",
		"CAUTEM_RELAY_TARGET_CLIENT_CERT=/run/control/client.crt",
		"CAUTEM_RELAY_TARGET_CLIENT_KEY=/run/control/client.key",
		"CAUTEM_RELAY_TARGET_SOCKET=/run/control/target.sock",
		"OPENSHELL_SANDBOX_UID=1000",
		"OPENSHELL_SANDBOX_GID=1000",
		"OPENSHELL_SANDBOX_TOKEN=secret",
		"OPENSHELL_TLS_KEY=/run/secrets/key",
		"OPENSHELL_NETWORK_RUNTIME_CAPABILITIES=policy-dns-transparent-tcp",
		"OPENSHELL_USER_ENVIRONMENT={}",
		"OPENAI_API_KEY=workload-secret",
	}
	want := []string{
		"PATH=/usr/bin",
		"OPENSHELL_USER_ENVIRONMENT={}",
		"OPENAI_API_KEY=workload-secret",
	}
	if got := workloadEnvironment(in); !reflect.DeepEqual(got, want) {
		t.Fatalf("workloadEnvironment() = %v, want %v", got, want)
	}
}
