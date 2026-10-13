package wsinit

import (
	"strings"

	"github.com/cautem/cautem-runtime/relaytarget"
	"github.com/cautem/cautem-runtime/supervisorcontrol"
)

// These OpenShell variables are consumed by the supervisor and must not leak
// into the workload process environment.
var supervisorOnlyEnv = map[string]struct{}{
	supervisorcontrol.EnvSocket:                     {},
	supervisorcontrol.EnvEndpoint:                   {},
	supervisorcontrol.EnvClientCA:                   {},
	supervisorcontrol.EnvClientCert:                 {},
	supervisorcontrol.EnvClientKey:                  {},
	supervisorcontrol.EnvPrivateDir:                 {},
	supervisorcontrol.EnvServerCA:                   {},
	supervisorcontrol.EnvServerCert:                 {},
	supervisorcontrol.EnvServerKey:                  {},
	relaytarget.EnvEndpoint:                         {},
	relaytarget.EnvListen:                           {},
	relaytarget.EnvClientCA:                         {},
	relaytarget.EnvServerCert:                       {},
	relaytarget.EnvServerKey:                        {},
	relaytarget.EnvSSHSock:                          {},
	relaytarget.EnvServerCA:                         {},
	relaytarget.EnvClientCert:                       {},
	relaytarget.EnvClientKey:                        {},
	"CAUTEM_RELAY_TARGET_SOCKET":                    {},
	"OPENSHELL_OCI_IMAGE_USER":                      {},
	"OPENSHELL_SANDBOX_UID":                         {},
	"OPENSHELL_SANDBOX_GID":                         {},
	"OPENSHELL_SANDBOX_TOKEN":                       {},
	"OPENSHELL_SANDBOX_TOKEN_FILE":                  {},
	"OPENSHELL_K8S_SA_TOKEN_FILE":                   {},
	"OPENSHELL_TLS_CA":                              {},
	"OPENSHELL_TLS_CERT":                            {},
	"OPENSHELL_TLS_KEY":                             {},
	"OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET": {},
	"OPENSHELL_NETWORK_RUNTIME_CAPABILITIES":        {},
}

func workloadEnvironment(environ []string) []string {
	out := make([]string, 0, len(environ))
	for _, entry := range environ {
		key, _, _ := strings.Cut(entry, "=")
		if _, reserved := supervisorOnlyEnv[key]; reserved {
			continue
		}
		out = append(out, entry)
	}
	return out
}
