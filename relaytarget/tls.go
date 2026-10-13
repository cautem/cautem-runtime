package relaytarget

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// EnvEndpoint is set in the trusted companion Pod and points at the
	// workload's per-sandbox boundary Service.
	EnvEndpoint = "CAUTEM_RELAY_TARGET_ENDPOINT"
	// EnvListen and the server identity are set only in the workload supervisor.
	EnvListen     = "CAUTEM_RELAY_TARGET_LISTEN"
	EnvClientCA   = "CAUTEM_RELAY_TARGET_CLIENT_CA"
	EnvServerCert = "CAUTEM_RELAY_TARGET_SERVER_CERT"
	EnvServerKey  = "CAUTEM_RELAY_TARGET_SERVER_KEY"
	EnvSSHSock    = "CAUTEM_RELAY_TARGET_SSH_SOCKET"
	// Client identity and server trust are set only in the trusted companion.
	EnvServerCA   = "CAUTEM_RELAY_TARGET_SERVER_CA"
	EnvClientCert = "CAUTEM_RELAY_TARGET_CLIENT_CERT"
	EnvClientKey  = "CAUTEM_RELAY_TARGET_CLIENT_KEY"
)

// ServerTLSConfigFromEnvironment loads the workload-side mTLS identity and
// returns its credential directory. The caller must keep that directory away
// from workload processes (Landlock on Linux) and verify it matches the
// supervisor's private credential directory before launching the workload.
func ServerTLSConfigFromEnvironment() (*tls.Config, string, error) {
	clientCAPath := strings.TrimSpace(os.Getenv(EnvClientCA))
	certPath := strings.TrimSpace(os.Getenv(EnvServerCert))
	keyPath := strings.TrimSpace(os.Getenv(EnvServerKey))
	if clientCAPath == "" || certPath == "" || keyPath == "" {
		return nil, "", errors.New("relaytarget: TLS listener requires client CA, server certificate, and server key")
	}
	directory, err := validateCredentialPaths(clientCAPath, certPath, keyPath)
	if err != nil {
		return nil, "", err
	}
	caPEM, err := os.ReadFile(clientCAPath)
	if err != nil {
		return nil, "", fmt.Errorf("relaytarget: read client CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, "", errors.New("relaytarget: client CA contains no certificates")
	}
	identity, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, "", fmt.Errorf("relaytarget: load server identity: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{identity},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}, directory, nil
}

func validateCredentialPaths(paths ...string) (string, error) {
	directory := ""
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return "", errors.New("relaytarget: TLS credential paths must be clean absolute paths")
		}
		current := filepath.Dir(path)
		if directory == "" {
			directory = current
			continue
		}
		if current != directory {
			return "", errors.New("relaytarget: TLS credentials must share one private directory")
		}
	}
	if directory == "" || directory == "/" {
		return "", errors.New("relaytarget: TLS credentials must be inside a private directory")
	}
	return directory, nil
}
