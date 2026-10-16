package relayclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/cautem/cautem-runtime/relaytarget"
	"github.com/cautem/cautem-runtime/supervisorcontrol"
)

// runSupervisorGRPC speaks the Gateway supervisor and relay gRPC
// gRPC protocol. It is selected when GatewayGRPCEndpoint is configured.

func grpcTarget(endpoint string) (string, bool, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", false, errors.New("relayclient: OpenShell gRPC endpoint is required")
	}
	if !strings.Contains(endpoint, "://") {
		if _, _, err := net.SplitHostPort(endpoint); err != nil {
			return "", false, errors.New("relayclient: bare gRPC endpoint must be host:port")
		}
		return endpoint, false, nil
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", false, fmt.Errorf("relayclient: invalid OpenShell gRPC endpoint: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", false, errors.New("relayclient: gRPC endpoint must be host:port, http://host:port, or https://host:port")
	}
	return u.Host, u.Scheme == "https", nil
}

// GRPCTarget validates and normalizes an OpenShell gateway endpoint.

// GRPCTarget validates and normalizes an OpenShell gateway endpoint.
func GRPCTarget(endpoint string) (string, bool, error) {
	return grpcTarget(endpoint)
}

// GatewayTLSConfigFromEnvironment loads the guest mTLS triplet mounted by the
// Docker/Podman driver. Empty settings leave TLS verification to system roots.

// GatewayTLSConfigFromEnvironment loads the guest mTLS triplet mounted by the
// Docker/Podman driver. Empty settings leave TLS verification to system roots.
func GatewayTLSConfigFromEnvironment() (*tls.Config, error) {
	caPath := strings.TrimSpace(os.Getenv("CAUTEM_GUEST_TLS_CA"))
	certPath := strings.TrimSpace(os.Getenv("CAUTEM_GUEST_TLS_CERT"))
	keyPath := strings.TrimSpace(os.Getenv("CAUTEM_GUEST_TLS_KEY"))
	if caPath == "" && certPath == "" && keyPath == "" {
		return nil, nil
	}
	if caPath == "" || certPath == "" || keyPath == "" {
		return nil, errors.New("relayclient: guest gateway TLS requires CA, certificate and key")
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("relayclient: read guest gateway CA: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("relayclient: guest gateway CA contains no certificates")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("relayclient: load guest gateway client identity: %w", err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{cert}}, nil
}

// TargetTLSConfigFromEnvironment loads the companion's client identity and
// trust anchor for the paired workload's relay-target mTLS bridge. An entirely
// unset triplet selects the legacy local Unix-socket transport; partial
// configuration is rejected.
func TargetTLSConfigFromEnvironment() (*tls.Config, error) {
	caPath := strings.TrimSpace(os.Getenv(relaytarget.EnvServerCA))
	certPath := strings.TrimSpace(os.Getenv(relaytarget.EnvClientCert))
	keyPath := strings.TrimSpace(os.Getenv(relaytarget.EnvClientKey))
	if caPath == "" && certPath == "" && keyPath == "" {
		return nil, nil
	}
	if caPath == "" || certPath == "" || keyPath == "" {
		return nil, errors.New("relayclient: target bridge TLS requires server CA, client certificate, and client key")
	}
	if !filepath.IsAbs(caPath) || filepath.Clean(caPath) != caPath || !filepath.IsAbs(certPath) || filepath.Clean(certPath) != certPath || !filepath.IsAbs(keyPath) || filepath.Clean(keyPath) != keyPath {
		return nil, errors.New("relayclient: target bridge TLS paths must be clean absolute paths")
	}
	if filepath.Dir(caPath) != filepath.Dir(certPath) || filepath.Dir(certPath) != filepath.Dir(keyPath) || filepath.Dir(certPath) == "/" {
		return nil, errors.New("relayclient: target bridge TLS credentials must share one private directory")
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("relayclient: read target bridge server CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("relayclient: target bridge server CA contains no certificates")
	}
	identity, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("relayclient: load target bridge client identity: %w", err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{identity}}, nil
}

// SupervisorControlServerTLSConfigFromEnvironment loads the per-sandbox mTLS
// identity mounted into the trusted supervisor process.
func SupervisorControlServerTLSConfigFromEnvironment() (*tls.Config, error) {
	return supervisorcontrol.ServerTLSConfigFromEnvironment()
}
