package relayclient

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/cautem/cautem-core/relayproto"
)

// ValidateTargetTransport checks mutually exclusive target relay settings and
// verifies the mTLS configuration required by a remote workload bridge.
func (cfg Config) ValidateTargetTransport() error {
	if cfg.DialTarget != nil {
		return nil
	}
	endpoint := strings.TrimSpace(cfg.TargetDialEndpoint)
	socket := strings.TrimSpace(cfg.TargetDialSocket)
	if endpoint != "" && socket != "" {
		return errors.New("relayclient: configure either an mTLS target endpoint or a Unix target socket")
	}
	if endpoint == "" {
		if cfg.TargetTLSConfig != nil {
			return errors.New("relayclient: target bridge TLS credentials require a target endpoint")
		}
		return nil
	}
	if _, _, err := splitTargetEndpoint(endpoint); err != nil {
		return err
	}
	if cfg.TargetTLSConfig == nil {
		return errors.New("relayclient: target endpoint requires mutual TLS credentials")
	}
	config := cfg.TargetTLSConfig
	if config.MinVersion != 0 && config.MinVersion < tls.VersionTLS12 || config.InsecureSkipVerify || config.RootCAs == nil || len(config.Certificates) == 0 && config.GetClientCertificate == nil {
		return errors.New("relayclient: target bridge requires TLS 1.2+, verified server certificates, and a client identity")
	}
	return nil
}

func splitTargetEndpoint(endpoint string) (string, string, error) {
	if strings.Contains(endpoint, "://") {
		return "", "", errors.New("relayclient: target bridge endpoint must be host:port")
	}
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil || strings.TrimSpace(host) == "" {
		return "", "", errors.New("relayclient: target bridge endpoint must be host:port")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", "", errors.New("relayclient: target bridge endpoint port must be between 1 and 65535")
	}
	return host, strconv.FormatUint(port, 10), nil
}

func dialSandboxTargetTLS(ctx context.Context, endpoint string, config *tls.Config, target string) (net.Conn, error) {
	if target != relayproto.TargetSSH {
		if _, err := validateLoopbackTarget(target); err != nil {
			return nil, err
		}
	}
	if _, _, err := splitTargetEndpoint(endpoint); err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errors.New("relayclient: target bridge mutual TLS configuration is required")
	}
	tlsConfig := config.Clone()
	if tlsConfig.MinVersion == 0 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	if tlsConfig.MinVersion < tls.VersionTLS12 || tlsConfig.InsecureSkipVerify || tlsConfig.RootCAs == nil || len(tlsConfig.Certificates) == 0 && tlsConfig.GetClientCertificate == nil {
		return nil, errors.New("relayclient: target bridge TLS 1.2+, server verification, and a client identity are required")
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{}, Config: tlsConfig}
	conn, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("relayclient: connect to workload target bridge: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	}
	if _, err := fmt.Fprintf(conn, "%s\n", target); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("relayclient: send target bridge request: %w", err)
	}
	ack, err := bufio.NewReaderSize(conn, 128).ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("relayclient: read target bridge acknowledgement: %w", err)
	}
	if ack != "OK\n" {
		_ = conn.Close()
		return nil, errors.New("relayclient: workload target is unavailable")
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}
