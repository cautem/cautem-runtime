package relayclient

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cautem/cautem-core/relayproto"
	"github.com/cautem/cautem-runtime/relaytarget"
)

func TestTargetBridgeMutualTLSRelaysLoopbackTCPAndSSH(t *testing.T) {
	serverTLS, clientTLS := targetBridgeTLSConfigs(t)
	t.Run("loopback TCP", func(t *testing.T) {
		echo := startTCPEcho(t)
		bridge, err := relaytarget.ListenTLS("127.0.0.1:0", serverTLS, "")
		if err != nil {
			t.Fatal(err)
		}
		defer bridge.Close()

		conn, err := dialSandboxTargetTLS(context.Background(), bridge.Addr().String(), clientTLS, "tcp://"+echo.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		assertEcho(t, conn)
	})

	t.Run("SSH Unix socket", func(t *testing.T) {
		sshDir, err := os.MkdirTemp("", "cautem-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(sshDir) })
		sshPath := filepath.Join(sshDir, "sshd.sock")
		sshListener, err := net.Listen("unix", sshPath)
		if err != nil {
			t.Fatal(err)
		}
		defer sshListener.Close()
		go echoConnections(sshListener)

		bridge, err := relaytarget.ListenTLS("127.0.0.1:0", serverTLS, sshPath)
		if err != nil {
			t.Fatal(err)
		}
		defer bridge.Close()

		conn, err := dialSandboxTargetTLS(context.Background(), bridge.Addr().String(), clientTLS, relayproto.TargetSSH)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		assertEcho(t, conn)
	})
}

func TestTargetBridgeRejectsUnauthenticatedClientAndNonLoopbackTarget(t *testing.T) {
	serverTLS, clientTLS := targetBridgeTLSConfigs(t)
	sshDir, err := os.MkdirTemp("", "cautem-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sshDir) })
	sshListener, err := net.Listen("unix", filepath.Join(sshDir, "sshd.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer sshListener.Close()
	go echoConnections(sshListener)
	bridge, err := relaytarget.ListenTLS("127.0.0.1:0", serverTLS, sshListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()

	unauthenticated := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: clientTLS.RootCAs}
	conn, err := tls.Dial("tcp", bridge.Addr().String(), unauthenticated)
	if err == nil {
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if _, writeErr := io.WriteString(conn, relayproto.TargetSSH+"\n"); writeErr == nil {
			ack, readErr := bufio.NewReader(conn).ReadString('\n')
			if readErr == nil && ack == "OK\n" {
				t.Fatal("unauthenticated TLS client was accepted")
			}
		}
	}

	if _, err := dialSandboxTargetTLS(context.Background(), bridge.Addr().String(), clientTLS, "tcp://192.0.2.1:80"); err == nil {
		t.Fatal("non-loopback target was accepted")
	}
}

func TestTargetBridgeRequiresMutualTLSServerConfiguration(t *testing.T) {
	if _, err := relaytarget.ListenTLS("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{}}}, ""); err == nil {
		t.Fatal("TLS listener without verified client certificates was accepted")
	}
}

func TestValidateTargetTransport(t *testing.T) {
	validTLS := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      x509.NewCertPool(),
		Certificates: []tls.Certificate{{}},
	}
	tests := []struct {
		name string
		cfg  Config
		want bool
	}{
		{name: "legacy local socket", cfg: Config{TargetDialSocket: "/run/target.sock"}},
		{name: "valid mTLS endpoint", cfg: Config{TargetDialEndpoint: "workload.default.svc:5500", TargetTLSConfig: validTLS}},
		{name: "endpoint needs credentials", cfg: Config{TargetDialEndpoint: "workload.default.svc:5500"}, want: true},
		{name: "transport choices are exclusive", cfg: Config{TargetDialSocket: "/run/target.sock", TargetDialEndpoint: "workload.default.svc:5500", TargetTLSConfig: validTLS}, want: true},
		{name: "TLS config needs endpoint", cfg: Config{TargetTLSConfig: validTLS}, want: true},
		{name: "scheme rejected", cfg: Config{TargetDialEndpoint: "https://workload.default.svc:5500", TargetTLSConfig: validTLS}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cfg.ValidateTargetTransport(); (err != nil) != tt.want {
				t.Fatalf("ValidateTargetTransport() error = %v, want error %t", err, tt.want)
			}
		})
	}
}

func TestRunSupervisorGRPCRejectsTargetEndpointWithoutTLSBeforeConnecting(t *testing.T) {
	err := RunSupervisorGRPC(context.Background(), Config{TargetDialEndpoint: "workload.default.svc:5500"})
	if err == nil || !strings.Contains(err.Error(), "requires mutual TLS credentials") {
		t.Fatalf("RunSupervisorGRPC() error = %v, want missing target mTLS credentials", err)
	}
}

func targetBridgeTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "relay target test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	serverIdentity := targetBridgeCertificate(t, caCert, caKey, now, x509.ExtKeyUsageServerAuth)
	clientIdentity := targetBridgeCertificate(t, caCert, caKey, now, x509.ExtKeyUsageClientAuth)
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverIdentity},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
	}, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{clientIdentity},
		RootCAs:      roots,
	}
}

func targetBridgeCertificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, now time.Time, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: "relay target bridge"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey})
	identity, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func startTCPEcho(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go echoConnections(listener)
	return listener
}

func echoConnections(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}()
	}
}

func assertEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	payload := []byte("cautem-bridge")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo=%q, want %q", got, payload)
	}
}
