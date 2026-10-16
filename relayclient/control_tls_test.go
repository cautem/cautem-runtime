package relayclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/cautem/quarshell-runtime/supervisorcontrol"
)

func TestLifecycleControlServesRemoteWorkloadOverMTLS(t *testing.T) {
	ca, caKey := newControlTestCA(t)
	serverCert := newControlTestCert(t, ca, caKey, true)
	clientCert := newControlTestCert(t, ca, caKey, false)
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(ca)
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(ca)

	instance := newSupervisorInstance("initial-instance")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, err := startLifecycleControl(ctx, Config{
		SupervisorControlAddress: "127.0.0.1:0",
		SupervisorControlTLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCAs,
		},
		Sandbox: "sandbox-1",
	}, nil, instance, newSupervisorToken("sandbox-token"), make(chan processEventItem, 1))
	if err != nil {
		t.Fatalf("startLifecycleControl() error = %v", err)
	}
	if server == nil {
		t.Fatal("startLifecycleControl() returned no server")
	}
	t.Cleanup(func() { _ = server.Close() })

	clientTLS := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      serverRoots,
		ServerName:   "localhost",
	}
	callCtx, callCancel := context.WithTimeout(ctx, 3*time.Second)
	defer callCancel()
	response, err := supervisorcontrol.CallTLS(callCtx, server.Addr().String(), clientTLS, supervisorcontrol.Request{Operation: supervisorcontrol.OperationBegin})
	if err != nil {
		t.Fatalf("CallTLS(begin) error = %v", err)
	}
	if response.InstanceID == "" || instance.current() != response.InstanceID {
		t.Fatalf("remote begin returned instance %q, active instance is %q", response.InstanceID, instance.current())
	}
}

func newControlTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(CA) error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "control-test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate(CA) error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(CA) error = %v", err)
	}
	return cert, key
}

func newControlTestCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, server bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(peer) error = %v", err)
	}
	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "control-test-peer"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usage,
	}
	if server {
		template.DNSNames = []string{"localhost"}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate(peer) error = %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
