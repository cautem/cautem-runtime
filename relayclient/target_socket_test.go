package relayclient

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cautem/quarshell-core/relayproto"
	"github.com/cautem/quarshell-runtime/relaytarget"
)

func TestConfigDelegatesLoopbackDialIntoSandbox(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		conn, err := echo.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	tempDir, err := os.MkdirTemp("", "wst-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	socket := filepath.Join(tempDir, "f.sock")
	server, err := relaytarget.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	cfg := Config{SSHSocket: filepath.Join(t.TempDir(), "ssh.sock"), TargetDialSocket: socket}
	cfg.defaults()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, portText, err := net.SplitHostPort(echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	targetPort, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := cfg.DialTarget(ctx, "tcp://127.0.0.1:"+strconv.Itoa(targetPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	const payload = "sidecar-to-sandbox"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != payload {
		t.Fatalf("sandbox loopback roundtrip=%q err=%v", got, err)
	}
}

func TestConfigKeepsSSHOnOriginalDialerWhenSandboxDialSocketSet(t *testing.T) {
	calls := 0
	want, peer := net.Pipe()
	defer want.Close()
	defer peer.Close()
	cfg := Config{
		SSHSocket:        "/run/ssh.sock",
		TargetDialSocket: "/run/tcp-forward.sock",
		DialTarget: func(_ context.Context, target string) (net.Conn, error) {
			if target != relayproto.TargetSSH {
				t.Fatalf("target=%q; want SSH target", target)
			}
			calls++
			return want, nil
		},
	}
	cfg.defaults()
	got, err := cfg.DialTarget(context.Background(), relayproto.TargetSSH)
	if err != nil || got != want || calls != 1 {
		t.Fatalf("SSH dial got=%v err=%v calls=%d", got, err, calls)
	}
}

func TestConfigFailsClosedWhenSandboxDialSocketIsMissing(t *testing.T) {
	cfg := Config{SSHSocket: "/run/ssh.sock"}
	cfg.defaults()
	if conn, err := cfg.DialTarget(context.Background(), "tcp://127.0.0.1:8080"); err == nil {
		_ = conn.Close()
		t.Fatal("TCP target unexpectedly dialed the proxy sidecar loopback")
	}
}
