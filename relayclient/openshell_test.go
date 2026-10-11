package relayclient

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type refreshSessionServer struct {
	openshellv1.UnimplementedOpenShellServer
	refreshes atomic.Int32
}

func (s *refreshSessionServer) ConnectSupervisor(stream openshellv1.OpenShell_ConnectSupervisorServer) error {
	message, err := stream.Recv()
	if err != nil {
		return err
	}
	if message.GetHello() == nil {
		return errMissingSupervisorHello
	}
	if err := stream.Send(&openshellv1.GatewayMessage{Payload: &openshellv1.GatewayMessage_SessionAccepted{SessionAccepted: &openshellv1.SessionAccepted{HeartbeatIntervalSecs: 60}}}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

func (s *refreshSessionServer) RefreshSandboxToken(context.Context, *openshellv1.RefreshSandboxTokenRequest) (*openshellv1.RefreshSandboxTokenResponse, error) {
	n := s.refreshes.Add(1)
	return &openshellv1.RefreshSandboxTokenResponse{Token: "refreshed-token-" + strconv.Itoa(int(n))}, nil
}

var errMissingSupervisorHello = errors.New("missing supervisor hello")

func TestOpenShellSessionRefreshesSupervisorToken(t *testing.T) {
	const bufferSize = 1 << 20
	listener := bufconn.Listen(bufferSize)
	server := grpc.NewServer()
	backend := &refreshSessionServer{}
	openshellv1.RegisterOpenShellServer(server, backend)
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()

	conn, err := grpc.NewClient("passthrough:///bufconn", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := openshellv1.NewOpenShellClient(conn)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	instance := newOpenShellInstance("instance-1")
	token := newSupervisorToken("initial-token")
	cfg := Config{Sandbox: "sandbox-1", Log: slog.New(slog.NewTextHandler(io.Discard, nil)), TokenRefreshInterval: 20 * time.Millisecond}
	done := make(chan error, 1)
	go func() {
		done <- openShellSession(ctx, client, cfg, "instance-1", instance, token)
	}()
	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for backend.refreshes.Load() < 2 {
		select {
		case err := <-done:
			t.Fatalf("openShellSession returned before refreshing the token: %v", err)
		case <-deadline:
			t.Fatal("timed out waiting for supervisor token refreshes")
		case <-ticker.C:
		}
	}
	if got := token.get(); got == "initial-token" {
		t.Fatal("supervisor token was not replaced after RefreshSandboxToken")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("openShellSession did not stop after context cancellation")
	}
}
