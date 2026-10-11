package integration

import (
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-runtime/relayclient"
	"github.com/cautem/cautem-runtime/supervisorcontrol"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type reconnectService struct {
	openshellv1.UnimplementedOpenShellServer
	connections atomic.Int32
}

func (s *reconnectService) ConnectSupervisor(stream grpc.BidiStreamingServer[openshellv1.SupervisorMessage, openshellv1.GatewayMessage]) error {
	if got, ok := metadata.FromIncomingContext(stream.Context()); !ok || len(got.Get("authorization")) != 1 || got.Get("authorization")[0] != "Bearer sandbox-token" {
		return status.Error(codes.Unauthenticated, "missing sandbox bearer")
	}
	hello, err := stream.Recv()
	if err != nil || hello.GetHello() == nil || hello.GetHello().GetSandboxId() != "sandbox-1" || hello.GetHello().GetInstanceId() == "" {
		return status.Error(codes.InvalidArgument, "invalid supervisor hello")
	}
	if err := stream.Send(&openshellv1.GatewayMessage{Payload: &openshellv1.GatewayMessage_SessionAccepted{SessionAccepted: &openshellv1.SessionAccepted{SessionId: "session", HeartbeatIntervalSecs: 1}}}); err != nil {
		return err
	}
	s.connections.Add(1)
	// Returning closes this accepted stream and forces the client to reconnect.
	return nil
}

func TestOpenShellSupervisorReconnectsAfterControlStreamLoss(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	service := &reconnectService{}
	openshellv1.RegisterOpenShellServer(server, service)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	connected := make(chan struct{}, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- relayclient.Run(ctx, relayclient.Config{
			GatewayGRPCEndpoint: listener.Addr().String(),
			Sandbox:             "sandbox-1",
			Token:               "sandbox-token",
			MinBackoff:          10 * time.Millisecond,
			MaxBackoff:          20 * time.Millisecond,
			OnConnected:         func() { connected <- struct{}{} },
		})
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-connected:
		case <-ctx.Done():
			t.Fatalf("supervisor did not reconnect after control stream loss (handshakes=%d): %v", service.connections.Load(), ctx.Err())
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("relayclient.Run returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("relayclient.Run did not stop after context cancellation")
	}
}

type lifecycleService struct {
	openshellv1.UnimplementedOpenShellServer
	mu          sync.Mutex
	activeID    string
	reported    bool
	finalized   bool
	connectedID chan string
}

func (s *lifecycleService) ConnectSupervisor(stream grpc.BidiStreamingServer[openshellv1.SupervisorMessage, openshellv1.GatewayMessage]) error {
	if got, ok := metadata.FromIncomingContext(stream.Context()); !ok || len(got.Get("authorization")) != 1 || got.Get("authorization")[0] != "Bearer sandbox-token" {
		return status.Error(codes.Unauthenticated, "missing sandbox bearer")
	}
	hello, err := stream.Recv()
	if err != nil || hello.GetHello() == nil || hello.GetHello().GetSandboxId() != "sandbox-1" || hello.GetHello().GetInstanceId() == "" {
		return status.Error(codes.InvalidArgument, "invalid supervisor hello")
	}
	id := hello.GetHello().GetInstanceId()
	s.mu.Lock()
	s.activeID = id
	s.mu.Unlock()
	s.connectedID <- id
	if err := stream.Send(&openshellv1.GatewayMessage{Payload: &openshellv1.GatewayMessage_SessionAccepted{SessionAccepted: &openshellv1.SessionAccepted{SessionId: "session", HeartbeatIntervalSecs: 30}}}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

func (s *lifecycleService) ReportMainProcessExit(ctx context.Context, req *openshellv1.ReportMainProcessExitRequest) (*openshellv1.ReportMainProcessExitResponse, error) {
	if got, ok := metadata.FromIncomingContext(ctx); !ok || len(got.Get("authorization")) != 1 || got.Get("authorization")[0] != "Bearer sandbox-token" {
		return nil, status.Error(codes.Unauthenticated, "missing sandbox bearer")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.GetSandboxId() != "sandbox-1" || req.GetInstanceId() != s.activeID || req.GetExitCode() != 7 {
		return nil, status.Error(codes.FailedPrecondition, "report does not match active process")
	}
	s.reported = true
	return &openshellv1.ReportMainProcessExitResponse{}, nil
}

func (s *lifecycleService) FinalizeMainProcessExit(ctx context.Context, req *openshellv1.FinalizeMainProcessExitRequest) (*openshellv1.FinalizeMainProcessExitResponse, error) {
	if got, ok := metadata.FromIncomingContext(ctx); !ok || len(got.Get("authorization")) != 1 || got.Get("authorization")[0] != "Bearer sandbox-token" {
		return nil, status.Error(codes.Unauthenticated, "missing sandbox bearer")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.GetSandboxId() != "sandbox-1" || req.GetInstanceId() != s.activeID || !s.reported {
		return nil, status.Error(codes.FailedPrecondition, "finalize before report or stale instance")
	}
	s.finalized = true
	return &openshellv1.FinalizeMainProcessExitResponse{}, nil
}

func TestOpenShellSidecarBridgesPID1LifecycleToPinnedGRPC(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := grpc.NewServer()
	service := &lifecycleService{connectedID: make(chan string, 4)}
	openshellv1.RegisterOpenShellServer(grpcServer, service)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(func() { grpcServer.Stop(); _ = listener.Close() })

	tmp, err := os.MkdirTemp(os.TempDir(), "sc-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)
	controlPath := filepath.Join(tmp, "c.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- relayclient.RunOpenShell(ctx, relayclient.Config{
			GatewayGRPCEndpoint:     listener.Addr().String(),
			SupervisorControlSocket: controlPath,
			Sandbox:                 "sandbox-1",
			Token:                   "sandbox-token",
			Log:                     slog.Default(),
			MinBackoff:              10 * time.Millisecond,
			MaxBackoff:              100 * time.Millisecond,
		})
	}()

	var instanceID string
	deadline := time.Now().Add(3 * time.Second)
	for instanceID == "" && time.Now().Before(deadline) {
		callCtx, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
		response, callErr := supervisorcontrol.Call(callCtx, controlPath, supervisorcontrol.Request{Operation: supervisorcontrol.OperationBegin})
		stop()
		if callErr == nil {
			instanceID = response.InstanceID
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if instanceID == "" {
		cancel()
		t.Fatal("sidecar lifecycle control socket did not become ready")
	}
	connectedDeadline := time.After(3 * time.Second)
	for {
		select {
		case got := <-service.connectedID:
			if got == instanceID {
				goto connected
			}
		case <-connectedDeadline:
			cancel()
			t.Fatal("sidecar did not reconnect with PID1 process instance")
		}
	}
connected:
	for _, operation := range []string{supervisorcontrol.OperationReport, supervisorcontrol.OperationFinalize} {
		callCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		_, callErr := supervisorcontrol.Call(callCtx, controlPath, supervisorcontrol.Request{Operation: operation, InstanceID: instanceID, ExitCode: 7})
		stop()
		if callErr != nil {
			cancel()
			t.Fatalf("PID1 %s over pinned gRPC: %v", operation, callErr)
		}
	}
	service.mu.Lock()
	gotReported, gotFinalized := service.reported, service.finalized
	service.mu.Unlock()
	if !gotReported || !gotFinalized {
		t.Fatalf("gateway lifecycle state reported=%v finalized=%v", gotReported, gotFinalized)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runOpenShell returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("sidecar did not stop after context cancellation")
	}
}

func TestGRPCTarget(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
		secure   bool
		wantErr  bool
	}{
		{name: "bare target", endpoint: "gateway.internal:17670", want: "gateway.internal:17670"},
		{name: "h2c URL", endpoint: "http://gateway.internal:17670", want: "gateway.internal:17670"},
		{name: "TLS URL", endpoint: "https://gateway.internal:17670", want: "gateway.internal:17670", secure: true},
		{name: "reject unsupported scheme", endpoint: "ws://gateway.internal:17670", wantErr: true},
		{name: "reject URL path", endpoint: "https://gateway.internal:17670/rpc", wantErr: true},
		{name: "reject credentials", endpoint: "https://user:pass@gateway.internal:17670", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, secure, err := relayclient.GRPCTarget(test.endpoint)
			if (err != nil) != test.wantErr {
				t.Fatalf("grpcTarget(%q) error=%v, wantErr=%t", test.endpoint, err, test.wantErr)
			}
			if err == nil && (got != test.want || secure != test.secure) {
				t.Fatalf("grpcTarget(%q)=(%q,%t), want (%q,%t)", test.endpoint, got, secure, test.want, test.secure)
			}
		})
	}
}

func TestGatewayTLSConfigRequiresCompleteTriplet(t *testing.T) {
	t.Setenv("CAUTEM_GUEST_TLS_CA", "")
	t.Setenv("CAUTEM_GUEST_TLS_CERT", "")
	t.Setenv("CAUTEM_GUEST_TLS_KEY", "")
	if config, err := relayclient.GatewayTLSConfigFromEnvironment(); err != nil || config != nil {
		t.Fatalf("empty TLS environment=(%v,%v), want (nil,nil)", config, err)
	}
	t.Setenv("CAUTEM_GUEST_TLS_CA", "/ca.pem")
	if config, err := relayclient.GatewayTLSConfigFromEnvironment(); err == nil || config != nil {
		t.Fatalf("partial TLS environment=(%v,%v), want error", config, err)
	}
}
