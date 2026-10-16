package relayclient

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-core/relayproto"
	"github.com/cautem/cautem-runtime/supervisorcontrol"
	"github.com/cautem/slogx"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// runSupervisorGRPC speaks the Gateway supervisor and relay gRPC
// gRPC protocol. It is selected when GatewayGRPCEndpoint is configured.

func runSupervisorGRPC(ctx context.Context, cfg Config) error {
	if err := cfg.ValidateTargetTransport(); err != nil {
		return err
	}
	cfg.defaults()
	target, secure, err := grpcTarget(cfg.GatewayGRPCEndpoint)
	if err != nil {
		return err
	}
	transport := credentials.TransportCredentials(insecure.NewCredentials())
	if secure {
		tlsConfig := cfg.TLSConfig
		if tlsConfig == nil {
			tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		transport = credentials.NewTLS(tlsConfig.Clone())
	}
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(transport))
	if err != nil {
		return fmt.Errorf("relayclient: Gateway gRPC connection: %w", err)
	}
	defer conn.Close()
	client := openshellv1.NewOpenShellClient(conn)
	instanceID, err := newInstanceID()
	if err != nil {
		return fmt.Errorf("relayclient: create supervisor instance id: %w", err)
	}
	instance := newSupervisorInstance(instanceID)
	token := newSupervisorToken(cfg.Token)
	processEvents := make(chan processEventItem, 256)
	go runProcessEventPusher(ctx, cfg, client, token, processEvents)
	controlServer, err := startLifecycleControl(ctx, cfg, client, instance, token, processEvents)
	if err != nil {
		return err
	}
	defer controlServer.Close()
	backoff := cfg.MinBackoff
	for {
		instanceID, changed := instance.snapshot()
		started := time.Now()
		sessionCtx, sessionCancel := context.WithCancel(ctx)
		go func() {
			select {
			case <-changed:
				sessionCancel()
			case <-sessionCtx.Done():
			}
		}()
		err = supervisorSession(sessionCtx, client, cfg, instanceID, instance, token)
		sessionCancel()
		if ctx.Err() != nil {
			return nil
		}
		if instance.current() != instanceID {
			continue
		}
		if time.Since(started) > 2*relayproto.KeepaliveTimeout {
			backoff = cfg.MinBackoff
		}
		cfg.Log.Warn("supervisor gRPC session ended", slog.String("op", "supervisor.reconnect"), slog.String("sandbox", cfg.Sandbox), slog.Duration("backoff", backoff), slogx.Err(err))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > cfg.MaxBackoff {
			backoff = cfg.MaxBackoff
		}
	}
}

type supervisorToken struct {
	mu    sync.RWMutex
	value string
}

func newSupervisorToken(value string) *supervisorToken {
	return &supervisorToken{value: strings.TrimSpace(value)}
}

func (t *supervisorToken) get() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.value
}

func (t *supervisorToken) set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("supervisor token refresh returned an empty token")
	}
	t.mu.Lock()
	t.value = value
	t.mu.Unlock()
	return nil
}

// RunSupervisorGRPC starts the Gateway supervisor/relay gRPC protocol. It is
// exposed for black-box integration tests and for embedders that need the
// OpenShell transport directly.

// RunSupervisorGRPC starts the Gateway supervisor/relay gRPC protocol. It is
// exposed for black-box integration tests and for embedders that need the
// OpenShell transport directly.
func RunSupervisorGRPC(ctx context.Context, cfg Config) error {
	return runSupervisorGRPC(ctx, cfg)
}

type supervisorInstance struct {
	mu              sync.Mutex
	value           string
	changed         chan struct{}
	connectedID     string
	connectionEvent chan struct{}
}

func newSupervisorInstance(value string) *supervisorInstance {
	return &supervisorInstance{value: value, changed: make(chan struct{}), connectionEvent: make(chan struct{})}
}

func (i *supervisorInstance) snapshot() (string, <-chan struct{}) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.value, i.changed
}

func (i *supervisorInstance) current() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.value
}

func (i *supervisorInstance) rotate(value string) {
	i.mu.Lock()
	old := i.changed
	oldConnection := i.connectionEvent
	i.value = value
	i.connectedID = ""
	i.changed = make(chan struct{})
	i.connectionEvent = make(chan struct{})
	close(old)
	close(oldConnection)
	i.mu.Unlock()
}

func (i *supervisorInstance) markConnected(id string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.value != id || i.connectedID == id {
		return
	}
	i.connectedID = id
	close(i.connectionEvent)
	i.connectionEvent = make(chan struct{})
}

func (i *supervisorInstance) markDisconnected(id string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.connectedID != id {
		return
	}
	i.connectedID = ""
	close(i.connectionEvent)
	i.connectionEvent = make(chan struct{})
}

func (i *supervisorInstance) waitConnected(ctx context.Context, id string) error {
	for {
		i.mu.Lock()
		if i.value != id {
			i.mu.Unlock()
			return errors.New("supervisor instance is stale")
		}
		if i.connectedID == id {
			i.mu.Unlock()
			return nil
		}
		changed := i.connectionEvent
		i.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

func startLifecycleControl(ctx context.Context, cfg Config, client openshellv1.OpenShellClient, instance *supervisorInstance, token *supervisorToken, processEvents chan<- processEventItem) (*supervisorcontrol.Server, error) {
	socket := strings.TrimSpace(cfg.SupervisorControlSocket)
	address := strings.TrimSpace(cfg.SupervisorControlAddress)
	if socket != "" && address != "" {
		return nil, errors.New("relayclient: configure either a supervisor control socket or mTLS address")
	}
	if socket == "" && address == "" {
		return nil, nil
	}
	handler := func(parent context.Context, request supervisorcontrol.Request) supervisorcontrol.Response {
		switch request.Operation {
		case supervisorcontrol.OperationBegin:
			id, err := newInstanceID()
			if err != nil {
				return supervisorcontrol.Response{Error: "could not create supervisor instance id"}
			}
			instance.rotate(id)
			return supervisorcontrol.Response{InstanceID: id}
		case supervisorcontrol.OperationProcess:
			id := instance.current()
			if request.InstanceID == "" || request.InstanceID != id {
				return supervisorcontrol.Response{Error: "supervisor instance is stale"}
			}
			if request.Process == nil || request.Process.InstanceID != id || !validSupervisorProcessEvent(request.Process) {
				return supervisorcontrol.Response{Error: "invalid supervisor process event"}
			}
			event := *request.Process
			select {
			case <-parent.Done():
				return supervisorcontrol.Response{Error: parent.Err().Error()}
			case processEvents <- processEventItem{event: &event}:
				return supervisorcontrol.Response{InstanceID: id}
			}
		case supervisorcontrol.OperationFlush:
			id := instance.current()
			if request.InstanceID == "" || request.InstanceID != id {
				return supervisorcontrol.Response{Error: "supervisor instance is stale"}
			}
			flushed := make(chan error, 1)
			select {
			case <-parent.Done():
				return supervisorcontrol.Response{Error: parent.Err().Error()}
			case processEvents <- processEventItem{flushed: flushed}:
			}
			select {
			case <-parent.Done():
				return supervisorcontrol.Response{Error: parent.Err().Error()}
			case err := <-flushed:
				if err != nil {
					return supervisorcontrol.Response{Error: err.Error()}
				}
				return supervisorcontrol.Response{InstanceID: id}
			}
		case supervisorcontrol.OperationReport, supervisorcontrol.OperationFinalize:
			id := instance.current()
			if request.InstanceID == "" || request.InstanceID != id {
				return supervisorcontrol.Response{Error: "supervisor instance is stale"}
			}
			callCtx, cancel := context.WithTimeout(parent, 15*time.Second)
			defer cancel()
			if err := instance.waitConnected(callCtx, id); err != nil {
				return supervisorcontrol.Response{Error: err.Error()}
			}
			callCtx = metadata.NewOutgoingContext(callCtx, metadata.Pairs("authorization", "Bearer "+token.get()))
			if request.Operation == supervisorcontrol.OperationReport {
				_, err := client.ReportMainProcessExit(callCtx, &openshellv1.ReportMainProcessExitRequest{SandboxId: cfg.Sandbox, InstanceId: id, ExitCode: request.ExitCode})
				if err != nil {
					return supervisorcontrol.Response{Error: err.Error()}
				}
				return supervisorcontrol.Response{InstanceID: id}
			}
			_, err := client.FinalizeMainProcessExit(callCtx, &openshellv1.FinalizeMainProcessExitRequest{SandboxId: cfg.Sandbox, InstanceId: id})
			if err != nil {
				return supervisorcontrol.Response{Error: err.Error()}
			}
			return supervisorcontrol.Response{InstanceID: id}
		default:
			return supervisorcontrol.Response{Error: "unsupported supervisor lifecycle operation"}
		}
	}
	if address != "" {
		if cfg.SupervisorControlTLSConfig == nil {
			return nil, errors.New("relayclient: supervisor control mTLS configuration is required")
		}
		return supervisorcontrol.StartTLS(ctx, address, cfg.SupervisorControlTLSConfig, handler)
	}
	return supervisorcontrol.Start(ctx, socket, handler)
}

func newInstanceID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
