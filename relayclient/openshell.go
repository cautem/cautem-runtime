package relayclient

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strconv"
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

// runOpenShell speaks the pinned OpenShell ConnectSupervisor and RelayStream
// gRPC protocol. It is selected when GatewayGRPCEndpoint is configured.
func runOpenShell(ctx context.Context, cfg Config) error {
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
		return fmt.Errorf("relayclient: OpenShell gateway connection: %w", err)
	}
	defer conn.Close()
	client := openshellv1.NewOpenShellClient(conn)
	instanceID, err := newInstanceID()
	if err != nil {
		return fmt.Errorf("relayclient: create supervisor instance id: %w", err)
	}
	instance := newOpenShellInstance(instanceID)
	token := newSupervisorToken(cfg.Token)
	controlServer, err := startLifecycleControl(ctx, cfg, client, instance, token)
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
		err = openShellSession(sessionCtx, client, cfg, instanceID, instance, token)
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
		cfg.Log.Warn("OpenShell supervisor session ended", slog.String("op", "supervisor.reconnect"), slog.String("sandbox", cfg.Sandbox), slog.Duration("backoff", backoff), slogx.Err(err))
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

// RunOpenShell starts the pinned OpenShell supervisor/relay protocol. It is
// exposed for black-box integration tests and for embedders that need the
// OpenShell transport directly.
func RunOpenShell(ctx context.Context, cfg Config) error {
	return runOpenShell(ctx, cfg)
}

type openShellInstance struct {
	mu              sync.Mutex
	value           string
	changed         chan struct{}
	connectedID     string
	connectionEvent chan struct{}
}

func newOpenShellInstance(value string) *openShellInstance {
	return &openShellInstance{value: value, changed: make(chan struct{}), connectionEvent: make(chan struct{})}
}

func (i *openShellInstance) snapshot() (string, <-chan struct{}) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.value, i.changed
}

func (i *openShellInstance) current() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.value
}

func (i *openShellInstance) rotate(value string) {
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

func (i *openShellInstance) markConnected(id string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.value != id || i.connectedID == id {
		return
	}
	i.connectedID = id
	close(i.connectionEvent)
	i.connectionEvent = make(chan struct{})
}

func (i *openShellInstance) markDisconnected(id string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.connectedID != id {
		return
	}
	i.connectedID = ""
	close(i.connectionEvent)
	i.connectionEvent = make(chan struct{})
}

func (i *openShellInstance) waitConnected(ctx context.Context, id string) error {
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

func startLifecycleControl(ctx context.Context, cfg Config, client openshellv1.OpenShellClient, instance *openShellInstance, token *supervisorToken) (*supervisorcontrol.Server, error) {
	if strings.TrimSpace(cfg.SupervisorControlSocket) == "" {
		return nil, nil
	}
	return supervisorcontrol.Start(ctx, cfg.SupervisorControlSocket, func(parent context.Context, request supervisorcontrol.Request) supervisorcontrol.Response {
		switch request.Operation {
		case supervisorcontrol.OperationBegin:
			id, err := newInstanceID()
			if err != nil {
				return supervisorcontrol.Response{Error: "could not create supervisor instance id"}
			}
			instance.rotate(id)
			return supervisorcontrol.Response{InstanceID: id}
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
	})
}

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
func GRPCTarget(endpoint string) (string, bool, error) {
	return grpcTarget(endpoint)
}

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

func newInstanceID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

type supervisorControl struct {
	stream openshellv1.OpenShell_ConnectSupervisorClient
	mu     sync.Mutex
}

func (c *supervisorControl) send(message *openshellv1.SupervisorMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stream.Send(message)
}

func openShellSession(ctx context.Context, client openshellv1.OpenShellClient, cfg Config, instanceID string, instance *openShellInstance, token *supervisorToken) error {
	sessionCtx, sessionCancel := context.WithCancel(ctx)
	defer sessionCancel()
	if token.get() == "" {
		return errors.New("supervisor token is required")
	}
	sessionCtx = metadata.NewOutgoingContext(sessionCtx, metadata.Pairs("authorization", "Bearer "+token.get()))
	stream, err := client.ConnectSupervisor(sessionCtx)
	if err != nil {
		return err
	}
	control := &supervisorControl{stream: stream}
	if err := control.send(&openshellv1.SupervisorMessage{Payload: &openshellv1.SupervisorMessage_Hello{Hello: &openshellv1.SupervisorHello{SandboxId: cfg.Sandbox, InstanceId: instanceID}}}); err != nil {
		return err
	}
	accepted, err := stream.Recv()
	if err != nil {
		return err
	}
	if rejected := accepted.GetSessionRejected(); rejected != nil {
		return fmt.Errorf("gateway rejected supervisor session: %s", rejected.GetReason())
	}
	if accepted.GetSessionAccepted() == nil {
		return errors.New("gateway did not accept OpenShell supervisor session")
	}
	instance.markConnected(instanceID)
	defer instance.markDisconnected(instanceID)
	if cfg.OnConnected != nil {
		cfg.OnConnected()
	}
	interval := time.Duration(accepted.GetSessionAccepted().GetHeartbeatIntervalSecs()) * time.Second
	if interval <= 0 {
		interval = 15 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	refreshTicker := time.NewTicker(cfg.TokenRefreshInterval)
	defer refreshTicker.Stop()
	type receiveResult struct {
		message *openshellv1.GatewayMessage
		err     error
	}
	received := make(chan receiveResult, 1)
	go func() {
		for {
			message, recvErr := stream.Recv()
			select {
			case received <- receiveResult{message: message, err: recvErr}:
			case <-sessionCtx.Done():
				return
			}
			if recvErr != nil {
				return
			}
		}
	}()
	cfg.Log.Info("OpenShell supervisor connected", "op", "supervisor.connect", "sandbox", cfg.Sandbox, "instance", instanceID)
	for {
		select {
		case <-sessionCtx.Done():
			return nil
		case <-ticker.C:
			if err := control.send(&openshellv1.SupervisorMessage{Payload: &openshellv1.SupervisorMessage_Heartbeat{Heartbeat: &openshellv1.SupervisorHeartbeat{}}}); err != nil {
				return err
			}
		case <-refreshTicker.C:
			refreshCtx, cancel := context.WithTimeout(sessionCtx, 15*time.Second)
			response, refreshErr := client.RefreshSandboxToken(metadata.NewOutgoingContext(refreshCtx, metadata.Pairs("authorization", "Bearer "+token.get())), &openshellv1.RefreshSandboxTokenRequest{})
			cancel()
			if refreshErr != nil {
				return fmt.Errorf("refresh supervisor token: %w", refreshErr)
			}
			if err := token.set(response.GetToken()); err != nil {
				return err
			}
			cfg.Log.Debug("OpenShell supervisor token refreshed", "op", "supervisor.token.refresh", "sandbox", cfg.Sandbox)
		case result := <-received:
			if result.err != nil {
				return result.err
			}
			if open := result.message.GetRelayOpen(); open != nil {
				go openShellRelay(sessionCtx, client, control, cfg, token, open)
				continue
			}
			if result.message.GetHeartbeat() != nil {
				continue
			}
			if closeMessage := result.message.GetRelayClose(); closeMessage != nil {
				continue // RelayStream owns the channel lifetime.
			}
			return errors.New("gateway sent an unsupported OpenShell supervisor message")
		}
	}
}

func openShellRelay(ctx context.Context, client openshellv1.OpenShellClient, control *supervisorControl, cfg Config, token *supervisorToken, open *openshellv1.RelayOpen) {
	channelID := open.GetChannelId()
	target := relayproto.TargetSSH
	if tcp := open.GetTcp(); tcp != nil {
		if tcp.GetPort() == 0 || tcp.GetPort() > 65535 {
			sendOpenResult(control, channelID, errors.New("invalid TCP relay port"))
			return
		}
		target = "tcp://" + net.JoinHostPort(tcp.GetHost(), strconv.FormatUint(uint64(tcp.GetPort()), 10))
	}
	dctx, cancel := context.WithTimeout(ctx, relayDialTimeout)
	defer cancel()
	targetConn, err := cfg.DialTarget(dctx, target)
	if err != nil {
		sendOpenResult(control, channelID, err)
		return
	}
	defer targetConn.Close()
	streamCtx, streamCancel := context.WithCancel(ctx)
	defer streamCancel()
	streamCtx = metadata.NewOutgoingContext(streamCtx, metadata.Pairs("authorization", "Bearer "+token.get()))
	stream, err := client.RelayStream(streamCtx)
	if err != nil {
		sendOpenResult(control, channelID, err)
		return
	}
	if err := stream.Send(&openshellv1.RelayFrame{Payload: &openshellv1.RelayFrame_Init{Init: &openshellv1.RelayInit{ChannelId: channelID}}}); err != nil {
		sendOpenResult(control, channelID, err)
		return
	}
	if err := control.send(&openshellv1.SupervisorMessage{Payload: &openshellv1.SupervisorMessage_RelayOpenResult{RelayOpenResult: &openshellv1.RelayOpenResult{ChannelId: channelID, Success: true}}}); err != nil {
		return
	}
	sendDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, readErr := targetConn.Read(buf)
			if n > 0 {
				if sendErr := stream.Send(&openshellv1.RelayFrame{Payload: &openshellv1.RelayFrame_Data{Data: append([]byte(nil), buf[:n]...)}}); sendErr != nil {
					sendDone <- sendErr
					return
				}
			}
			if readErr != nil {
				if readErr == io.EOF {
					sendDone <- stream.CloseSend()
				} else {
					sendDone <- readErr
				}
				return
			}
		}
	}()
	for {
		frame, recvErr := stream.Recv()
		if recvErr != nil {
			if recvErr == io.EOF {
				if half, ok := targetConn.(interface{ CloseWrite() error }); ok {
					_ = half.CloseWrite()
				}
				if sendErr := <-sendDone; sendErr != nil && !errors.Is(sendErr, io.EOF) {
					cfg.Log.Debug("OpenShell relay send completed with error", "channel", channelID, "error", sendErr)
				}
				return
			}
			streamCancel()
			return
		}
		data := frame.GetData()
		for len(data) > 0 {
			n, writeErr := targetConn.Write(data)
			if writeErr != nil {
				streamCancel()
				return
			}
			data = data[n:]
		}
	}
}

func sendOpenResult(control *supervisorControl, channelID string, cause error) {
	if cause == nil {
		return
	}
	_ = control.send(&openshellv1.SupervisorMessage{Payload: &openshellv1.SupervisorMessage_RelayOpenResult{RelayOpenResult: &openshellv1.RelayOpenResult{ChannelId: channelID, Error: cause.Error()}}})
}
