package relayclient

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc/metadata"
)

// runOpenShell speaks the pinned OpenShell ConnectSupervisor and RelayStream
// gRPC protocol. It is selected when GatewayGRPCEndpoint is configured.

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
