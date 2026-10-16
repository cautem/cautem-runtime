package relayclient

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/quarshell-runtime/supervisorcontrol"
	"google.golang.org/grpc"
)

type processEventPushReceipt struct {
	request *openshellv1.PushSandboxLogsRequest
	when    time.Time
}

type processEventPushTestClient struct {
	openshellv1.OpenShellClient
	sent chan processEventPushReceipt
}

func (c *processEventPushTestClient) PushSandboxLogs(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[openshellv1.PushSandboxLogsRequest, openshellv1.PushSandboxLogsResponse], error) {
	return &processEventPushTestStream{sent: c.sent}, nil
}

type processEventPushTestStream struct {
	grpc.ClientStream
	sent chan processEventPushReceipt
}

func (s *processEventPushTestStream) Send(request *openshellv1.PushSandboxLogsRequest) error {
	s.sent <- processEventPushReceipt{request: request, when: time.Now()}
	return nil
}

func (s *processEventPushTestStream) CloseAndRecv() (*openshellv1.PushSandboxLogsResponse, error) {
	return &openshellv1.PushSandboxLogsResponse{}, nil
}

type processEventRetryTestClient struct {
	openshellv1.OpenShellClient
	attemptNo atomic.Int32
	attempts  chan int
	sent      chan processEventPushReceipt
}

func (c *processEventRetryTestClient) PushSandboxLogs(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[openshellv1.PushSandboxLogsRequest, openshellv1.PushSandboxLogsResponse], error) {
	attempt := int(c.attemptNo.Add(1))
	c.attempts <- attempt
	if attempt == 1 {
		return nil, errors.New("temporary gateway outage")
	}
	return &processEventRetryTestStream{sent: c.sent}, nil
}

type processEventRetryTestStream struct {
	grpc.ClientStream
	sent chan processEventPushReceipt
}

func (s *processEventRetryTestStream) Send(request *openshellv1.PushSandboxLogsRequest) error {
	s.sent <- processEventPushReceipt{request: request, when: time.Now()}
	return nil
}

func (s *processEventRetryTestStream) CloseAndRecv() (*openshellv1.PushSandboxLogsResponse, error) {
	return &openshellv1.PushSandboxLogsResponse{}, nil
}

func TestProcessEventPusherBatchDelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	processEvents := make(chan processEventItem, 8)
	pushes := make(chan processEventPushReceipt, 1)
	client := &processEventPushTestClient{sent: pushes}
	config := Config{Sandbox: "sandbox-test", Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	done := make(chan struct{})
	go func() {
		runProcessEventPusher(ctx, config, client, newSupervisorToken("test-token"), processEvents)
		close(done)
	}()

	socketDir, err := os.MkdirTemp("", "pe-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socketPath := filepath.Join(socketDir, "s.sock")
	server, err := supervisorcontrol.Start(ctx, socketPath, func(_ context.Context, request supervisorcontrol.Request) supervisorcontrol.Response {
		if request.Operation != supervisorcontrol.OperationProcess || request.Process == nil {
			return supervisorcontrol.Response{Error: "unexpected process event request"}
		}
		processEvents <- processEventItem{event: request.Process}
		return supervisorcontrol.Response{InstanceID: request.InstanceID}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	event := supervisorcontrol.ProcessEvent{
		InstanceID: "instance-test", Activity: "EXIT", PID: 42, ParentPID: 1,
		Executable: "worker", Timestamp: time.Now().UnixMilli(),
	}
	if _, err := supervisorcontrol.Call(ctx, socketPath, supervisorcontrol.Request{
		Operation: supervisorcontrol.OperationProcess, InstanceID: event.InstanceID, Process: &event,
	}); err != nil {
		t.Fatal(err)
	}

	select {
	case receipt := <-pushes:
		latency := receipt.when.Sub(time.UnixMilli(event.Timestamp))
		t.Logf("local supervisor socket to PushSandboxLogs Send: %s (configured batch wait %s)", latency, processEventBatchWait)
		if len(receipt.request.GetLogs()) != 1 || receipt.request.GetLogs()[0].GetFields()["activity"] != "EXIT" {
			t.Fatalf("unexpected pushed process logs: %+v", receipt.request.GetLogs())
		}
		if latency < processEventBatchWait-10*time.Millisecond {
			t.Fatalf("event bypassed the configured batch wait: latency=%s wait=%s", latency, processEventBatchWait)
		}
		if latency > processEventBatchWait+500*time.Millisecond {
			t.Fatalf("event exceeded the batching budget by too much: latency=%s wait=%s", latency, processEventBatchWait)
		}
	case <-time.After(processEventBatchWait + 3*time.Second):
		t.Fatal("process event was not pushed")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("process event pusher did not stop after cancellation")
	}
}

func TestProcessEventPusherRetriesRetainedBatchAfterGatewayRecovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	processEvents := make(chan processEventItem, 1)
	client := &processEventRetryTestClient{
		attempts: make(chan int, 2),
		sent:     make(chan processEventPushReceipt, 1),
	}
	config := Config{Sandbox: "sandbox-test", Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	done := make(chan struct{})
	go func() {
		runProcessEventPusher(ctx, config, client, newSupervisorToken("test-token"), processEvents)
		close(done)
	}()

	event := supervisorcontrol.ProcessEvent{
		InstanceID: "instance-retry", Activity: "EXIT", PID: 73, ParentPID: 1,
		Executable: "retry-worker", Timestamp: time.Now().UnixMilli(),
	}
	processEvents <- processEventItem{event: &event}

	select {
	case attempt := <-client.attempts:
		if attempt != 1 {
			t.Fatalf("first gateway push attempt=%d; want 1", attempt)
		}
	case <-time.After(time.Second):
		t.Fatal("pusher did not attempt delivery to the unavailable gateway")
	}
	select {
	case receipt := <-client.sent:
		t.Fatalf("batch was reported delivered before gateway recovery: %+v", receipt.request.GetLogs())
	case <-time.After(100 * time.Millisecond):
	}

	select {
	case attempt := <-client.attempts:
		if attempt != 2 {
			t.Fatalf("recovery push attempt=%d; want 2", attempt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pusher did not retry after the gateway recovered")
	}
	select {
	case receipt := <-client.sent:
		logs := receipt.request.GetLogs()
		if len(logs) != 1 || logs[0].GetFields()["activity"] != event.Activity || logs[0].GetFields()["pid"] != "73" || logs[0].GetFields()["instance_id"] != event.InstanceID {
			t.Fatalf("recovered gateway received a different batch: %+v", logs)
		}
		t.Logf("gateway recovery retained and delivered the original process event on retry %d", 2)
	case <-time.After(time.Second):
		t.Fatal("recovered gateway did not receive the retained process event")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("process event pusher did not stop after cancellation")
	}
}
