package relayclient

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-runtime/supervisorcontrol"
	"github.com/cautem/slogx"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	processEventBatchSize = 32
	processEventBatchWait = 25 * time.Millisecond
)

type processEventItem struct {
	event   *supervisorcontrol.ProcessEvent
	flushed chan error
}

func validSupervisorProcessEvent(event *supervisorcontrol.ProcessEvent) bool {
	if event == nil || event.PID <= 0 || event.ParentPID < 0 || event.Timestamp <= 0 {
		return false
	}
	if event.Activity != "LAUNCH" && event.Activity != "EXIT" {
		return false
	}
	if event.Executable == "" || len(event.Executable) > 255 || !utf8.ValidString(event.Executable) {
		return false
	}
	return !strings.ContainsAny(event.Executable, "/\\\r\n\x00")
}

func runProcessEventPusher(ctx context.Context, cfg Config, client openshellv1.OpenShellClient, token *supervisorToken, events <-chan processEventItem) {
	for {
		batch, barriers, ok := nextProcessEventBatch(ctx, events)
		if !ok {
			completeProcessEventBarriers(barriers, ctx.Err())
			return
		}
		if len(batch) == 0 {
			completeProcessEventBarriers(barriers, nil)
			continue
		}
		backoff := 500 * time.Millisecond
		loggedFailure := false
		for {
			if err := pushProcessEventBatch(ctx, cfg, client, token, batch); err == nil {
				completeProcessEventBarriers(barriers, nil)
				break
			} else if !loggedFailure {
				cfg.Log.Warn("sandbox process event delivery failed; retaining batch for retry", slog.String("op", "supervisor.process_events.push"), slog.String("sandbox", cfg.Sandbox), slogx.Err(err))
				loggedFailure = true
			}
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				completeProcessEventBarriers(barriers, ctx.Err())
				return
			case <-timer.C:
			}
			if backoff < 5*time.Second {
				backoff *= 2
			}
		}
	}
}

func nextProcessEventBatch(ctx context.Context, events <-chan processEventItem) ([]supervisorcontrol.ProcessEvent, []chan error, bool) {
	var first processEventItem
	select {
	case <-ctx.Done():
		return nil, nil, false
	case item := <-events:
		first = item
	}
	batch := make([]supervisorcontrol.ProcessEvent, 0, processEventBatchSize)
	barriers := make([]chan error, 0, 1)
	if first.event != nil {
		batch = append(batch, *first.event)
	}
	if first.flushed != nil {
		barriers = append(barriers, first.flushed)
	}
	if len(batch) == 0 {
		return batch, barriers, true
	}
	timer := time.NewTimer(processEventBatchWait)
	defer timer.Stop()
	for len(batch) < processEventBatchSize {
		select {
		case <-ctx.Done():
			return batch, barriers, false
		case item := <-events:
			if item.event != nil {
				batch = append(batch, *item.event)
			}
			if item.flushed != nil {
				barriers = append(barriers, item.flushed)
				return batch, barriers, true
			}
		case <-timer.C:
			return batch, barriers, true
		}
	}
	return batch, barriers, true
}

func completeProcessEventBarriers(barriers []chan error, err error) {
	for _, barrier := range barriers {
		select {
		case barrier <- err:
		default:
		}
	}
}

func pushProcessEventBatch(ctx context.Context, cfg Config, client openshellv1.OpenShellClient, token *supervisorToken, events []supervisorcontrol.ProcessEvent) error {
	if len(events) == 0 {
		return nil
	}
	callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	callCtx = metadata.NewOutgoingContext(callCtx, metadata.Pairs("authorization", "Bearer "+token.get()))
	stream, err := client.PushSandboxLogs(callCtx)
	if err != nil {
		return err
	}
	lines := make([]*openshellv1.SandboxLogLine, 0, len(events))
	for _, event := range events {
		ts := time.UnixMilli(event.Timestamp).UTC()
		pid := strconv.Itoa(event.PID)
		parentPID := strconv.Itoa(event.ParentPID)
		message := fmt.Sprintf("%s OCSF PROC:%s [INFO] ALLOWED pid=%s ppid=%s executable=%s", ts.Format(time.RFC3339Nano), event.Activity, pid, parentPID, event.Executable)
		lines = append(lines, &openshellv1.SandboxLogLine{
			SandboxId: cfg.Sandbox,
			EventTime: timestamppb.New(ts),
			Level:     "OCSF",
			Target:    event.Executable,
			Message:   message,
			Source:    "sandbox",
			Fields: map[string]string{
				"activity":    event.Activity,
				"pid":         pid,
				"parent_pid":  parentPID,
				"executable":  event.Executable,
				"instance_id": event.InstanceID,
			},
		})
	}
	if err := stream.Send(&openshellv1.PushSandboxLogsRequest{SandboxId: cfg.Sandbox, Logs: lines}); err != nil {
		return err
	}
	_, err = stream.CloseAndRecv()
	return err
}
