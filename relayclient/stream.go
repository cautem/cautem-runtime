package relayclient

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-core/relayproto"
	"google.golang.org/grpc/metadata"
)

// runOpenShell speaks the pinned OpenShell ConnectSupervisor and RelayStream
// gRPC protocol. It is selected when GatewayGRPCEndpoint is configured.

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
