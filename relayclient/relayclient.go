// Package relayclient is the proxy-side gateway relay client. It keeps the
// outbound control/data connections in the proxy sidecar, dials SSH over the
// shared Unix socket, and delegates loopback TCP dialing to the sandbox-side
// relaytarget service.
package relayclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cautem/cautem-core/relayproto"
	"github.com/cautem/slogx"
)

// Config configures Run.
type Config struct {
	GatewayURL string
	// GatewayGRPCEndpoint selects the pinned OpenShell supervisor protocol.
	// When empty, Run uses the cautem HTTP relay transport.
	GatewayGRPCEndpoint string
	Sandbox             string
	// Token is the sandbox-scoped supervisor token (never a user token).
	Token string
	// SSHSocket is the sandbox sshd Unix socket (TargetSSH).
	SSHSocket string
	// TargetDialSocket delegates TCP target dialing into the sandbox network namespace.
	TargetDialSocket string
	// TargetDialEndpoint delegates both SSH and loopback TCP dialing to the
	// paired workload Pod over its mutually authenticated boundary Service.
	TargetDialEndpoint string
	TargetTLSConfig    *tls.Config
	// SupervisorControlSocket bridges PID 1 lifecycle events through this
	// authenticated sidecar without exposing its sandbox bearer to the workload.
	SupervisorControlSocket string
	// SupervisorControlAddress serves the same lifecycle bridge over mTLS when
	// the supervisor and workload run in separate pods.
	SupervisorControlAddress   string
	SupervisorControlTLSConfig *tls.Config
	TLSConfig                  *tls.Config
	Log                        *slog.Logger
	// DialTarget overrides how targets are dialed (tests).
	DialTarget func(ctx context.Context, target string) (net.Conn, error)
	MinBackoff time.Duration
	MaxBackoff time.Duration
	// TokenRefreshInterval controls proactive RefreshSandboxToken calls for
	// the pinned OpenShell supervisor transport. A refresh keeps an active
	// supervisor session usable when the gateway rotates its bearer token.
	TokenRefreshInterval time.Duration
	// OnConnected is called after each successful control handshake (tests).
	OnConnected func()
}

func (c *Config) defaults() {
	if c.Log == nil {
		c.Log = slog.Default()
	}
	if c.MinBackoff <= 0 {
		c.MinBackoff = time.Second
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = defaultMaxBackoff
	}
	if c.TokenRefreshInterval <= 0 {
		c.TokenRefreshInterval = 5 * time.Minute
	}
	customDial := c.DialTarget
	baseDial := customDial
	if baseDial == nil {
		sock := c.SSHSocket
		baseDial = func(ctx context.Context, target string) (net.Conn, error) { return dialRelayTarget(ctx, sock, target) }
	}
	if customDial != nil {
		c.DialTarget = customDial
	} else if endpoint := strings.TrimSpace(c.TargetDialEndpoint); endpoint != "" {
		c.DialTarget = func(ctx context.Context, target string) (net.Conn, error) {
			return dialSandboxTargetTLS(ctx, endpoint, c.TargetTLSConfig, target)
		}
	} else if targetSocket := strings.TrimSpace(c.TargetDialSocket); targetSocket != "" {
		c.DialTarget = func(ctx context.Context, target string) (net.Conn, error) {
			if target == relayproto.TargetSSH {
				return baseDial(ctx, target)
			}
			return dialSandboxTCP(ctx, targetSocket, target)
		}
	} else {
		c.DialTarget = func(ctx context.Context, target string) (net.Conn, error) {
			if target != relayproto.TargetSSH {
				return nil, errors.New("relayclient: sandbox TCP target dial socket is not configured")
			}
			return baseDial(ctx, target)
		}
	}
}

// DialLoopbackTCP opens a validated literal loopback TCP target.
func DialLoopbackTCP(ctx context.Context, target string) (net.Conn, error) {
	return dialRelayTarget(ctx, "", target)
}

func dialSandboxTCP(ctx context.Context, socketPath, target string) (net.Conn, error) {
	if _, err := validateLoopbackTarget(target); err != nil {
		return nil, err
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("relayclient: connect sandbox TCP dial socket: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := fmt.Fprintf(conn, "%s\n", target); err != nil {
		_ = conn.Close()
		return nil, err
	}
	ack := make([]byte, 3)
	if _, err := io.ReadFull(conn, ack); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("relayclient: sandbox TCP target handshake: %w", err)
	}
	if string(ack) != "OK\n" {
		_ = conn.Close()
		return nil, errors.New("relayclient: sandbox TCP target is unavailable")
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func validateLoopbackTarget(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "tcp" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("relay target is not permitted")
	}
	host, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		return "", fmt.Errorf("relay target is not permitted")
	}
	ip := net.ParseIP(host)
	port, err := strconv.ParseUint(portText, 10, 16)
	if ip == nil || !ip.IsLoopback() || err != nil || port == 0 {
		return "", fmt.Errorf("relay target is not permitted")
	}
	return net.JoinHostPort(ip.String(), strconv.FormatUint(port, 10)), nil
}

func dialRelayTarget(ctx context.Context, sshSocket, target string) (net.Conn, error) {
	var dialer net.Dialer
	if target == relayproto.TargetSSH {
		return dialer.DialContext(ctx, "unix", sshSocket)
	}
	addr, err := validateLoopbackTarget(target)
	if err != nil {
		return nil, err
	}
	return dialer.DialContext(ctx, "tcp", addr)
}

// Run keeps the supervisor session alive until ctx is done.
func Run(ctx context.Context, cfg Config) error {
	if err := cfg.ValidateTargetTransport(); err != nil {
		return err
	}
	cfg.defaults()
	if strings.TrimSpace(cfg.GatewayGRPCEndpoint) != "" {
		return runOpenShell(ctx, cfg)
	}
	if strings.TrimSpace(cfg.GatewayURL) == "" || strings.TrimSpace(cfg.Sandbox) == "" || strings.TrimSpace(cfg.Token) == "" {
		return errors.New("relayclient: gateway url, sandbox and token are required")
	}
	backoff := cfg.MinBackoff
	for {
		started := time.Now()
		err := session(ctx, cfg)
		if ctx.Err() != nil {
			return nil
		}
		if time.Since(started) > 2*relayproto.KeepaliveTimeout {
			backoff = cfg.MinBackoff
		}
		attrs := []any{slog.String("op", "supervisor.reconnect"), slog.String("sandbox", cfg.Sandbox), slog.Duration("backoff", backoff)}
		if err != nil {
			attrs = append(attrs, slogx.Err(err))
		}
		var se *relayproto.StatusError
		if errors.As(err, &se) && (se.Code == http.StatusUnauthorized || se.Code == http.StatusForbidden) {
			cfg.Log.Error("supervisor token rejected by gateway", attrs...)
		} else {
			cfg.Log.Warn("supervisor session ended", attrs...)
		}
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

func (cfg *Config) header() http.Header {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+cfg.Token)
	return h
}

func session(ctx context.Context, cfg Config) error {
	path := relayproto.PathSupervisorConnect + "?sandbox=" + url.QueryEscape(cfg.Sandbox)
	conn, err := relayproto.Dial(ctx, cfg.GatewayURL, path, relayproto.DialOptions{Header: cfg.header(), TLSConfig: cfg.TLSConfig})
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	mw := relayproto.NewMessageWriter(conn)
	if err := mw.Write(relayproto.Message{Type: relayproto.MsgHello, Sandbox: cfg.Sandbox}); err != nil {
		return err
	}
	cfg.Log.Info("supervisor connected", slog.String("op", "supervisor.connect"), slog.String("sandbox", cfg.Sandbox))
	if cfg.OnConnected != nil {
		cfg.OnConnected()
	}
	mr := relayproto.NewMessageReader(conn)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(relayproto.KeepaliveTimeout))
		m, err := mr.Read()
		if err != nil {
			return err
		}
		switch m.Type {
		case relayproto.MsgPing:
			if err := mw.Write(relayproto.Message{Type: relayproto.MsgPong}); err != nil {
				return err
			}
		case relayproto.MsgOpen:
			if m.Channel == "" {
				continue
			}
			go openChannel(ctx, cfg, m)
		}
	}
}

func openChannel(ctx context.Context, cfg Config, m relayproto.Message) {
	log := cfg.Log.With(
		slog.String("op", "supervisor.open"),
		slog.String("sandbox", cfg.Sandbox),
		slog.String("channel", m.Channel),
		slog.String("target", m.Target),
	)
	log.Debug("dialing relay target")
	dctx, cancel := context.WithTimeout(ctx, relayDialTimeout)
	defer cancel()
	target, err := cfg.DialTarget(dctx, m.Target)
	if err != nil {
		log.Warn("relay target dial failed", slogx.Err(err))
		return
	}
	data, err := relayproto.Dial(dctx, cfg.GatewayURL, relayproto.PathSupervisorRelay+url.PathEscape(m.Channel),
		relayproto.DialOptions{Header: cfg.header(), TLSConfig: cfg.TLSConfig})
	if err != nil {
		if closeErr := target.Close(); closeErr != nil {
			log.Debug("relay target close after dial failure failed", slogx.Err(closeErr))
		}
		log.Warn("relay data stream failed", slogx.Err(err))
		return
	}
	log.Info("relay channel opened")
	if err := relayproto.Pipe(data, target); err != nil {
		log.Warn("relay channel ended with error", slogx.Err(err))
		return
	}
	log.Debug("relay channel closed")
}
