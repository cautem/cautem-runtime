// Package sshserver is the in-sandbox SSH server reached only through the
// supervisor relay (OpenShell supervisor SSH). It listens on a root-only Unix
// socket, never on TCP, so the transport is authorized by socket permissions
// plus the gateway session token — SSH-level auth accepts "none" by design.
//
// Channel policy (fail-closed):
//   - session: shell / exec via login shell, optional PTY, allowlisted env.
//   - direct-tcpip: loopback destinations only, valid port range.
//   - agent forwarding, X11, reverse forwarding, streamlocal, subsystems: refused.
package sshserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cautem/quarshell-slogx"
	"golang.org/x/crypto/ssh"
)

// EnvNoLoginShell selects `bash -c` instead of `bash -lc` for exec requests
// (OpenShell OPENSHELL_NO_LOGIN_SHELL).
const EnvNoLoginShell = "CAUTEM_NO_LOGIN_SHELL"

// allowedEnv are the only client env requests applied to children.
var allowedEnv = map[string]bool{
	"TERM": true, "COLORTERM": true, "LANG": true, "LANGUAGE": true, "TZ": true,
	EnvNoLoginShell: true,
}

func envAllowed(name string) bool {
	return allowedEnv[name] || strings.HasPrefix(name, "LC_")
}

// Config configures a Server.
type Config struct {
	// HostKey is optional; an ephemeral ed25519 key is generated when nil.
	HostKey ssh.Signer
	// Shell is the login shell (default /bin/bash, then /bin/sh).
	Shell string
	// InitPath is required and wraps every child as `InitPath -- <argv>`;
	// cautem-init applies Landlock / privilege drop from policy.
	InitPath string
	// Env is the base child environment (default os.Environ()).
	Env []string
	// WorkDir is the child working directory when it exists.
	WorkDir string
	Log     *slog.Logger
	// DialLoopback dials allowed direct-tcpip targets (tests override).
	DialLoopback func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Server serves SSH connections.
type Server struct {
	cfg    Config
	sshCfg *ssh.ServerConfig
	log    *slog.Logger
}

// New builds a Server.
func New(cfg Config) (*Server, error) {
	if strings.TrimSpace(cfg.InitPath) == "" {
		return nil, fmt.Errorf("ssh server: hardening init path is required")
	}
	initInfo, initErr := os.Stat(cfg.InitPath)
	if initErr != nil || !initInfo.Mode().IsRegular() || initInfo.Mode().Perm()&0o111 == 0 {
		return nil, fmt.Errorf("ssh server: hardening init is unavailable or not executable")
	}
	if cfg.HostKey == nil {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			return nil, err
		}
		cfg.HostKey = signer
	}
	if cfg.Shell == "" {
		cfg.Shell = "/bin/bash"
		if _, err := os.Stat(cfg.Shell); err != nil {
			cfg.Shell = "/bin/sh"
		}
	}
	if cfg.Env == nil {
		cfg.Env = os.Environ()
	}
	if cfg.DialLoopback == nil {
		d := &net.Dialer{Timeout: sessionRequestTimeout}
		cfg.DialLoopback = d.DialContext
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	sc := &ssh.ServerConfig{
		NoClientAuth:  true,
		ServerVersion: "SSH-2.0-cautem-sshd",
	}
	sc.AddHostKey(cfg.HostKey)
	return &Server{cfg: cfg, sshCfg: sc, log: log}, nil
}

// ListenUnix binds a Unix socket at path with a 0700 parent and 0600 socket.
func ListenUnix(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("sshserver: %s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

// Serve accepts connections until ln is closed.
func (s *Server) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.ServeConn(c)
	}
}

// ServeConn handles one SSH transport.
func (s *Server) ServeConn(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	conn, chans, reqs, err := ssh.NewServerConn(c, s.sshCfg)
	if err != nil {
		s.log.Debug("ssh handshake failed", slog.String("op", "sshd.handshake"), slogx.Err(err))
		return
	}
	_ = c.SetDeadline(time.Time{})
	defer conn.Close()
	s.log.Info("ssh connection accepted", slog.String("op", "sshd.accept"), slog.String("user", conn.User()))
	go s.handleGlobal(reqs)
	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			go s.handleSession(nc)
		case "direct-tcpip":
			go s.handleDirectTCPIP(nc)
		default:
			s.deny("channel", nc.ChannelType())
			_ = nc.Reject(ssh.Prohibited, "channel type not permitted in sandbox")
		}
	}
}

func (s *Server) deny(kind, what string) {
	s.log.Warn("ssh request denied", slog.String("op", "sshd.deny"), slog.String("kind", kind), slog.String("request", what))
}

func (s *Server) handleGlobal(reqs <-chan *ssh.Request) {
	for r := range reqs {
		ok := r.Type == "keepalive@openssh.com"
		if !ok {
			s.deny("global", r.Type)
		}
		if r.WantReply {
			_ = r.Reply(ok, nil)
		}
	}
}

// IsLoopbackHost accepts localhost and loopback IP literals only.
func IsLoopbackHost(host string) bool {
	h := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(host), "["), "]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

type directTCPIPPayload struct {
	Host     string
	Port     uint32
	OrigHost string
	OrigPort uint32
}

func (s *Server) handleDirectTCPIP(nc ssh.NewChannel) {
	var p directTCPIPPayload
	if err := ssh.Unmarshal(nc.ExtraData(), &p); err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, "bad direct-tcpip payload")
		return
	}
	if p.Port == 0 || p.Port > 65535 {
		s.deny("direct-tcpip", fmt.Sprintf("%s:%d invalid port", p.Host, p.Port))
		_ = nc.Reject(ssh.Prohibited, "invalid port")
		return
	}
	if !IsLoopbackHost(p.Host) {
		s.deny("direct-tcpip", fmt.Sprintf("%s:%d non-loopback", p.Host, p.Port))
		_ = nc.Reject(ssh.Prohibited, "only loopback forwarding is permitted")
		return
	}
	host := p.Host
	if strings.EqualFold(host, "localhost") {
		host = "127.0.0.1"
	}
	ctx, cancel := context.WithTimeout(context.Background(), sessionRequestTimeout)
	target, err := s.cfg.DialLoopback(ctx, "tcp", net.JoinHostPort(strings.Trim(host, "[]"), fmt.Sprint(p.Port)))
	cancel()
	if err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	if tc, ok := target.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		_ = target.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(target, ch)
		if tc, ok := target.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(ch, target)
		_ = ch.CloseWrite()
	}()
	wg.Wait()
	_ = ch.Close()
	_ = target.Close()
}

type ptyRequest struct {
	Term   string
	Cols   uint32
	Rows   uint32
	Width  uint32
	Height uint32
	Modes  string
}

type windowChange struct {
	Cols   uint32
	Rows   uint32
	Width  uint32
	Height uint32
}

type session struct {
	srv  *Server
	ch   ssh.Channel
	env  []string
	pty  *ptyRequest
	mu   sync.Mutex
	proc *process
}

func (s *Server) handleSession(nc ssh.NewChannel) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	sess := &session{srv: s, ch: ch}
	defer func() {
		sess.mu.Lock()
		p := sess.proc
		sess.mu.Unlock()
		if p != nil {
			p.hangup()
		}
		_ = ch.Close()
	}()
	for r := range reqs {
		sess.handle(r)
	}
}

func (ss *session) reply(r *ssh.Request, ok bool) {
	if r.WantReply {
		_ = r.Reply(ok, nil)
	}
}

func (ss *session) handle(r *ssh.Request) {
	switch r.Type {
	case "pty-req":
		var p ptyRequest
		if err := ssh.Unmarshal(r.Payload, &p); err != nil {
			ss.reply(r, false)
			return
		}
		ss.pty = &p
		ss.reply(r, true)
	case "env":
		var kv struct{ Name, Value string }
		if err := ssh.Unmarshal(r.Payload, &kv); err != nil || !envAllowed(kv.Name) {
			ss.srv.deny("env", kv.Name)
			ss.reply(r, false)
			return
		}
		ss.env = append(ss.env, kv.Name+"="+kv.Value)
		ss.reply(r, true)
	case "shell":
		ss.start(r, "")
	case "exec":
		var cmd struct{ Command string }
		if err := ssh.Unmarshal(r.Payload, &cmd); err != nil {
			ss.reply(r, false)
			return
		}
		ss.start(r, cmd.Command)
	case "window-change":
		var wc windowChange
		if err := ssh.Unmarshal(r.Payload, &wc); err == nil {
			ss.mu.Lock()
			p := ss.proc
			ss.mu.Unlock()
			if p != nil {
				p.resize(wc.Rows, wc.Cols)
			}
		}
		ss.reply(r, true)
	case "signal":
		var sig struct{ Signal string }
		if err := ssh.Unmarshal(r.Payload, &sig); err == nil {
			ss.mu.Lock()
			p := ss.proc
			ss.mu.Unlock()
			if p != nil {
				p.signal(sig.Signal)
			}
		}
		ss.reply(r, true)
	case "auth-agent-req@openssh.com", "x11-req", "subsystem":
		ss.srv.deny("session", r.Type)
		ss.reply(r, false)
	default:
		ss.srv.deny("session", r.Type)
		ss.reply(r, false)
	}
}

// childArgv builds the (optionally init-wrapped) login-shell argv.
func (ss *session) childArgv(command string) ([]string, error) {
	shell := ss.srv.cfg.Shell
	var argv []string
	switch {
	case command == "":
		argv = []string{shell, "-l"}
	case ss.noLogin():
		argv = []string{shell, "-c", command}
	default:
		argv = []string{shell, "-lc", command}
	}
	ip := ss.srv.cfg.InitPath
	info, err := os.Stat(ip)
	if err != nil {
		return nil, fmt.Errorf("ssh child hardening init unavailable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return nil, fmt.Errorf("ssh child hardening init is not an executable regular file")
	}
	return append([]string{ip, "--"}, argv...), nil
}

func (ss *session) noLogin() bool {
	for _, e := range ss.env {
		if k, v, _ := strings.Cut(e, "="); k == EnvNoLoginShell {
			v = strings.ToLower(strings.TrimSpace(v))
			return v == "1" || v == "true" || v == "yes"
		}
	}
	return false
}

func (ss *session) childEnv() []string {
	env := append([]string{}, ss.srv.cfg.Env...)
	if ss.pty != nil && ss.pty.Term != "" {
		env = mergeEnv(env, []string{"TERM=" + ss.pty.Term})
	}
	return mergeEnv(env, ss.env)
}

func (ss *session) start(r *ssh.Request, command string) {
	ss.mu.Lock()
	if ss.proc != nil {
		ss.mu.Unlock()
		ss.reply(r, false)
		return
	}
	ss.mu.Unlock()
	argv, err := ss.childArgv(command)
	if err != nil {
		ss.srv.log.Error("ssh child hardening unavailable", slog.String("op", "sshd.exec"), slogx.Err(err))
		ss.reply(r, false)
		return
	}
	p, err := startProcess(argv, ss.childEnv(), ss.srv.cfg.WorkDir, ss.pty, ss.ch)
	if err != nil {
		ss.srv.log.Error("ssh child start failed", slog.String("op", "sshd.exec"), slogx.Err(err))
		ss.reply(r, false)
		return
	}
	ss.mu.Lock()
	ss.proc = p
	ss.mu.Unlock()
	ss.reply(r, true)
	kind := "exec"
	if command == "" {
		kind = "shell"
	}
	ss.srv.log.Info("ssh session started", slog.String("op", "sshd.session"), slog.String("kind", kind), slog.Bool("pty", ss.pty != nil))
	go func() {
		code := p.wait()
		_, _ = ss.ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
		_ = ss.ch.Close()
	}()
}

func mergeEnv(base, extra []string) []string {
	idx := map[string]int{}
	out := make([]string, 0, len(base)+len(extra))
	add := func(e string) {
		k, _, ok := strings.Cut(e, "=")
		if !ok || k == "" {
			return
		}
		if i, seen := idx[k]; seen {
			out[i] = e
			return
		}
		idx[k] = len(out)
		out = append(out, e)
	}
	for _, e := range base {
		add(e)
	}
	for _, e := range extra {
		add(e)
	}
	return out
}
