// Package supervisorcontrol provides a private lifecycle bridge between the
// sandbox PID 1 and its authenticated supervisor client.
package supervisorcontrol

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	OperationBegin    = "begin"
	OperationReport   = "report_main_process_exit"
	OperationFinalize = "finalize_main_process_exit"
	OperationProcess  = "process_event"
	OperationFlush    = "flush_process_events"
	maxMessageBytes   = 8 << 10
	EnvSocket         = "CAUTEM_SUPERVISOR_CONTROL_SOCKET"
	EnvEndpoint       = "CAUTEM_SUPERVISOR_CONTROL_ENDPOINT"
	EnvListen         = "CAUTEM_SUPERVISOR_CONTROL_LISTEN"
	EnvClientCA       = "CAUTEM_SUPERVISOR_CONTROL_CLIENT_CA"
	EnvClientCert     = "CAUTEM_SUPERVISOR_CONTROL_CLIENT_CERT"
	EnvClientKey      = "CAUTEM_SUPERVISOR_CONTROL_CLIENT_KEY"
	EnvPrivateDir     = "CAUTEM_SUPERVISOR_CONTROL_PRIVATE_DIR"
	EnvServerCA       = "CAUTEM_SUPERVISOR_CONTROL_SERVER_CA"
	EnvServerCert     = "CAUTEM_SUPERVISOR_CONTROL_SERVER_CERT"
	EnvServerKey      = "CAUTEM_SUPERVISOR_CONTROL_SERVER_KEY"
)

// Request is the versioned-by-operation local lifecycle contract. It carries
// no gateway bearer token; authentication remains in the proxy sidecar.
type Request struct {
	Operation  string        `json:"operation"`
	InstanceID string        `json:"instance_id,omitempty"`
	ExitCode   int32         `json:"exit_code,omitempty"`
	Process    *ProcessEvent `json:"process,omitempty"`
}

// ProcessEvent is a bounded observation from the sandbox PID 1. It deliberately
// excludes argv and environment values because those often contain secrets.
type ProcessEvent struct {
	InstanceID string `json:"instance_id,omitempty"`
	Activity   string `json:"activity"`
	PID        int    `json:"pid"`
	ParentPID  int    `json:"parent_pid"`
	Executable string `json:"executable"`
	Timestamp  int64  `json:"timestamp_ms"`
}

// Response returns the sidecar's current process instance or RPC result.
type Response struct {
	InstanceID string `json:"instance_id,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Handler executes one request from PID 1.
type Handler func(context.Context, Request) Response

// Client routes requests over the local Unix socket or an authenticated TLS
// endpoint. Its credentials are loaded once so the calling workload process
// does not need access to the private key files.
type Client struct {
	socket     string
	endpoint   string
	privateDir string
	tls        *tls.Config
}

// NewClientFromEnvironment selects the Unix socket or mutual TLS transport.
// TLS endpoint mode requires an explicit client CA, certificate, and key.
func NewClientFromEnvironment() (*Client, error) {
	socket := strings.TrimSpace(os.Getenv(EnvSocket))
	endpoint := strings.TrimSpace(os.Getenv(EnvEndpoint))
	if socket != "" && endpoint != "" {
		return nil, errors.New("supervisorcontrol: configure either a Unix socket or TLS endpoint, not both")
	}
	if endpoint == "" {
		for _, name := range []string{EnvClientCA, EnvClientCert, EnvClientKey} {
			if strings.TrimSpace(os.Getenv(name)) != "" {
				return nil, errors.New("supervisorcontrol: TLS client files require a control endpoint")
			}
		}
		if socket == "" {
			return nil, nil
		}
		return &Client{socket: socket}, nil
	}
	caPath := strings.TrimSpace(os.Getenv(EnvClientCA))
	certPath := strings.TrimSpace(os.Getenv(EnvClientCert))
	keyPath := strings.TrimSpace(os.Getenv(EnvClientKey))
	if caPath == "" || certPath == "" || keyPath == "" {
		return nil, errors.New("supervisorcontrol: TLS control endpoint requires client CA, certificate, and key")
	}
	credentialDir := filepath.Dir(certPath)
	for _, path := range []string{caPath, certPath, keyPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, errors.New("supervisorcontrol: TLS client credential paths must be absolute and clean")
		}
		if filepath.Dir(path) != credentialDir {
			return nil, errors.New("supervisorcontrol: TLS client credentials must share one private directory")
		}
	}
	config, err := loadClientTLSConfig(caPath, certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &Client{endpoint: endpoint, privateDir: credentialDir, tls: config}, nil
}

// PrivateCredentialDir reports the directory whose filesystem access must be
// denied to the untrusted child process launched by PID 1.
func (c *Client) PrivateCredentialDir() string {
	if c == nil {
		return ""
	}
	return c.privateDir
}

// Call sends one request using the selected transport.
func (c *Client) Call(ctx context.Context, request Request) (Response, error) {
	if c == nil {
		return Response{}, errors.New("supervisorcontrol: client is nil")
	}
	if c.socket != "" {
		return Call(ctx, c.socket, request)
	}
	if c.endpoint != "" {
		return CallTLS(ctx, c.endpoint, c.tls, request)
	}
	return Response{}, errors.New("supervisorcontrol: control transport is not configured")
}

// ServerTLSConfigFromEnvironment loads the server identity and client trust
// anchor mounted into the trusted supervisor process.
func ServerTLSConfigFromEnvironment() (*tls.Config, error) {
	return loadServerTLSConfig(
		strings.TrimSpace(os.Getenv(EnvServerCA)),
		strings.TrimSpace(os.Getenv(EnvServerCert)),
		strings.TrimSpace(os.Getenv(EnvServerKey)),
	)
}

func loadClientTLSConfig(caPath, certPath, keyPath string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("supervisorcontrol: read client trust anchor: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("supervisorcontrol: client trust anchor contains no certificates")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("supervisorcontrol: load client identity: %w", err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{cert}}, nil
}

func loadServerTLSConfig(clientCAPath, certPath, keyPath string) (*tls.Config, error) {
	if clientCAPath == "" || certPath == "" || keyPath == "" {
		return nil, errors.New("supervisorcontrol: TLS server requires client CA, server certificate, and key")
	}
	clientCAPEM, err := os.ReadFile(clientCAPath)
	if err != nil {
		return nil, fmt.Errorf("supervisorcontrol: read server client CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCAPEM) {
		return nil, errors.New("supervisorcontrol: server client CA contains no certificates")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("supervisorcontrol: load server identity: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}, nil
}

// Server serves bounded lifecycle requests on a Unix socket or authenticated TLS listener.
type Server struct {
	listener net.Listener
	path     string
	fileInfo os.FileInfo
	once     sync.Once
	done     chan struct{}
}

// Addr reports the bound address. For Unix sockets it returns the socket path;
// for TCP listeners it includes the selected port.
func (s *Server) Addr() net.Addr {
	if s == nil || s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Start binds the socket synchronously, then accepts requests until ctx ends.
func Start(ctx context.Context, path string, handler Handler) (*Server, error) {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || handler == nil {
		return nil, errors.New("supervisorcontrol: an absolute clean socket path and handler are required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("supervisorcontrol: create socket directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("supervisorcontrol: refusing to replace a non-socket path")
		}
		conn, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return nil, errors.New("supervisorcontrol: another control server is already listening")
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("supervisorcontrol: remove stale socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("supervisorcontrol: inspect socket path: %w", err)
	}
	addr := &net.UnixAddr{Name: path, Net: "unix"}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("supervisorcontrol: listen: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("supervisorcontrol: restrict socket permissions: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("supervisorcontrol: inspect bound socket: %w", err)
	}
	return startServer(ctx, listener, path, info, handler), nil
}

// StartTLS serves the same bounded control protocol over a mutually
// authenticated TLS connection. It is intended for trusted components that
// cannot share a filesystem socket, such as a workload and its Kubernetes
// supervisor Pod. The caller must configure a server certificate and a client
// CA pool; unauthenticated TLS modes are rejected.
func StartTLS(ctx context.Context, address string, config *tls.Config, handler Handler) (*Server, error) {
	address = strings.TrimSpace(address)
	if address == "" || handler == nil {
		return nil, errors.New("supervisorcontrol: a TCP address and handler are required")
	}
	if config == nil {
		return nil, errors.New("supervisorcontrol: mutual TLS configuration is required")
	}
	tlsConfig := config.Clone()
	if tlsConfig.MinVersion == 0 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	if tlsConfig.MinVersion < tls.VersionTLS12 || tlsConfig.InsecureSkipVerify || tlsConfig.GetConfigForClient != nil || tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert || tlsConfig.ClientCAs == nil {
		return nil, errors.New("supervisorcontrol: TLS 1.2+ and verified client certificates are required")
	}
	if len(tlsConfig.Certificates) == 0 && tlsConfig.GetCertificate == nil {
		return nil, errors.New("supervisorcontrol: server certificate is required")
	}
	listener, err := tls.Listen("tcp", address, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("supervisorcontrol: listen for authenticated TLS control: %w", err)
	}
	return startServer(ctx, listener, "", nil, handler), nil
}

func startServer(ctx context.Context, listener net.Listener, path string, fileInfo os.FileInfo, handler Handler) *Server {
	server := &Server{listener: listener, path: path, fileInfo: fileInfo, done: make(chan struct{})}
	go server.serve(ctx, handler)
	return server
}

func (s *Server) serve(ctx context.Context, handler Handler) {
	defer close(s.done)
	semaphore := make(chan struct{}, 16)
	go func() {
		select {
		case <-ctx.Done():
			_ = s.listener.Close()
		case <-s.done:
		}
	}()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		select {
		case semaphore <- struct{}{}:
			go func() {
				defer func() { <-semaphore }()
				defer conn.Close()
				s.handle(ctx, conn, handler)
			}()
		default:
			_ = conn.Close()
		}
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn, handler Handler) {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReader(io.LimitReader(conn, maxMessageBytes+1))
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) > maxMessageBytes {
		_ = json.NewEncoder(conn).Encode(Response{Error: "invalid or oversized request"})
		return
	}
	var request Request
	decoder := json.NewDecoder(strings.NewReader(string(line)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		_ = json.NewEncoder(conn).Encode(Response{Error: "invalid request"})
		return
	}
	response := handler(ctx, request)
	_ = json.NewEncoder(conn).Encode(response)
}

// Close stops accepting requests and removes only this server's socket inode.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	var closeErr error
	s.once.Do(func() {
		closeErr = s.listener.Close()
		<-s.done
		if info, err := os.Lstat(s.path); err == nil && os.SameFile(info, s.fileInfo) {
			if removeErr := os.Remove(s.path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) && closeErr == nil {
				closeErr = removeErr
			}
		}
	})
	return closeErr
}

// Call sends one request and waits for its response using ctx for dial and I/O
// deadlines. A response-level error is returned as a Go error.
func Call(ctx context.Context, path string, request Request) (Response, error) {
	var response Response
	if strings.TrimSpace(path) == "" {
		return response, errors.New("supervisorcontrol: socket path is required")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return response, fmt.Errorf("supervisorcontrol: connect: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return response, fmt.Errorf("supervisorcontrol: send request: %w", err)
	}
	decoder := json.NewDecoder(io.LimitReader(conn, maxMessageBytes))
	if err := decoder.Decode(&response); err != nil {
		return response, fmt.Errorf("supervisorcontrol: receive response: %w", err)
	}
	if response.Error != "" {
		return response, errors.New(response.Error)
	}
	return response, nil
}

// CallTLS sends one control request to a mutually authenticated TLS server.
// The client certificate authenticates the caller, and the server certificate
// is verified against RootCAs or the platform trust store.
func CallTLS(ctx context.Context, address string, config *tls.Config, request Request) (Response, error) {
	var response Response
	address = strings.TrimSpace(address)
	if address == "" || config == nil {
		return response, errors.New("supervisorcontrol: authenticated TLS address and configuration are required")
	}
	tlsConfig := config.Clone()
	if tlsConfig.MinVersion == 0 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	if tlsConfig.MinVersion < tls.VersionTLS12 || tlsConfig.InsecureSkipVerify || (len(tlsConfig.Certificates) == 0 && tlsConfig.GetClientCertificate == nil) {
		return response, errors.New("supervisorcontrol: TLS 1.2+ and a client certificate are required")
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{}, Config: tlsConfig}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return response, fmt.Errorf("supervisorcontrol: connect using authenticated TLS: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return response, fmt.Errorf("supervisorcontrol: send request: %w", err)
	}
	decoder := json.NewDecoder(io.LimitReader(conn, maxMessageBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return response, fmt.Errorf("supervisorcontrol: receive response: %w", err)
	}
	if response.Error != "" {
		return response, errors.New(response.Error)
	}
	return response, nil
}
