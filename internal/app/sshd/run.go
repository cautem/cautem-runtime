// Package sshd is the composition root for cautem-sshd.
package sshd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/cautem/cautem-core/defaults"
	"github.com/cautem/cautem-runtime/sshserver"
	"golang.org/x/crypto/ssh"
)

const usage = `usage: cautem-sshd [--socket PATH] [--host-key FILE] [--shell PATH] [--workdir DIR] [--init PATH]

Serves SSH on a root-only Unix socket (0600, parent 0700). There is no TCP
listener: clients reach it only through the gateway supervisor relay.
`

// Run starts cautem-sshd.
func Run(args []string) error {
	options, err := parseArgs(args)
	if err != nil {
		return err
	}
	if options.help {
		fmt.Fprint(os.Stderr, usage)
		return nil
	}
	socket, hostKeyPath, cfg := options.socket, options.hostKeyPath, options.server
	if hostKeyPath != "" {
		b, err := os.ReadFile(hostKeyPath)
		if err != nil {
			return err
		}
		signer, err := ssh.ParsePrivateKey(b)
		if err != nil {
			return fmt.Errorf("host key: %w", err)
		}
		cfg.HostKey = signer
	}
	cfg.Log = slog.New(slog.NewJSONHandler(os.Stderr, nil)).With(slog.String("component", "cautem-sshd"))
	if c, err := net.DialTimeout("unix", socket, time.Second); err == nil {
		_ = c.Close()
		cfg.Log.Info("already running", slog.String("op", "sshd.listen"), slog.String("socket", socket))
		return nil
	}
	srv, err := sshserver.New(cfg)
	if err != nil {
		return err
	}
	ln, err := sshserver.ListenUnix(socket)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	cfg.Log.Info("listening", slog.String("op", "sshd.listen"), slog.String("socket", socket))
	return srv.Serve(ln)
}

type runOptions struct {
	socket      string
	hostKeyPath string
	server      sshserver.Config
	help        bool
}

func parseArgs(args []string) (runOptions, error) {
	options := runOptions{
		socket: defaults.GuestSSHSocket,
		server: sshserver.Config{InitPath: defaults.GuestInit, WorkDir: defaults.GuestWorkspace},
	}
	for i := 0; i < len(args); i++ {
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s requires a value", args[i])
			}
			i++
			return args[i], nil
		}
		var err error
		switch args[i] {
		case "--socket":
			options.socket, err = next()
		case "--host-key":
			options.hostKeyPath, err = next()
		case "--shell":
			options.server.Shell, err = next()
		case "--workdir":
			options.server.WorkDir, err = next()
		case "--init":
			options.server.InitPath, err = next()
		case "-h", "--help":
			options.help = true
		default:
			return runOptions{}, fmt.Errorf("unknown flag %q (TCP --listen / --authorized-keys were removed; sshd is relay-only)", args[i])
		}
		if err != nil {
			return runOptions{}, err
		}
	}
	if strings.TrimSpace(options.socket) == "" || !path.IsAbs(options.socket) || path.Clean(options.socket) != options.socket {
		return runOptions{}, fmt.Errorf("sshd socket path must be clean and absolute")
	}
	if strings.TrimSpace(options.server.InitPath) == "" || !path.IsAbs(options.server.InitPath) || path.Clean(options.server.InitPath) != options.server.InitPath {
		return runOptions{}, fmt.Errorf("init path must be clean and absolute")
	}
	return options, nil
}
