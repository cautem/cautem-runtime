// Package agent is the composition root for cautem-agent.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cautem/quarshell-runtime/internal/logging"
	"github.com/cautem/quarshell-slogx"
)

func Run(args []string) error {
	const op = "agent.run"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := logging.Setup(ctx, logging.Options{Service: "cautem-agent"})
	ctx = logging.ToContext(ctx, log)
	log = log.With(slog.String("op", op))

	gateway := os.Getenv("CAUTEM_GATEWAY")
	name := os.Getenv("CAUTEM_SANDBOX")
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--gateway":
			i++
			gateway = args[i]
		case "--name":
			i++
			name = args[i]
		case "-h", "--help":
			fmt.Fprintf(os.Stderr, "usage: cautem-agent --gateway URL --name SANDBOX\n")
			return nil
		default:
			return fmt.Errorf("unknown flag %q", args[i])
		}
	}
	if gateway == "" || name == "" {
		return fmt.Errorf("cautem-agent: --gateway and --name required")
	}
	base := strings.TrimRight(gateway, "/")
	log.Info("registering with gateway", slog.String("sandbox", name), slog.String("gateway", base))

	// Long-poll style relay: poll for jobs, post results (works without gorilla/websocket).
	client := &http.Client{Timeout: requestTimeout}
	for {
		pollCtx, pollCancel := context.WithTimeout(ctx, pollTimeout)
		job, err := pollJob(pollCtx, client, base, name)
		pollCancel()
		if err != nil {
			log.Warn("poll failed", slogx.Err(err))
			time.Sleep(retryInterval)
			continue
		}
		if job == nil {
			continue
		}
		jobLog := log.With(slog.String("job_id", job.ID), slog.Int("argv_len", len(job.Argv)))
		jobLog.Info("executing relay job")
		out, code := runJob(job.Argv)
		if err := postResult(client, base, name, job.ID, out, code); err != nil {
			jobLog.Error("failed to post job result", slogx.Err(err), slog.Int("exit_code", code))
			continue
		}
		jobLog.Info("job completed", slog.Int("exit_code", code), slog.Int("output_bytes", len(out)))
	}
}

type job struct {
	ID   string   `json:"id"`
	Argv []string `json:"argv"`
}

func pollJob(ctx context.Context, client *http.Client, base, name string) (*job, error) {
	const op = "agent.pollJob"
	log := logging.FromContext(ctx).With(slog.String("op", op), slog.String("sandbox", name))

	u := base + "/v1/relay/" + url.PathEscape(name) + "/poll"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		log.Error("failed to build poll request", slogx.Err(err))
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if res.StatusCode >= 300 {
		err := fmt.Errorf("%s", res.Status)
		log.Error("poll returned error status", slogx.Err(err), slog.Int("status", res.StatusCode))
		return nil, err
	}
	var j job
	if err := json.NewDecoder(res.Body).Decode(&j); err != nil {
		log.Error("failed to decode poll response", slogx.Err(err))
		return nil, err
	}
	log.Info("job received", slog.String("job_id", j.ID))
	return &j, nil
}

func runJob(argv []string) (string, int) {
	if len(argv) == 0 {
		return "empty argv", 1
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	var buf cappedBuffer
	buf.max = maxJobOutputBytes
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = 1
			_, _ = buf.Write([]byte(err.Error()))
		}
	}
	return buf.String(), code
}

// maxJobOutputBytes caps relayed agent stdout/stderr (OpenShell-style: avoid
// unbounded capture into gateway/relay memory).
const maxJobOutputBytes = 4 << 20 // 4 MiB

type cappedBuffer struct {
	buf bytes.Buffer
	n   int
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.max <= 0 {
		return c.buf.Write(p)
	}
	if c.n >= c.max {
		return len(p), nil
	}
	remain := c.max - c.n
	if len(p) > remain {
		_, err := c.buf.Write(p[:remain])
		c.n = c.max
		_, _ = c.buf.WriteString("\n…[truncated]\n")
		return len(p), err
	}
	n, err := c.buf.Write(p)
	c.n += n
	return n, err
}

func (c *cappedBuffer) String() string {
	return c.buf.String()
}

func postResult(client *http.Client, base, name, id, out string, code int) error {
	body, _ := json.Marshal(map[string]any{"id": id, "exit_code": code, "output": out})
	u := base + "/v1/relay/" + url.PathEscape(name) + "/result"
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	return nil
}
