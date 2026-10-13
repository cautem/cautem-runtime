<h1 align="center">cautem-runtime</h1>

<p align="center">
  <strong>Sandbox glue & images</strong><br>
  Lifecycle helpers, harden, secrets store, cautem-init, and GHCR sandbox images.
</p>
<p align="center">
  <a href="https://github.com/cautem/cautem-runtime/actions/workflows/ci.yml"><img src="https://github.com/cautem/cautem-runtime/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pkg.go.dev/github.com/cautem/cautem-runtime"><img src="https://pkg.go.dev/badge/github.com/cautem/cautem-runtime.svg" alt="Go Reference"></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache--2.0-blue.svg" alt="License"></a>
  <a href="https://github.com/cautem/cautem-runtime"><img src="https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go" alt="Go Version"></a>

  <a href="https://github.com/cautem/cautem-runtime/actions/workflows/images-sandbox.yml"><img src="https://github.com/cautem/cautem-runtime/actions/workflows/images-sandbox.yml/badge.svg" alt="images-sandbox"></a>
</p>
<p align="center">
  <sub>Part of the <a href="https://github.com/cautem">cautem / cautem</a> ecosystem</sub>
</p>

---

## Overview

See the [architecture](https://cautem.github.io/sandbox.dev/concepts/architecture/) and [security](https://cautem.github.io/sandbox.dev/concepts/security/) pages for the sandbox process and its trust boundaries.

**cautem-runtime** ties sandbox creation together: guest init (`cautem-init`), Landlock/seccomp harden, secrets store, inference snippets, and the Debian-based sandbox image flavors published to GHCR.

### Key Features

| Category | Capabilities |
|----------|--------------|
| **Images** | `sandboxes/{base,gui,gpu,gui-gpu}` on `ghcr.io/cautem/cautem` |
| **Init** | `cautem-init` — Landlock, seccomp, workspace mount |
| **Supervisor** | `cautem-supervisor` — PID 1 workload lifecycle and sandbox-side loopback dial socket for `ForwardTcp` |
| **Relay** | `relaytarget` — validates and dials loopback TCP targets inside the sandbox network namespace over the private shared Unix socket |
| **Secrets** | Host-side store resolved into guest placeholders |
| **Harden** | Linux sandbox hardening helpers |
| **Inference** | Local host-gateway model URL helpers |

---

## Installation

Build from this checkout in the sibling `go.work` workspace. The published alpha tag still declares an older module path, so a standalone `go get` needs a new coordinated release.

**Images (after CI publish):**

```text
ghcr.io/cautem/cautem/sandboxes/base:latest
ghcr.io/cautem/cautem/sandboxes/gui:latest
ghcr.io/cautem/cautem/sandboxes/gpu:latest
ghcr.io/cautem/cautem/sandboxes/gui-gpu:latest # experimental GUI+GPU; hardware acceleration unverified
```

**Requirements:** Go 1.27+

Sandbox images declare `USER sandbox` and give that account writable ownership of `/sandbox`, `/workspace`, and `/cautem/data`. Docker/Podman start the hardened supervisor as root while passing the inspected image's OCI `Config.User` to the workload identity resolver; explicit OpenShell policy fields take precedence. Custom images that omit OCI `USER` must specify both process identity fields in policy or use a backend that provides resolved `OPENSHELL_SANDBOX_UID` / `OPENSHELL_SANDBOX_GID` values.

---

## Quick Start

```bash
# build guest init into the image context (as CI does)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -o images/sandbox/cautem-init ./cmd/cautem-init
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -o images/sandbox/cautem-supervisor ./cmd/cautem-supervisor

docker build -t cautem-sandbox:local --target cli -f images/sandbox/Dockerfile images/sandbox
```

---

## Package Structure

| Path | Purpose |
|------|---------|
| `cmd/cautem-init` | Guest entrypoint |
| `cmd/cautem-supervisor` | PID 1 workload supervisor for local and remote control transports |
| `sandbox/` | Lifecycle helpers |
| `harden/` | Landlock / seccomp |
| `secrets/` | Secret store |
| `images/sandbox/` | Multi-target Dockerfile |
| `inference/` | Local model policy snippets |
| `agentconfig/` | Supervisor policy-advisor and `AGENTS.md` installation |


---

## Related

| Resource | Link |
|----------|------|
| Roadmap | [ROADMAP.md](./ROADMAP.md) |
| Organization | [https://github.com/cautem](https://github.com/cautem) |
| Organization overview | [github.com/cautem](https://github.com/cautem) |
| pkg.go.dev | [`github.com/cautem/cautem-runtime`](https://pkg.go.dev/github.com/cautem/cautem-runtime) |

## License

[Apache-2.0](./LICENSE) © cautem
