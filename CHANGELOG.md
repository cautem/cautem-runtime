# Changelog

## [Unreleased]

## [v0.3.0] - 2026-10-16

### Added

- Support `never`, `on-failure`, and `always` workload restart policies with bounded backoff.
- Refresh supervisor session tokens and honor the Gateway-advertised heartbeat interval.

### Changed

- Track orphaned workload processes adopted by the supervisor and publish VM supervisor readiness.
- Use timestamp and duration fields from the pinned OpenShell v0.1.4 protocol.

### Fixed

- Install agent instructions through POSIX `/bin/sh` so minimal guest images do not require Bash.

## [v0.2.1] - 2026-10-13

### Fixed

- Include the active supervisor instance ID in process activity events so the Gateway accepts and records them.

## [v0.2.0] - 2026-10-13

### Added

- Add mutually authenticated workload relay bridges, supervisor control channels, and lifecycle event forwarding.
- Add the experimental `gui-gpu` sandbox image target with Chromium graphics libraries.

### Changed

- Harden supervisor process monitoring and sandbox startup across supported platforms.

### Limitations

- Hardware GPU rendering is experimental and has not been verified on an NVIDIA Linux host.

## [v0.1.8] - 2026-10-11

### Compatibility

- Pin the OpenShell SDK to the gateway-compatible API schema while retaining the v0.1.7 secret-store and KEK hardening fixes.

## [v0.1.7] - 2026-10-11

### Security

- Keep the in-memory secret cache aligned with atomic file updates when a write fails.
- Restrict the secrets directory and file-backed KEK to owner-only permissions; reject KEK symlinks and non-regular files.

### Changed

- Refresh the OpenShell SDK, cautem-driver, crypto, and system dependencies.
- Read the OpenShell supervisor heartbeat interval from its duration-based field.

## [v0.1.6] - 2026-10-11

### Changed

- Rename the module, runtime identifiers and project references to the `cautem` namespace.

## [v0.1.0-beta.2] - 2026-10-10

### Added

- Prepare and exchange OIDC PKCE authorization codes for the Go management console.

### Changed

- Resolve `cautem-core` v0.1.0-beta.2, `cautem-driver` v0.1.0-beta.2 and `slogx` v0.1.0-beta.1 from published tags.

### Fixed

- Harden runtime identity, filesystem ownership and path handling across supported platforms.
- Align sandbox image builds and module workflows with the current Go toolchain.

## [v0.1.0-beta.1] - 2026-10-07

### Added

- Add contextual structured logs for relay channel and SSH session lifecycle events.

### Changed

- Use `cautem-core` v0.1.0-beta.1 for relay errors with operation context.

### Fixed

- Isolate Unix-only filesystem ownership and supervisor tests from other platforms.

## [v0.1.0-alpha.2] - 2026-10-07

### Added

- Add a Go workload supervisor for signal forwarding, child reaping, and authenticated lifecycle control over a Unix socket.
- Add OpenShell relay targets and policy-status reporting for gateway-backed sandboxes.
- Validate OCI process identity and apply filesystem hardening with explicit best-effort diagnostics.

### Compatibility

- Unix guests provide process-group signal forwarding, adopted-child reaping, and sidecar lifecycle reporting. Windows builds retain a command-launch fallback without those Unix lifecycle features.

### Changed

- Replace shell-based agent entrypoints with the Go supervisor and staged harness files.
- Update core, driver, proxy, and slogx to their published v0.1.0-alpha.2 modules; update Landlock to v0.10.1 and `golang.org/x/crypto` to v0.57.0.
- Distribute the module under Apache-2.0.

### Security

- Bound OIDC/token refresh requests and preserve fail-closed behavior for credential staging and policy lifecycle failures.

## [v0.0.2-alpha.1] - 2026-09-28

### Security

- Secrets KEK v2: scrypt+salt for passwords, raw 32-byte keys without KDF; durable migrate/rename.
- Stage agent/runtime credential files as mode `0600`.
- OIDC validates token `typ` and uses bounded HTTP client timeouts.
- Harden `best_effort` always logs Landlock/drop failures.

### Fixed

- JWT payload split uses `strings.Cut` instead of a custom scanner.
