# Agent instructions

## Scope

This repository contains sandbox process glue, hardening helpers, secrets
storage, `cautem-init`, and sandbox image sources.

## Working rules

- Treat privilege dropping, filesystem restrictions, secret storage, process
  startup, and relay authentication as critical security boundaries.
- Check Linux and other supported platform implementations when changing
  shared behavior. Keep image contents and runtime contracts in sync with CLI
  and driver expectations.
- Keep local Go workspace replacements in the parent workspace's `go.work`,
  never in this repository's `go.mod`.

## Checks

- Run `go test ./...` from this checkout for Go changes.
- Use the image and lifecycle checks for changes to `images/` or startup paths;
  they require container tooling.
- From the parent workspace, `task check` runs the shared Go gate.
