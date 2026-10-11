# Roadmap — cautem-runtime

Status: **v0.1.8** (stable numbered release) · Depends on core `v0.1.6` / driver `v0.1.7`; slogx `v0.1.3`

## This module

| ID | Item | Notes |
|----|------|-------|
| T1 | **Image catalog** | Keep GHCR `sandboxes/{base,gui,gpu}` in sync with tags |
| T2 | **Secrets store** | Map/Env → Vault adapters |
| T3 | **Identity federation** | Align gateway OIDC/mTLS and workload identity with OpenShell config and authorization semantics |
| T4 | **Harden depth** | Landlock/seccomp profile documentation |

## Release

Tagged after core + driver + proxy in the cascade.
