# Roadmap — cautem-runtime

Status: **v0.3.1** (release prepared) · Depends on quarshell-core `v0.3.1` / quarshell-driver `v0.3.1`; quarshell-slogx `v0.1.4`

## This module

| ID | Item | Notes |
|----|------|-------|
| T1 | **Image catalog** | Keep GHCR `sandboxes/{base,gui,gpu,gui-gpu}` in sync with tags; GPU GUI remains experimental |
| T2 | **Secrets store** | Map/Env → Vault adapters |
| T3 | **Identity federation** | Align gateway OIDC/mTLS and workload identity with OpenShell config and authorization semantics |
| T4 | **Harden depth** | Landlock/seccomp profile documentation |

## Release

Tagged after core + driver + proxy in the cascade.
