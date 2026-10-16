# SPDX-FileCopyrightText: Copyright (c) 2026 lkmavi
# SPDX-License-Identifier: Apache-2.0
#
# Multi-target sandbox images (Debian bookworm).
#   docker build --target cli -t cautem-sandbox:local .
#   docker build --target gui -t cautem-sandbox:gui .
#   docker build --target gpu -t cautem-sandbox:gpu .
#   docker build --target gui-gpu -t cautem-sandbox:gui-gpu .
#
# cli  — OpenShell-like base: languages, agents, networking, developer tools
# gui  — Debian bookworm: Chromium + Xvfb/openbox/noVNC
# gpu  — Debian bookworm + CUDA *userland* packages; host injects libcuda via CDI
# gui-gpu — GUI image with GL/EGL/Vulkan userspace and NVIDIA render capabilities

ARG DEBIAN_BASE=debian:bookworm@sha256:2c037a04925515fdd6ea85ea14a682d0e79931f5e9f5d07b6dbfc6ba12f9e858

FROM ${DEBIAN_BASE} AS cli
LABEL org.opencontainers.image.title="cautem-sandbox" \
      org.opencontainers.image.description="cautem agent sandbox (OpenShell-like toolset)" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/cautem/quarshell-runtime"
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    bash \
    build-essential \
    python3 \
    python3-pip \
    python3-venv \
    vim-tiny \
    nano \
    dnsutils \
    iproute2 \
    iputils-ping \
    net-tools \
    netcat-openbsd \
    traceroute \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Node.js 22 (nodesource) + npm
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g npm@11

# GitHub CLI
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/*

# Agent CLIs (OpenShell Community base parity)
RUN npm install -g \
        opencode-ai \
        @openai/codex \
        @github/copilot \
    && curl -fsSL https://claude.ai/install.sh | bash \
    && if [ -x /root/.local/bin/claude ]; then cp /root/.local/bin/claude /usr/local/bin/claude && chmod 755 /usr/local/bin/claude; fi \
    && npm cache clean --force

# uv for Python toolchain (optional; system python3 remains available)
COPY --from=ghcr.io/astral-sh/uv:0.10.8@sha256:88234bc9e09c2b2f6d176a3daf411419eb0370d450a08129257410de9cfafd2a /uv /usr/local/bin/uv

COPY cautem-init /usr/local/bin/cautem-init
COPY cautem-supervisor /usr/local/bin/cautem-supervisor
COPY cautem-sshd /usr/local/bin/cautem-sshd
RUN chmod 0755 /usr/local/bin/cautem-init /usr/local/bin/cautem-supervisor /usr/local/bin/cautem-sshd \
    && mkdir -p /cautem/data/home/.local/bin /cautem/data/bin /workspace \
    && ln -sf /usr/bin/python3 /usr/local/bin/python || true
RUN groupadd --system sandbox \
    && useradd --system --gid sandbox --home-dir /sandbox --create-home --shell /bin/bash sandbox \
    && chown -R sandbox:sandbox /cautem/data /sandbox /workspace

ENV CAUTEM_POLICY=/cautem/policy.yaml \
    HOME=/cautem/data/home \
    PATH=/cautem/data/home/.local/bin:/cautem/data/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WORKDIR /workspace
USER sandbox
ENTRYPOINT ["/usr/local/bin/cautem-init"]
CMD ["--", "sleep", "infinity"]

# GPU-oriented sandbox: toolchain for CUDA samples / torch wheels.
# Drivers and libcuda.so come from the host via CDI (cautem sandbox create --gpu).
FROM ${DEBIAN_BASE} AS gpu
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    bash \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*
COPY cautem-init /usr/local/bin/cautem-init
COPY cautem-supervisor /usr/local/bin/cautem-supervisor
COPY cautem-sshd /usr/local/bin/cautem-sshd
RUN chmod 0755 /usr/local/bin/cautem-init /usr/local/bin/cautem-supervisor /usr/local/bin/cautem-sshd \
    && groupadd --system sandbox \
    && useradd --system --gid sandbox --home-dir /sandbox --create-home --shell /bin/sh sandbox \
    && mkdir -p /cautem/data /workspace \
    && chown -R sandbox:sandbox /cautem/data /sandbox /workspace
ENV CAUTEM_POLICY=/cautem/policy.yaml \
    HOME=/cautem/data/home \
    PATH=/cautem/data/home/.local/bin:/cautem/data/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    NVIDIA_VISIBLE_DEVICES=all \
    NVIDIA_DRIVER_CAPABILITIES=compute,utility
USER sandbox
ENTRYPOINT ["/usr/local/bin/cautem-init"]
CMD ["--", "sleep", "infinity"]

FROM ${DEBIAN_BASE} AS gui
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    xvfb \
    x11vnc \
    openbox \
    novnc \
    websockify \
    chromium \
    chromium-sandbox \
    fonts-liberation \
    fonts-dejavu-core \
    dbus-x11 \
    xterm \
    curl \
    git \
    bash \
    && rm -rf /var/lib/apt/lists/* \
    && chromium --version

COPY cautem-init /usr/local/bin/cautem-init
COPY cautem-supervisor /usr/local/bin/cautem-supervisor
COPY cautem-sshd /usr/local/bin/cautem-sshd
COPY cautem-gui-boot /usr/local/bin/cautem-gui-boot
COPY cautem-display-start /usr/local/bin/cautem-display-start
COPY chromium-cautem /usr/local/bin/chromium-cautem
RUN chmod 0755 /usr/local/bin/cautem-init /usr/local/bin/cautem-supervisor /usr/local/bin/cautem-sshd /usr/local/bin/cautem-gui-boot \
        /usr/local/bin/cautem-display-start /usr/local/bin/chromium-cautem \
    && ln -sf /usr/local/bin/chromium-cautem /usr/local/bin/google-chrome \
    && ln -sf /usr/local/bin/chromium-cautem /usr/local/bin/chrome \
    && groupadd --system sandbox \
    && useradd --system --gid sandbox --home-dir /sandbox --create-home --shell /bin/bash sandbox \
    && mkdir -p /cautem/data /workspace \
    && chown -R sandbox:sandbox /cautem/data /sandbox /workspace

ENV CAUTEM_POLICY=/cautem/policy.yaml \
    HOME=/cautem/data/home \
    PATH=/cautem/data/home/.local/bin:/cautem/data/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    DISPLAY=:99 \
    DISPLAY_MODE=none \
    CAUTEM_DISPLAY_GEOM=1280x800x24 \
    CHROME_BIN=/usr/local/bin/chromium-cautem \
    BROWSER=/usr/local/bin/chromium-cautem

USER sandbox
ENTRYPOINT ["/usr/local/bin/cautem-init"]
CMD ["--", "/usr/local/bin/cautem-gui-boot"]

# Experimental GUI + GPU image. The host must provide a compatible NVIDIA
# Container Toolkit/CDI setup. Enabling driver capabilities is not proof that
# Chromium or another application uses hardware rendering; verify on GPU hosts.
FROM gui AS gui-gpu
USER root
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    libegl1 \
    libgl1 \
    libgles2 \
    libvulkan1 \
    mesa-utils \
    vulkan-tools \
    && rm -rf /var/lib/apt/lists/*
COPY chromium-cautem-gpu /usr/local/bin/chromium-cautem-gpu
RUN chmod 0755 /usr/local/bin/chromium-cautem-gpu \
    && ln -sf /usr/local/bin/chromium-cautem-gpu /usr/local/bin/google-chrome \
    && ln -sf /usr/local/bin/chromium-cautem-gpu /usr/local/bin/chrome
ENV CHROME_BIN=/usr/local/bin/chromium-cautem-gpu \
    BROWSER=/usr/local/bin/chromium-cautem-gpu \
    NVIDIA_VISIBLE_DEVICES=all \
    NVIDIA_DRIVER_CAPABILITIES=graphics,display,compute,utility
USER sandbox
