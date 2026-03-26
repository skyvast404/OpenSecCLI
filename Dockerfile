# OpenSecCLI Docker Image
#
# Two targets:
#   docker build -t opensec .                    # Lite: opensec + pure-TS adapters only (~200MB, 30s build)
#   docker build -t opensec-full --target full .  # Full: opensec + 40 external tools (~3GB, 10min build)
#
# Usage:
#   docker run -it opensec list
#   docker run -it opensec vuln header-audit --url https://example.com
#   docker run -it -v $(pwd):/workspace opensec scan analyze --path /workspace

# ============================================================
# Builder
# ============================================================
FROM node:22-slim AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build

# ============================================================
# Lite: opensec CLI only (pure-TS adapters work out of the box)
# ============================================================
FROM node:22-slim AS lite

WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY .claude/skills/ /skills/

VOLUME ["/workspace"]
WORKDIR /workspace

ENTRYPOINT ["node", "/app/dist/main.js"]
CMD ["--help"]

# ============================================================
# Full: opensec + all external security tools
# ============================================================
FROM lite AS full

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/usr/local/go/bin:/root/go/bin:/root/.local/bin:${PATH}"
ENV GOPATH=/root/go

USER root

# System packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget git unzip ca-certificates gnupg jq file \
    nmap dnsutils \
    libimage-exiftool-perl binwalk tshark binutils \
    python3 python3-pip python3-venv pipx \
    && rm -rf /var/lib/apt/lists/*

# Go
ARG TARGETARCH
RUN GOARCH=${TARGETARCH} && \
    curl -fsSL "https://go.dev/dl/go1.23.6.linux-${GOARCH}.tar.gz" | tar xz -C /usr/local

# Go tools (ProjectDiscovery + others)
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/hahwul/dalfox/v2@latest && \
    go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest && \
    go install github.com/jaeles-project/gospider@latest && \
    go install github.com/securego/gosec/v2/cmd/gosec@latest && \
    rm -rf /root/go/pkg /root/.cache/go-build

# Python tools
RUN pipx install semgrep && \
    pipx install sqlmap && \
    pipx install bandit && \
    pipx install trufflehog && \
    pipx install checkov && \
    pipx install pip-audit || true

# Binary tools
RUN curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin || true
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin || true
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && \
    ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

WORKDIR /workspace
ENTRYPOINT ["node", "/app/dist/main.js"]
CMD ["--help"]
