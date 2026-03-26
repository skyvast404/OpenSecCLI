# OpenSecCLI — All-in-one security toolkit container
# Usage:
#   docker build -t opensec .
#   docker run -it opensec list
#   docker run -it opensec vuln header-audit --url https://example.com
#   docker run -it -v $(pwd):/workspace opensec scan analyze --path /workspace
#
# With API keys:
#   docker run -it \
#     -e OPENSECCLI_VIRUSTOTAL_API_KEY=xxx \
#     -e OPENSECCLI_ABUSEIPDB_API_KEY=xxx \
#     opensec enrichment ip-enrich --ip 8.8.8.8
#
# Interactive shell:
#   docker run -it --entrypoint /bin/bash opensec

# ============================================================
# Stage 1: Build OpenSecCLI
# ============================================================
FROM node:22-slim AS builder

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build

# ============================================================
# Stage 2: Runtime with all security tools
# ============================================================
FROM node:22-slim

LABEL maintainer="OpenSecCLI"
LABEL description="All-in-one open-source security CLI hub"
LABEL org.opencontainers.image.source="https://github.com/skyvast404/OpenSecCLI"

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/root/go
ENV PATH="/root/go/bin:/root/.local/bin:${PATH}"

WORKDIR /app

# ---- System dependencies ----
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core tools
    curl wget git unzip ca-certificates gnupg \
    # Network tools
    nmap masscan dnsutils \
    # Analysis tools
    exiftool binwalk tshark \
    # Build tools (for Go/Rust installs)
    golang-go \
    # Python (for semgrep, sqlmap, etc.)
    python3 python3-pip python3-venv pipx \
    # Misc
    jq file strings \
    && rm -rf /var/lib/apt/lists/*

# ---- Python security tools ----
RUN pipx install semgrep && \
    pipx install sqlmap && \
    pipx install bandit && \
    pipx install commix && \
    pipx install trufflehog && \
    pipx install checkov && \
    pipx install prowler && \
    pipx install arjun && \
    pipx install theharvester && \
    pipx install graphql-cop && \
    pipx install pip-audit

# ---- Go security tools (ProjectDiscovery ecosystem + others) ----
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
    go install github.com/projectdiscovery/ffuf/v2@latest && \
    # Clean Go cache to reduce image size
    rm -rf /root/go/pkg /root/go/src

# ---- Binary tools (direct download) ----
# hadolint
RUN curl -fsSL https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 \
    -o /usr/local/bin/hadolint && chmod +x /usr/local/bin/hadolint

# kubescape
RUN curl -fsSL https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash

# gitleaks
RUN GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r .tag_name) && \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_linux_x64.tar.gz" | \
    tar xz -C /usr/local/bin gitleaks

# trivy
RUN curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# syft (SBOM)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# dockle
RUN DOCKLE_VERSION=$(curl -s https://api.github.com/repos/goodwithtech/dockle/releases/latest | jq -r .tag_name | sed 's/v//') && \
    curl -fsSL "https://github.com/goodwithtech/dockle/releases/download/v${DOCKLE_VERSION}/dockle_${DOCKLE_VERSION}_Linux-64bit.tar.gz" | \
    tar xz -C /usr/local/bin dockle

# kube-bench
RUN KUBEBENCH_VERSION=$(curl -s https://api.github.com/repos/aquasecurity/kube-bench/releases/latest | jq -r .tag_name) && \
    curl -fsSL "https://github.com/aquasecurity/kube-bench/releases/download/${KUBEBENCH_VERSION}/kube-bench_${KUBEBENCH_VERSION#v}_linux_amd64.tar.gz" | \
    tar xz -C /usr/local/bin kube-bench

# checksec
RUN curl -fsSL https://raw.githubusercontent.com/slimm609/checksec.sh/main/checksec -o /usr/local/bin/checksec && \
    chmod +x /usr/local/bin/checksec

# testssl.sh
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && \
    ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# ---- Install OpenSecCLI ----
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package.json ./
COPY --from=builder /app/node_modules ./node_modules

# ---- Claude Code Skills ----
COPY .claude/skills/ /skills/

# ---- Workspace volume ----
VOLUME ["/workspace"]
WORKDIR /workspace

# ---- Healthcheck ----
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD node /app/dist/main.js list --format json > /dev/null 2>&1

ENTRYPOINT ["node", "/app/dist/main.js"]
CMD ["--help"]
