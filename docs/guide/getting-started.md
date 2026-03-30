# Getting Started

## Install

### npm (recommended)

```bash
npm install -g openseccli
opensec --help
```

Requires Node.js >= 20.

### Docker

```bash
# Lite (~200 MB) — pure-TS adapters, no external tools
docker build -t opensec .
docker run -it opensec --help

# Full (~3 GB) — includes nuclei, subfinder, semgrep, trivy, and 40+ tools
docker build -t opensec-full --target full .
```

### From source

```bash
git clone https://github.com/skyvast404/OpenSecCLI.git
cd OpenSecCLI
npm install && npm run build
node dist/main.js --help
```

## First command

```bash
# No API key needed — query NVD for a CVE
opensec nvd cve-get CVE-2024-3094
```

## Autopilot

Run a full security assessment with one command:

```bash
opensec autopilot https://target.com
```

This runs header audit, CORS check, cert transparency search, tech fingerprint, and more — then produces a graded report.

## Authentication

Most threat intel commands need free API keys. Add them once:

```bash
opensec auth add virustotal --api-key
opensec auth add abuseipdb --api-key
opensec auth list        # show configured providers
opensec auth test virustotal  # verify connectivity
```

Credentials stored in `~/.openseccli/auth/` with `0600` permissions. Override with env vars: `OPENSECCLI_VIRUSTOTAL_API_KEY`.

## Output formats

Every command supports 5 output formats:

```bash
opensec nvd cve-get CVE-2024-3094 --format json
opensec nvd cve-get CVE-2024-3094 --format csv
opensec nvd cve-get CVE-2024-3094 --format yaml
opensec nvd cve-get CVE-2024-3094 --format markdown
opensec nvd cve-get CVE-2024-3094               # table (default)
```

## Next steps

- [Commands](/guide/commands) — browse all 84 commands
- [Skills](/guide/skills) — use AI-powered security workflows
- [Workflows](/guide/workflows) — define multi-step pipelines in YAML
- [MCP Integration](/guide/mcp) — connect to Claude Desktop or Cursor
- [Docker](/guide/docker) — run in containers
