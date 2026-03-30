# Docker

## Images

### Lite (~200 MB)

Pure-TS adapters only. No external tools required. Covers header audit, CORS check, fuzzing, JWT testing, hash ID, race testing, CI audit, and HTTP requests.

```bash
docker build -t opensec .
```

### Full (~3 GB)

Includes nuclei, subfinder, semgrep, trivy, sqlmap, and 40+ external security tools.

```bash
docker build -t opensec-full --target full .
```

## Usage

```bash
# List all commands
docker run -it opensec list

# Run a command
docker run -it opensec vuln header-audit --url https://example.com

# JSON output
docker run -it opensec nvd cve-get CVE-2024-3094 --json
```

## Volume mounts

Mount local files for scanning:

```bash
# Scan local source code
docker run -it -v $(pwd):/workspace opensec scan analyze --path /workspace

# Use local workflow files
docker run -it -v $(pwd)/workflows:/workflows opensec workflow run /workflows/web-audit.yaml --target example.com
```

## API keys

Pass API keys via environment variables:

```bash
docker run -it \
  -e OPENSECCLI_VIRUSTOTAL_API_KEY=your-key \
  -e OPENSECCLI_ABUSEIPDB_API_KEY=your-key \
  -e OPENSECCLI_GREYNOISE_API_KEY=your-key \
  opensec enrichment ip-enrich 203.0.113.5
```

Or mount the auth directory:

```bash
docker run -it \
  -v ~/.openseccli/auth:/root/.openseccli/auth:ro \
  opensec enrichment ip-enrich 203.0.113.5
```

## MCP server in Docker

```bash
docker run -i --rm opensec mcp
```

See [MCP Integration](/guide/mcp) for config examples.

## Tools included in Full image

| Category | Tools |
|----------|-------|
| Go (ProjectDiscovery) | nuclei, subfinder, httpx, katana, dnsx, gau, waybackurls, dalfox, crlfuzz, gospider, gosec |
| Python | semgrep, sqlmap, bandit, trufflehog, checkov, pip-audit |
| Binary | trivy, syft, testssl.sh |
| System | nmap, tshark, exiftool, binwalk, file, strings |
