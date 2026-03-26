# Show HN: OpenSecCLI — 84 security commands in one CLI, with 30 AI-powered Skills

Hey HN,

I built OpenSecCLI because I was tired of switching between 20 different security tools with 20 different output formats.

**What it does:**
- Wraps 84 security commands (nmap, nuclei, sqlmap, semgrep, trivy, ZAP, etc.) into one CLI with consistent JSON output
- Multi-source enrichment: query 5 threat intel APIs in parallel for any IP/domain/hash/URL
- 30 Claude Code Skills for AI-powered security workflows (code review, pentesting, incident response)
- 10 pure-TypeScript commands that work with zero external dependencies (header audit, CORS check, JWT analysis, parameter fuzzing)

**What makes it different:**
- Not just a wrapper — multi-source enrichment with consensus verdicts is unique
- Agent-friendly by design: structured JSON errors, exit 0 for empty results, stderr/stdout separation
- Plugin system: drop a YAML file in `~/.openseccli/plugins/` and it auto-loads
- Custom semgrep rules for SQLi, XSS, SSRF, path traversal that `--config auto` misses

```bash
npm install -g openseccli
opensec enrichment ip-enrich 8.8.8.8
opensec vuln header-audit --url https://example.com
opensec crypto hash-id <suspicious-hash>
```

GitHub: https://github.com/skyvast404/OpenSecCLI

Tech: TypeScript, Commander.js, 337 tests, Docker support. Inspired by OpenCLI's architecture.

Happy to answer questions about the architecture or security tool integration approach.
