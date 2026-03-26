# Open-Source Security Tool Integration Roadmap

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Systematically integrate 20+ best-in-class open-source security tools into OpenSecCLI, transforming it from a wrapper collection into a comprehensive security platform.

**Architecture:** Three-phase integration following the existing adapter pattern (TypeScript wrappers using `tool-runner.ts`). Prioritized by: gap severity, integration difficulty, community adoption. All tools must have JSON/structured output.

---

## Current State: 62 CLI commands across 19 providers

## Phase 1: Critical Gap Fill (Easy integration, high impact)

All tools below use JSONL/JSON output and follow the same pattern as existing adapters.

| # | Tool | Provider | Command | What it does | Stars | Difficulty |
|---|------|----------|---------|-------------|-------|------------|
| 1 | **katana** | recon | url-crawl | Web crawling + JS parsing (ProjectDiscovery) | 12k | Easy |
| 2 | **dnsx** | recon | dns-resolve | Fast DNS resolution + record types (ProjectDiscovery) | 2.2k | Easy |
| 3 | **gau** | recon | url-archive | Passive URL collection from Wayback/OTX/CommonCrawl | 4k | Easy |
| 4 | **dalfox** | vuln | xss-scan | Parameter analysis + XSS detection | 3.7k | Easy |
| 5 | **hadolint** | cloud | dockerfile-lint | Dockerfile security linting (CIS) | 10k | Easy |
| 6 | **kubescape** | cloud | kube-security | K8s security scanning (NSA/CISA/MITRE) | 10k | Easy |

**Total: 6 new commands, all Easy difficulty, ~2 hours work**

## Phase 2: High-Value Medium Complexity

| # | Tool | Provider | Command | What it does | Stars | Difficulty |
|---|------|----------|---------|-------------|-------|------------|
| 7 | **OWASP ZAP** | dast (new) | zap-scan | Full DAST web scanning | 13k | Medium |
| 8 | **sqlmap** | pentest | sqli-scan | Automated SQL injection | 33k | Medium |
| 9 | **prowler** | cloud | cloud-posture | AWS/Azure/GCP runtime audit | 11k | Medium |
| 10 | **Snyk CLI** | supply-chain | snyk-scan | Comprehensive SCA | 5k | Easy |
| 11 | **Arjun** | recon | param-discover | Hidden HTTP parameter discovery | 4.5k | Easy |
| 12 | **theHarvester** | recon | osint-harvest | Email/subdomain OSINT | 12k | Easy |

**Total: 6 new commands (1 new provider: `dast`)**

## Phase 3: Language-Specific SAST + API Security

| # | Tool | Provider | Command | What it does | Stars | Difficulty |
|---|------|----------|---------|-------------|-------|------------|
| 13 | **gosec** | scan | gosec-scan | Go security SAST | 7.8k | Easy |
| 14 | **Bandit** | scan | bandit-scan | Python security SAST | 6.5k | Easy |
| 15 | **graphql-cop** | vuln | graphql-audit | GraphQL API security | 800 | Easy |
| 16 | **jwt_tool** | pentest | jwt-test | JWT security testing | 5.5k | Medium |
| 17 | **dockle** | cloud | container-lint | Container image CIS linting | 2.8k | Easy |
| 18 | **crlfuzz** | vuln | crlf-scan | CRLF injection detection | 1.3k | Easy |
| 19 | **commix** | pentest | cmdi-scan | Command injection testing | 4.6k | Medium |
| 20 | **rustscan** | recon | fast-scan | Ultra-fast port scanning (65535 ports in 3s) | 14k | Medium |
| 21 | **waybackurls** | recon | wayback-urls | Wayback Machine URL fetching | 3.5k | Easy |
| 22 | **gospider** | recon | web-spider | Fast web crawling + JS parsing | 2.5k | Easy |

**Total: 10 new commands**

## Not Integrating (and why)

| Tool | Reason |
|------|--------|
| Arachni, w3af, tplmap | Unmaintained / abandoned |
| hashcat, john, hydra | Long-running, GPU-dependent, ethically sensitive |
| responder | Network poisoning — too dangerous for CLI hub |
| MobSF | Server-based, not CLI-first |
| frida, objection | Interactive, requires physical device |
| aircrack-ng, wifite | Hardware-dependent |
| Recon-ng | Framework-style, doesn't map to single commands |
| pacu | Exploitation framework, ethically sensitive |
| ScoutSuite | Overlaps with prowler |
| CodeQL | Complex two-step setup (database creation + analysis) |

## New Domains Needed

```typescript
// Add to src/constants/domains.ts:
'dast': 'Dynamic application security testing (runtime web scanning)'
```

## Integration Pattern

All Phase 1-2 tools follow this pattern (already proven 24 times):

```typescript
// src/adapters/recon/url-crawl.ts (example: katana)
import { cli, Strategy } from '../../registry.js'
import { runExternalTool } from '../_utils/tool-runner.js'
import { parseJsonLines } from '../_utils/tool-runner.js'

cli({
  provider: 'recon',
  name: 'url-crawl',
  description: 'Crawl web application and extract URLs using katana',
  strategy: Strategy.FREE,
  domain: 'recon',
  args: {
    url: { type: 'string', required: true, help: 'Target URL' },
    depth: { type: 'number', default: 3, help: 'Crawl depth' },
  },
  columns: ['url', 'source', 'status'],
  timeout: 300,
  async func(ctx, args) {
    const { results } = await runExternalTool({
      tools: ['katana'],
      buildArgs: () => ['-u', args.url, '-jsonl', '-silent', '-depth', String(args.depth), '-jc'],
      installHint: 'go install github.com/projectdiscovery/katana/cmd/katana@latest',
      parseOutput: (stdout) => parseJsonLines(stdout).map(r => ({
        url: r.endpoint ?? r.url,
        source: r.source ?? '',
        status: r.status_code ?? 0,
      })),
    })
    ctx.log.info(`Crawled ${results.length} URLs`)
    return results
  },
})
```

## After All Phases

```
Current:  62 commands · 19 providers · 10 domains
Phase 1: +6 commands → 68 commands
Phase 2: +6 commands → 74 commands (+ dast provider)
Phase 3: +10 commands → 84 commands
```

**Final: 84 CLI commands · 20 providers · 11 domains · 22 Skills**

## Recon Pipeline (unlocked by Phase 1)

```bash
# The "ProjectDiscovery pipeline" — all tools share the same JSONL convention
opensec recon subdomain-enum --domain target.com --format json \
  | jq -r '.[].subdomain' \
  | opensec recon dns-resolve \
  | opensec recon tech-fingerprint \
  | opensec recon url-crawl \
  | opensec vuln nuclei-scan
```

This pipeline becomes possible once katana + dnsx are integrated.
