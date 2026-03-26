# Twitter/X Thread Draft

## Tweet 1 (Hook)
I built an open-source CLI that replaces 20 security tools with one command.

84 commands. 30 AI Skills. Zero config.

Meet OpenSecCLI 🔒

🧵 Thread ↓

## Tweet 2 (Multi-source enrichment)
Most powerful feature: multi-source enrichment.

One command queries 5 threat intel APIs in parallel and returns a consensus verdict.

```
opensec enrichment ip-enrich 203.0.113.5
```

→ AbuseIPDB: Malicious
→ VirusTotal: Malicious
→ GreyNoise: Malicious
→ ThreatFox: Known IOC

Verdict: 🔴 Malicious (4/5 sources agree)

## Tweet 3 (Zero-dep commands)
10 commands need ZERO external tools — pure TypeScript:

• header-audit → A-F security grade with CSP deep analysis
• cors-check → 9 CORS misconfig tests + preflight
• jwt-test → alg:none, key confusion, expiry checks
• fuzz → 52 built-in payloads (SQLi/XSS/SSRF)
• scan-skill → detect prompt injection in AI skills

Just `npm install -g openseccli` and go.

## Tweet 4 (AI Skills)
30 Claude Code Skills turn natural language into security workflows:

"Check if this IP is malicious" → triggers ioc-investigate
"Pentest this API" → triggers api-pentest
"Review this code for security" → triggers whitebox-code-review

No security expertise needed. Claude + Skills = security autopilot.

## Tweet 5 (CTA)
GitHub: github.com/skyvast404/OpenSecCLI

⭐ Star if useful
🐛 Issues welcome
🔧 PRs welcome — `opensec create adapter` scaffolds a new command in 10 seconds

npm install -g openseccli

Built with TypeScript. 337 tests. Docker support. Apache-2.0.
