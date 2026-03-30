# Claude Code Skills

OpenSecCLI ships 35 AI-powered security workflows as Claude Code slash commands. Each skill orchestrates multiple `opensec` commands into complete investigation or pentest workflows.

## Install

Copy the skills directory into your project:

```bash
# Already included if you cloned the repo
ls .claude/skills/
```

Or install globally:

```bash
cp -r .claude/skills/ ~/.claude/skills/
```

Skills appear as `/slash-commands` in Claude Code.

## Usage

In Claude Code, type the skill name:

```
/ioc-investigate 203.0.113.5
/web-pentest https://target.com
/cve-impact-check CVE-2024-3094
```

## Threat Intelligence & Incident Response (5)

| Skill | What it does |
|-------|-------------|
| `/ioc-investigate` | Deep-dive IOC analysis across multiple threat intel sources |
| `/incident-response` | Guided triage, evidence collection, containment steps |
| `/cve-impact-check` | Assess CVE impact on your specific infrastructure |
| `/threat-hunting` | Proactive threat hunting across logs and telemetry |
| `/osint-deep-dive` | Open-source intelligence deep investigation |

## Penetration Testing (6)

| Skill | What it does |
|-------|-------------|
| `/web-pentest` | Full web application pentest workflow |
| `/api-pentest` | API security testing: auth, IDOR, injection, rate limiting |
| `/network-pentest` | Network pentest: scanning, enumeration, exploitation |
| `/ai-llm-pentest` | AI/LLM application pentest: prompt injection, jailbreak, data leak |
| `/bug-bounty-workflow` | End-to-end bug bounty hunting workflow |
| `/red-team-recon` | Red team reconnaissance and initial access |

## Code & Application Security (6)

| Skill | What it does |
|-------|-------------|
| `/code-security-audit` | Automated source code security review |
| `/whitebox-code-review` | White-box code review with taint analysis |
| `/semantic-hunter` | Semantic vulnerability hunting beyond pattern matching |
| `/detect-semantic-attack` | Detect semantic attacks: backdoors, logic bombs |
| `/business-logic-test` | Business logic flaw testing |
| `/missed-patch-hunter` | Find incomplete fixes and missed patches |

## Infrastructure & Supply Chain (5)

| Skill | What it does |
|-------|-------------|
| `/supply-chain-audit` | Full supply chain security audit |
| `/cloud-audit` | Cloud security posture assessment |
| `/container-security` | Container and image security assessment |
| `/devsecops-pipeline` | DevSecOps pipeline security review |
| `/compliance-check` | Compliance verification (SOC2, PCI-DSS, HIPAA) |

## Agent Security & Research (4)

| Skill | What it does |
|-------|-------------|
| `/agent-security-suite` | Full agent/LLM security test suite |
| `/agent-attack-research` | Agent attack research and novel technique discovery |
| `/dast-assessment` | Dynamic application security testing workflow |
| `/ctf-toolkit` | CTF challenge solving toolkit |

## Triage & Recon (4)

| Skill | What it does |
|-------|-------------|
| `/attack-surface-map` | Map external attack surface for a domain/org |
| `/domain-recon` | Full domain reconnaissance and intelligence |
| `/security-triage` | Security finding triage and prioritization |
| `/exploit-validation` | Exploit validation and PoC development |

## Quick Utilities (5)

| Skill | What it does |
|-------|-------------|
| `/quick-security-check` | Fast security posture check |
| `/jwt-decoder` | Decode and analyze JWT tokens |
| `/cve-lookup` | Quick CVE lookup |
| `/skill-scanner` | Scan Claude Code skills for security issues |
| `/cert-check` | Certificate transparency check |
