---
name: skill-scanner
description: >
  Trigger when user asks to "scan this skill", "is this skill safe", "check skill for malware",
  "audit Claude Code skill". Security scan of Claude Code skill files before installation.
---

# Skill Scanner

Scan Claude Code skills for security issues before installation using built-in OpenSecCLI commands.

## Workflow

### Step 1: Skill Security Scan

```bash
opensec agent-security scan-skill --path "$SKILL_PATH" --format json
```

Parse JSON output. Extract:
- Prompt injection patterns detected
- Data exfiltration risks (URLs, fetch calls, encoded data)
- Credential exposure (API keys, tokens referenced)
- Dangerous tool usage patterns
- Overall risk score

### Step 2: MCP Audit (if applicable)

Check if the skill directory contains MCP configuration (e.g., `mcp.json`, `server.json`,
or references to MCP servers in SKILL.md). If found:

```bash
opensec agent-security mcp-audit --path "$SKILL_PATH" --format json
```

Parse JSON output. Extract:
- Tool description poisoning risks
- Rug-pull potential (dynamic behavior changes)
- Cross-server data flow risks

### Step 3: Render Verdict

```markdown
# Skill Security Scan Report

**Skill:** <skill name>
**Path:** <scanned path>
**Scanned:** <current date/time>

## Verdict: ALLOW / WARN / BLOCK

| Check | Status | Details |
|-------|--------|---------|
| Prompt Injection | Clear/Found | <details> |
| Data Exfiltration | Clear/Found | <details> |
| Credential Exposure | Clear/Found | <details> |
| MCP Poisoning | Clear/Found/N/A | <details> |

## Explanation
<2-3 sentences explaining the verdict in plain language>

## Action
- **ALLOW:** Safe to install.
- **WARN:** Review flagged items manually before installing.
- **BLOCK:** Do not install. <specific dangerous pattern found>
```

## Verdict Rules

- **BLOCK:** Any prompt injection or credential exfiltration detected.
- **WARN:** Suspicious patterns (external URLs, encoded strings) but no confirmed attack.
- **ALLOW:** No issues found across all checks.
