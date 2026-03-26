/**
 * MCP server tool description auditor.
 * Pure TypeScript -- no external dependencies.
 * Scans for poisoning, rug-pull, and cross-server data flow risks.
 */

import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs'
import { join, relative } from 'node:path'
import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'

// --- Types ---

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

interface McpFinding {
  rule_id: string
  severity: Severity
  finding: string
  location: string
  detail: string
  [key: string]: unknown
}

// --- Rule Definitions ---

interface McpRule {
  id: string
  severity: Severity
  finding: string
  pattern: RegExp
  detail: string
}

export const MCP_RULES: McpRule[] = [
  {
    id: 'MCP-001',
    severity: 'CRITICAL',
    finding: 'XML tag injection in tool description',
    pattern: /<IMPORTANT>|<SYSTEM>/i,
    detail: 'Tool description contains prompt injection tags that may override agent behavior',
  },
  {
    id: 'MCP-002',
    severity: 'HIGH',
    finding: 'Cross-tool call directive',
    pattern: /also\s+call|then\s+invoke|must\s+call|always\s+call|first\s+call/i,
    detail: 'Tool description attempts to chain additional tool invocations',
  },
  {
    id: 'MCP-003',
    severity: 'HIGH',
    finding: 'Sensitive file path reference',
    pattern: /\/etc\/passwd|~\/\.ssh\/|~\/\.aws\/|\/etc\/shadow|\.env\b/,
    detail: 'Tool description references sensitive system files',
  },
  {
    id: 'MCP-004',
    severity: 'HIGH',
    finding: 'Hidden parameter exfiltration',
    pattern: /hidden\s+param|internal\s+param|__\w+__|do\s+not\s+show\s+user/i,
    detail: 'Tool description hints at hidden parameters for data exfiltration',
  },
  {
    id: 'MCP-005',
    severity: 'CRITICAL',
    finding: 'Zero-width character sequence',
    pattern: /\u200B|\u200C|\u200D|\uFEFF/,
    detail: 'Tool description contains zero-width characters that may hide instructions',
  },
  {
    id: 'MCP-006',
    severity: 'MEDIUM',
    finding: 'External URL in description',
    pattern: /https?:\/\/[^\s'"]+/,
    detail: 'Tool description contains external URL that may be used for exfiltration',
  },
  {
    id: 'MCP-007',
    severity: 'HIGH',
    finding: 'OAuth token operation',
    pattern: /oauth|access_token|refresh_token|bearer\s+token|authorization\s*:/i,
    detail: 'Tool description references OAuth token operations',
  },
  {
    id: 'MCP-008',
    severity: 'HIGH',
    finding: 'Covert behavior directive',
    pattern: /silently|without\s+telling|do\s+not\s+inform|secretly|hide\s+from\s+user/i,
    detail: 'Tool description instructs covert behavior hidden from the user',
  },
]

// --- Scanning ---

export function auditContent(
  content: string,
  location: string,
): McpFinding[] {
  const findings: McpFinding[] = []
  const lines = content.split('\n')

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]

    for (const rule of MCP_RULES) {
      if (!rule.pattern.test(line)) continue

      findings.push({
        rule_id: rule.id,
        severity: rule.severity,
        finding: rule.finding,
        location: `${location}:${i + 1}`,
        detail: rule.detail,
      })
    }
  }

  return findings
}

function collectFiles(dir: string, base: string): Array<{ path: string; rel: string }> {
  const results: Array<{ path: string; rel: string }> = []
  try {
    const stat = statSync(dir)
    if (stat.isFile()) {
      return [{ path: dir, rel: relative(base, dir) || dir }]
    }
    const entries = readdirSync(dir)
    for (const entry of entries) {
      if (entry === 'node_modules' || entry === '.git') continue
      const full = join(dir, entry)
      const entryStat = statSync(full)
      if (entryStat.isDirectory()) {
        results.push(...collectFiles(full, base))
      } else if (entryStat.isFile()) {
        results.push({ path: full, rel: relative(base, full) })
      }
    }
  } catch {
    // unreadable
  }
  return results
}

// --- CLI Registration ---

cli({
  provider: 'agent-security',
  name: 'mcp-audit',
  description:
    'Audit MCP server tool descriptions for poisoning, rug-pull, and cross-server data flow risks',
  strategy: Strategy.FREE,
  domain: 'agent-security',
  args: {
    path: { type: 'string', required: true, help: 'Path to MCP server code or tool description file' },
  },
  columns: ['rule_id', 'severity', 'finding', 'location', 'detail'],
  timeout: 60,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const targetPath = args.path as string

    if (!existsSync(targetPath)) {
      throw new Error(`Path not found: ${targetPath}`)
    }

    const files = collectFiles(targetPath, targetPath)
    if (files.length === 0) {
      throw new Error(`No files found at: ${targetPath}`)
    }

    ctx.log.info(`Auditing ${files.length} files for MCP security issues`)

    const allFindings: McpFinding[] = []

    for (const file of files) {
      try {
        const content = readFileSync(file.path, 'utf-8')
        const findings = auditContent(content, file.rel)
        allFindings.push(...findings)
      } catch {
        ctx.log.warn(`Could not read file: ${file.rel}`)
      }
    }

    ctx.log.info(`MCP audit complete: ${allFindings.length} findings`)
    return allFindings
  },
})
