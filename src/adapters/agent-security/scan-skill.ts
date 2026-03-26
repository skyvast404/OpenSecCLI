/**
 * Claude Code skill security scanner.
 * Pure TypeScript -- no external dependencies.
 * Scans skill directories for prompt injection, data exfiltration, credential exposure.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'

// --- Types ---

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

interface ScanFinding {
  rule_id: string
  severity: Severity
  category: string
  file: string
  line: number
  message: string
  [key: string]: unknown
}

// --- Rule Definitions ---

interface ScanRule {
  id: string
  severity: Severity
  category: string
  pattern: RegExp
  message: string
}

const SENSITIVE_PATH_PATTERN = /\/etc\/|~\/\.ssh\/|~\/\.aws\//

const FILE_WRITE_PATTERNS: ScanRule[] = [
  {
    id: 'SKILL-FW-001',
    severity: 'HIGH',
    category: 'file-write',
    pattern: /writeFile|appendFile|fs\.write/,
    message: 'File write operation detected',
  },
  {
    id: 'SKILL-FW-002',
    severity: 'HIGH',
    category: 'file-write',
    pattern: />\s*\/|>>\s*\//,
    message: 'Shell redirect to absolute path detected',
  },
]

const DATA_EXFILTRATION_PATTERNS: ScanRule[] = [
  {
    id: 'SKILL-EX-001',
    severity: 'CRITICAL',
    category: 'data-exfiltration',
    pattern: /fetch\(|http\.request|axios\.|curl\s/,
    message: 'Network request combined with sensitive data pattern',
  },
]

const SECRET_TOKEN_PATTERN = /secret|token|key|password/i

const TUNNEL_SHELL_PATTERNS: ScanRule[] = [
  {
    id: 'SKILL-TS-001',
    severity: 'CRITICAL',
    category: 'tunnel-shell',
    pattern: /reverse\.shell|nc\s+-e|bash\s+-i|ngrok|frp|chisel|ssh\s+-R/,
    message: 'Reverse shell or tunnel tool detected',
  },
]

const CREDENTIAL_PATTERNS: ScanRule[] = [
  {
    id: 'SKILL-CR-001',
    severity: 'HIGH',
    category: 'credential',
    pattern: /AKIA[0-9A-Z]{16}/,
    message: 'AWS access key ID detected',
  },
  {
    id: 'SKILL-CR-002',
    severity: 'HIGH',
    category: 'credential',
    pattern: /BEGIN[\s\S]*?PRIVATE KEY/,
    message: 'Private key block detected',
  },
  {
    id: 'SKILL-CR-003',
    severity: 'HIGH',
    category: 'credential',
    pattern: /(?:key|token|secret|password)\s*[:=]\s*['"][A-Za-z0-9]{32,}['"]/i,
    message: 'Hardcoded credential value detected',
  },
]

const PROMPT_INJECTION_PATTERNS: ScanRule[] = [
  {
    id: 'SKILL-PI-001',
    severity: 'CRITICAL',
    category: 'prompt-injection',
    pattern: /<IMPORTANT>|<SYSTEM>/,
    message: 'XML tag injection attempt detected',
  },
  {
    id: 'SKILL-PI-002',
    severity: 'CRITICAL',
    category: 'prompt-injection',
    pattern: /ignore previous|you are now/i,
    message: 'Prompt override directive detected',
  },
  {
    id: 'SKILL-PI-003',
    severity: 'CRITICAL',
    category: 'prompt-injection',
    pattern: /\u200B|\u200C|\u200D|\uFEFF/,
    message: 'Zero-width character detected (potential hidden instruction)',
  },
]

export const ALL_RULES: ScanRule[] = [
  ...FILE_WRITE_PATTERNS,
  ...DATA_EXFILTRATION_PATTERNS,
  ...TUNNEL_SHELL_PATTERNS,
  ...CREDENTIAL_PATTERNS,
  ...PROMPT_INJECTION_PATTERNS,
]

// --- File Reading ---

function collectFiles(dir: string, base: string): Array<{ path: string; rel: string }> {
  const results: Array<{ path: string; rel: string }> = []
  try {
    const entries = readdirSync(dir)
    for (const entry of entries) {
      if (entry === 'node_modules' || entry === '.git') continue
      const full = join(dir, entry)
      const stat = statSync(full)
      if (stat.isDirectory()) {
        results.push(...collectFiles(full, base))
      } else if (stat.isFile()) {
        results.push({ path: full, rel: relative(base, full) })
      }
    }
  } catch {
    // unreadable directory
  }
  return results
}

// --- Scanning ---

export function scanContent(
  content: string,
  filePath: string,
): ScanFinding[] {
  const findings: ScanFinding[] = []
  const lines = content.split('\n')

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    const lineNum = i + 1

    for (const rule of ALL_RULES) {
      if (!rule.pattern.test(line)) continue

      // data-exfiltration requires co-presence of secret/token patterns
      if (rule.category === 'data-exfiltration') {
        if (!SECRET_TOKEN_PATTERN.test(content)) continue
      }

      // file-write to sensitive paths gets elevated
      if (rule.category === 'file-write' && SENSITIVE_PATH_PATTERN.test(line)) {
        findings.push({
          rule_id: rule.id,
          severity: 'CRITICAL',
          category: rule.category,
          file: filePath,
          line: lineNum,
          message: `${rule.message} targeting sensitive path`,
        })
        continue
      }

      findings.push({
        rule_id: rule.id,
        severity: rule.severity,
        category: rule.category,
        file: filePath,
        line: lineNum,
        message: rule.message,
      })
    }
  }

  return findings
}

export function computeVerdict(findings: ScanFinding[]): string {
  if (findings.some((f) => f.severity === 'CRITICAL')) return 'BLOCK'
  if (findings.some((f) => f.severity === 'HIGH' || f.severity === 'MEDIUM')) return 'WARN'
  return 'ALLOW'
}

// --- CLI Registration ---

cli({
  provider: 'agent-security',
  name: 'scan-skill',
  description:
    'Scan Claude Code skills for security issues (prompt injection, data exfiltration, credential exposure)',
  strategy: Strategy.FREE,
  domain: 'agent-security',
  args: {
    path: { type: 'string', required: true, help: 'Path to skill directory containing SKILL.md' },
    format_output: {
      type: 'string',
      required: false,
      default: 'json',
      choices: ['json', 'markdown'],
      help: 'Report format',
    },
  },
  columns: ['rule_id', 'severity', 'category', 'file', 'line', 'message'],
  timeout: 60,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const skillPath = args.path as string
    const files = collectFiles(skillPath, skillPath)

    if (files.length === 0) {
      throw new Error(`No files found in skill directory: ${skillPath}`)
    }

    ctx.log.info(`Scanning ${files.length} files in ${skillPath}`)

    const allFindings: ScanFinding[] = []

    for (const file of files) {
      try {
        const content = readFileSync(file.path, 'utf-8')
        const findings = scanContent(content, file.rel)
        allFindings.push(...findings)
      } catch {
        ctx.log.warn(`Could not read file: ${file.rel}`)
      }
    }

    const verdict = computeVerdict(allFindings)
    ctx.log.info(`Scan complete: ${allFindings.length} findings, verdict: ${verdict}`)

    return allFindings
  },
})
