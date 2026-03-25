/**
 * CI/CD pipeline security auditor.
 * Pure TypeScript -- analyzes GitHub Actions / GitLab CI configs.
 * Source: pentest-supply-chain
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { readFileSync, existsSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

interface CiAuditFinding {
  file: string
  rule: string
  severity: string
  line: number
  detail: string
  [key: string]: unknown
}

const DANGEROUS_CONTEXTS = [
  'github.event.pull_request.title',
  'github.event.pull_request.body',
  'github.event.issue.title',
  'github.event.issue.body',
  'github.event.comment.body',
  'github.event.review.body',
  'github.event.head_commit.message',
  'github.head_ref',
]

export function parseCiAuditFindings(filePath: string, content: string): CiAuditFinding[] {
  const findings: CiAuditFinding[] = []
  const lines = content.split('\n')

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    const lineNum = i + 1

    // Check unpinned actions (uses: action@branch instead of action@sha)
    const usesMatch = line.match(/uses:\s*([^@]+)@(.+)/)
    if (usesMatch) {
      const ref = usesMatch[2].trim()
      if (!ref.match(/^[a-f0-9]{40}$/) && !ref.match(/^v\d/)) {
        findings.push({
          file: filePath,
          rule: 'unpinned-action',
          severity: 'medium',
          line: lineNum,
          detail: `Action ${usesMatch[1].trim()}@${ref} uses mutable ref. Pin to SHA for supply chain safety.`,
        })
      }
    }

    // Check expression injection in run steps
    const runMatch = line.match(/run:.*\$\{\{(.+?)\}\}/)
    if (runMatch) {
      const expr = runMatch[1].trim()
      for (const ctx of DANGEROUS_CONTEXTS) {
        if (expr.includes(ctx)) {
          findings.push({
            file: filePath,
            rule: 'expression-injection',
            severity: 'critical',
            line: lineNum,
            detail: `Untrusted input "${ctx}" used directly in run step. Use env var instead.`,
          })
        }
      }
    }

    // Check for secrets in logs
    if (line.match(/echo.*\$\{\{\s*secrets\./)) {
      findings.push({
        file: filePath,
        rule: 'secret-in-log',
        severity: 'high',
        line: lineNum,
        detail: 'Secret potentially logged via echo. Remove echo or mask output.',
      })
    }

    // Check for pull_request_target with checkout
    if (line.includes('pull_request_target')) {
      const remainingLines = lines.slice(i, Math.min(i + 30, lines.length)).join('\n')
      if (remainingLines.includes('actions/checkout') && remainingLines.includes('ref:')) {
        findings.push({
          file: filePath,
          rule: 'prt-checkout',
          severity: 'critical',
          line: lineNum,
          detail: 'pull_request_target with PR head checkout enables code execution from forks.',
        })
      }
    }
  }

  return findings
}

cli({
  provider: 'supply-chain',
  name: 'ci-audit',
  description: 'Audit CI/CD pipeline configs for security issues (GitHub Actions, GitLab CI)',
  strategy: Strategy.FREE,
  domain: 'supply-chain',
  args: {
    path: { type: 'string', required: true, help: 'Project root path' },
  },
  columns: ['file', 'rule', 'severity', 'line', 'detail'],
  timeout: 30,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const path = args.path as string
    const findings: CiAuditFinding[] = []

    // GitHub Actions
    const ghDir = join(path, '.github', 'workflows')
    if (existsSync(ghDir)) {
      const files = readdirSync(ghDir).filter((f) => f.endsWith('.yml') || f.endsWith('.yaml'))
      for (const file of files) {
        const filePath = join(ghDir, file)
        const content = readFileSync(filePath, 'utf-8')
        findings.push(...parseCiAuditFindings(`.github/workflows/${file}`, content))
      }
    }

    // GitLab CI
    const gitlabCi = join(path, '.gitlab-ci.yml')
    if (existsSync(gitlabCi)) {
      const content = readFileSync(gitlabCi, 'utf-8')
      const gitlabLines = content.split('\n')
      for (let i = 0; i < gitlabLines.length; i++) {
        if (gitlabLines[i].match(/script:.*\$CI_MERGE_REQUEST_TITLE/)) {
          findings.push({
            file: '.gitlab-ci.yml',
            rule: 'expression-injection',
            severity: 'critical',
            line: i + 1,
            detail: 'Untrusted MR title used in script. Sanitize input first.',
          })
        }
      }
    }

    ctx.log.info(`CI audit: ${findings.length} issues found`)
    return findings
  },
})
