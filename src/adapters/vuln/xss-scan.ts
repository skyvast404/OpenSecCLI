/**
 * XSS vulnerability scanner adapter.
 * Wraps: dalfox
 * Source: pentest-enterprise-web
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { runExternalTool, parseJsonLines } from '../_utils/tool-runner.js'

interface DalfoxFinding {
  type: string
  data: string
  payload: string
  evidence: string
}

export function parseDalfoxOutput(stdout: string): Record<string, unknown>[] {
  const lines = parseJsonLines(stdout)
  return lines.map((line) => {
    const finding = line as unknown as DalfoxFinding
    const rawType = (finding.type ?? '').toString().toLowerCase()
    return {
      type: finding.type ?? '',
      url: finding.data ?? '',
      payload: finding.payload ?? '',
      evidence: finding.evidence ?? '',
      severity: mapDalfoxSeverity(rawType),
    }
  })
}

function mapDalfoxSeverity(type: string): string {
  if (type === 'vuln') return 'high'
  if (type === 'reflected') return 'medium'
  if (type === 'grep') return 'low'
  return 'info'
}

cli({
  provider: 'vuln',
  name: 'xss-scan',
  description: 'Scan for XSS vulnerabilities with parameter analysis using dalfox',
  strategy: Strategy.FREE,
  domain: 'vuln-scan',
  args: {
    url: { type: 'string', required: true, help: 'Target URL with parameters' },
    blind: { type: 'string', required: false, help: 'Blind XSS callback URL' },
  },
  columns: ['type', 'url', 'payload', 'evidence', 'severity'],
  timeout: 300,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const url = args.url as string
    const blind = args.blind as string | undefined

    const { results } = await runExternalTool({
      tools: ['dalfox'],
      buildArgs: () => {
        const a = ['url', url, '--format', 'json', '--silence']
        if (blind) a.push('-b', blind)
        return a
      },
      installHint: 'go install github.com/hahwul/dalfox/v2@latest',
      parseOutput: (stdout) => parseDalfoxOutput(stdout),
      allowNonZero: true,
      timeout: 300,
    })

    ctx.log.info(`dalfox found ${results.length} XSS issues`)
    return results
  },
})
