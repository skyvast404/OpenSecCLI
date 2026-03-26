/**
 * OWASP ZAP DAST scanning adapter.
 * Wraps: zap-baseline.py / zap-full-scan.py / zap-api-scan.py (primary), docker (fallback)
 * Source: dast-zap-scan
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { runTool, findAvailableTool } from '../_utils/tool-runner.js'
import { ToolNotFoundError } from '../../errors.js'

interface ZapAlert {
  alert: string
  riskdesc?: string
  confidence?: string
  instances?: Array<{ uri?: string }>
  desc?: string
  solution?: string
}

interface ZapSite {
  alerts?: ZapAlert[]
}

interface ZapReport {
  site?: ZapSite[]
}

const SCAN_SCRIPTS: Record<string, string> = {
  baseline: 'zap-baseline.py',
  full: 'zap-full-scan.py',
  api: 'zap-api-scan.py',
}

export function parseZapOutput(stdout: string): Record<string, unknown>[] {
  try {
    const data = JSON.parse(stdout) as ZapReport
    const rows: Record<string, unknown>[] = []
    for (const site of data.site ?? []) {
      for (const a of site.alerts ?? []) {
        const uri = a.instances?.[0]?.uri ?? ''
        rows.push({
          alert: a.alert ?? '',
          risk: a.riskdesc ?? '',
          confidence: a.confidence ?? '',
          url: uri,
          description: a.desc ?? '',
          solution: a.solution ?? '',
        })
      }
    }
    return rows
  } catch {
    return []
  }
}

cli({
  provider: 'dast',
  name: 'zap-scan',
  description: 'Run OWASP ZAP baseline or full scan against a web application',
  strategy: Strategy.FREE,
  domain: 'dast',
  args: {
    url: { type: 'string', required: true, help: 'Target URL' },
    scan_type: {
      type: 'string',
      default: 'baseline',
      choices: ['baseline', 'full', 'api'],
      help: 'Scan type',
    },
    api_spec: { type: 'string', required: false, help: 'OpenAPI/Swagger spec URL (for api scan type)' },
    minutes: { type: 'number', default: 5, help: 'Maximum scan duration in minutes' },
  },
  columns: ['alert', 'risk', 'confidence', 'url', 'description', 'solution'],
  timeout: 600,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const url = args.url as string
    const scanType = (args.scan_type as string) ?? 'baseline'
    const apiSpec = args.api_spec as string | undefined
    const minutes = (args.minutes as number) ?? 5

    const script = SCAN_SCRIPTS[scanType] ?? SCAN_SCRIPTS.baseline

    // Try the ZAP python script first, fall back to docker
    const zapScript = await findAvailableTool([script])

    if (zapScript) {
      const scriptArgs = scanType === 'api' && apiSpec
        ? ['-t', apiSpec, '-f', 'openapi', '-J', 'report.json', '-m', String(minutes)]
        : ['-t', url, '-J', 'report.json', '-m', String(minutes)]

      const result = await runTool({
        tool: zapScript,
        args: scriptArgs,
        timeout: minutes * 60 + 60,
        allowNonZero: true,
      })

      const rows = parseZapOutput(result.stdout)
      ctx.log.info(`ZAP ${scanType} scan found ${rows.length} alerts for ${url}`)
      return rows
    }

    // Fallback: docker
    const docker = await findAvailableTool(['docker'])
    if (!docker) {
      throw new ToolNotFoundError(
        `${script}, docker`,
        'pip install zaproxy / docker pull zaproxy/zap-stable',
      )
    }

    const dockerArgs = ['run', '--rm', '-t', 'zaproxy/zap-stable']
    if (scanType === 'api' && apiSpec) {
      dockerArgs.push(script, '-t', apiSpec, '-f', 'openapi', '-J', '/dev/stdout', '-m', String(minutes))
    } else {
      dockerArgs.push(script, '-t', url, '-J', '/dev/stdout', '-m', String(minutes))
    }

    const result = await runTool({
      tool: docker,
      args: dockerArgs,
      timeout: minutes * 60 + 120,
      allowNonZero: true,
    })

    const rows = parseZapOutput(result.stdout)
    ctx.log.info(`ZAP ${scanType} scan (docker) found ${rows.length} alerts for ${url}`)
    return rows
  },
})
