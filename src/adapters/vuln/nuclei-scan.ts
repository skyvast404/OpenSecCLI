/**
 * Nuclei vulnerability scanner adapter.
 * Wraps: nuclei
 * Source: pentest-enterprise-web
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { ToolNotFoundError } from '../../errors.js'
import { runTool, checkToolInstalled } from '../_utils/tool-runner.js'
import { parseNucleiOutput } from './parsers.js'

cli({
  provider: 'vuln',
  name: 'nuclei-scan',
  description: 'Run nuclei vulnerability scanner against target URL(s)',
  strategy: Strategy.FREE,
  args: {
    target: { type: 'string', required: true, help: 'Target URL or file with URLs' },
    templates: { type: 'string', required: false, help: 'Template tags to use (e.g., "cve,misconfig")' },
    severity: { type: 'string', required: false, default: 'medium,high,critical', help: 'Minimum severity filter' },
    rate_limit: { type: 'number', required: false, default: 150, help: 'Max requests per second' },
  },
  columns: ['template', 'name', 'severity', 'host', 'matched_url', 'tags'],
  timeout: 600,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const target = args.target as string
    const templates = args.templates as string | undefined
    const severity = args.severity as string
    const rateLimit = args.rate_limit as number

    if (!(await checkToolInstalled('nuclei'))) {
      throw new ToolNotFoundError('nuclei', 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest')
    }

    const nucleiArgs = ['-jsonl', '-silent', '-rl', String(rateLimit), '-severity', severity]
    if (target.endsWith('.txt')) {
      nucleiArgs.push('-l', target)
    } else {
      nucleiArgs.push('-u', target)
    }
    if (templates) nucleiArgs.push('-tags', templates)

    const result = await runTool({
      tool: 'nuclei',
      args: nucleiArgs,
      timeout: 600,
      allowNonZero: true,
    })

    const findings = parseNucleiOutput(result.stdout)
    ctx.log.info(`Nuclei found ${findings.length} issues`)
    return findings
  },
})
