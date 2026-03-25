/**
 * Nikto web server scanner adapter.
 * Wraps: nikto
 * Source: pentest-enterprise-web
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { ToolNotFoundError } from '../../errors.js'
import { runTool, checkToolInstalled } from '../_utils/tool-runner.js'
import { parseNiktoOutput } from './parsers.js'

cli({
  provider: 'vuln',
  name: 'nikto-scan',
  description: 'Run Nikto web server scanner for misconfigurations and vulnerabilities',
  strategy: Strategy.FREE,
  domain: 'vuln-scan',
  args: {
    target: { type: 'string', required: true, help: 'Target URL or host' },
    tuning: { type: 'string', required: false, help: 'Scan tuning (e.g., "1234" for specific test types)' },
  },
  columns: ['finding', 'osvdb', 'severity'],
  timeout: 300,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const target = args.target as string
    const tuning = args.tuning as string | undefined

    if (!(await checkToolInstalled('nikto'))) {
      throw new ToolNotFoundError('nikto', 'apt install nikto / brew install nikto')
    }

    const niktoArgs = ['-h', target, '-Format', 'txt', '-nointeractive']
    if (tuning) niktoArgs.push('-Tuning', tuning)

    const result = await runTool({ tool: 'nikto', args: niktoArgs, timeout: 300, allowNonZero: true })
    const findings = parseNiktoOutput(result.stdout)
    ctx.log.info(`Nikto found ${findings.length} items`)
    return findings
  },
})
