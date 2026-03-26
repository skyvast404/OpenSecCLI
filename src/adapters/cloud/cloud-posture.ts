/**
 * Cloud security posture audit adapter.
 * Wraps: prowler
 * Source: cloud-posture-audit
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { runTool, findAvailableTool } from '../_utils/tool-runner.js'
import { ToolNotFoundError } from '../../errors.js'

interface ProwlerFinding {
  CheckID?: string
  ServiceName?: string
  Severity?: string
  Status?: string
  StatusExtended?: string
  Region?: string
  ResourceArn?: string
}

/**
 * Parse prowler JSONL output.
 * Each line is a JSON object with finding details.
 */
export function parseProwlerOutput(stdout: string): Record<string, unknown>[] {
  const rows: Record<string, unknown>[] = []
  const lines = stdout.split('\n')

  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed.startsWith('{')) continue

    try {
      const finding = JSON.parse(trimmed) as ProwlerFinding
      rows.push({
        check_id: finding.CheckID ?? '',
        service: finding.ServiceName ?? '',
        severity: finding.Severity ?? '',
        status: finding.Status ?? '',
        finding: finding.StatusExtended ?? '',
        region: finding.Region ?? '',
      })
    } catch {
      // Skip non-JSON lines
    }
  }

  return rows
}

cli({
  provider: 'cloud',
  name: 'cloud-posture',
  description: 'Audit AWS/Azure/GCP cloud security posture against CIS/PCI-DSS benchmarks using prowler',
  strategy: Strategy.FREE,
  domain: 'cloud-security',
  args: {
    provider: {
      type: 'string',
      required: true,
      choices: ['aws', 'azure', 'gcp'],
      help: 'Cloud provider',
    },
    severity: {
      type: 'string',
      default: 'critical,high',
      help: 'Severity filter',
    },
    service: {
      type: 'string',
      required: false,
      help: 'Specific service to audit (e.g., s3, iam, ec2)',
    },
  },
  columns: ['check_id', 'service', 'severity', 'status', 'finding', 'region'],
  timeout: 600,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const cloudProvider = args.provider as string
    const severity = (args.severity as string) ?? 'critical,high'
    const service = args.service as string | undefined

    const tool = await findAvailableTool(['prowler'])
    if (!tool) {
      throw new ToolNotFoundError('prowler', 'pip install prowler')
    }

    const severityArgs = severity.split(',').map((s) => s.trim())

    const toolArgs = [
      cloudProvider,
      '-M', 'json',
      '-F', '/dev/stdout',
      '--severity', ...severityArgs,
    ]

    if (service) {
      toolArgs.push('--service', service)
    }

    const result = await runTool({
      tool,
      args: toolArgs,
      timeout: 600,
      allowNonZero: true,
    })

    const rows = parseProwlerOutput(result.stdout)
    ctx.log.info(`Prowler found ${rows.length} findings for ${cloudProvider}`)
    return rows
  },
})
