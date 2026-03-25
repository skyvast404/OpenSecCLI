/**
 * SBOM (Software Bill of Materials) generator.
 * Wraps: syft (primary), cyclonedx-cli (fallback)
 * Source: pentest-supply-chain
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { ToolNotFoundError } from '../../errors.js'
import { runTool, findAvailableTool } from '../_utils/tool-runner.js'

interface SyftLicense {
  value?: string
  expression?: string
}

cli({
  provider: 'supply-chain',
  name: 'sbom',
  description: 'Generate Software Bill of Materials (SBOM) for a project',
  strategy: Strategy.FREE,
  domain: 'supply-chain',
  args: {
    path: { type: 'string', required: true, help: 'Project root or container image' },
    format: { type: 'string', default: 'json', choices: ['json', 'cyclonedx-json', 'spdx-json'], help: 'Output format' },
  },
  columns: ['name', 'version', 'type', 'license'],
  timeout: 120,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const path = args.path as string
    const format = args.format as string

    const tool = await findAvailableTool(['syft', 'cyclonedx-cli'])
    if (!tool) throw new ToolNotFoundError('syft, cyclonedx-cli', 'syft or cyclonedx-cli')

    if (tool === 'syft') {
      const syftArgs = [path, '-o', format === 'json' ? 'json' : format]
      const result = await runTool({ tool: 'syft', args: syftArgs, timeout: 120 })
      const output = JSON.parse(result.stdout) as {
        artifacts?: Array<Record<string, unknown>>
        components?: Array<Record<string, unknown>>
      }
      const artifacts = (output.artifacts ?? output.components ?? [])
      ctx.log.info(`SBOM generated: ${artifacts.length} components`)
      return artifacts.map((a) => ({
        name: a.name,
        version: a.version ?? '',
        type: a.type ?? ((a.purl as string) ?? '').split(':')[0] ?? '',
        license: Array.isArray(a.licenses)
          ? (a.licenses as SyftLicense[]).map((l) => l.value ?? l.expression ?? String(l)).join(', ')
          : '',
      }))
    }

    // cyclonedx fallback
    const cdxArgs = ['analyze', '--input-directory', path, '--format', 'json']
    const result = await runTool({ tool: 'cyclonedx-cli', args: cdxArgs, timeout: 120 })
    const output = JSON.parse(result.stdout) as { components?: Array<Record<string, unknown>> }
    const components = output.components ?? []
    ctx.log.info(`SBOM generated: ${components.length} components`)
    return components.map((c) => ({
      name: c.name,
      version: c.version ?? '',
      type: c.type ?? '',
      license: '',
    }))
  },
})
