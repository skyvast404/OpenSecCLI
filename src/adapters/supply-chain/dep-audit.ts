/**
 * Multi-ecosystem dependency auditor.
 * Wraps: npm audit + pip-audit + trivy (runs whichever are applicable)
 * Source: pentest-supply-chain
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { runTool, checkToolInstalled } from '../_utils/tool-runner.js'
import { existsSync } from 'node:fs'
import { join } from 'node:path'

interface VulnEntry {
  name?: string
  severity?: string
  via?: Array<Record<string, unknown>> | string
  fixAvailable?: unknown
}

cli({
  provider: 'supply-chain',
  name: 'dep-audit',
  description: 'Audit dependencies for known vulnerabilities (npm, pip, trivy)',
  strategy: Strategy.FREE,
  domain: 'supply-chain',
  args: {
    path: { type: 'string', required: true, help: 'Project root path' },
  },
  columns: ['ecosystem', 'package', 'severity', 'vulnerability', 'fix_version'],
  timeout: 120,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const path = args.path as string
    const results: Record<string, unknown>[] = []

    // npm audit
    if (existsSync(join(path, 'package-lock.json')) || existsSync(join(path, 'package.json'))) {
      if (await checkToolInstalled('npm')) {
        try {
          const r = await runTool({ tool: 'npm', args: ['audit', '--json'], cwd: path, allowNonZero: true })
          const output = JSON.parse(r.stdout) as { vulnerabilities?: Record<string, VulnEntry> }
          const vulns = output.vulnerabilities ?? {}
          for (const v of Object.values(vulns)) {
            const via = Array.isArray(v.via) ? (v.via[0]?.title ?? String(v.via)) : (v.via ?? '')
            results.push({
              ecosystem: 'npm',
              package: v.name,
              severity: v.severity,
              vulnerability: via,
              fix_version: v.fixAvailable ? String(v.fixAvailable) : 'N/A',
            })
          }
        } catch (e) { ctx.log.warn(`npm audit failed: ${(e as Error).message}`) }
      }
    }

    // pip-audit
    if (existsSync(join(path, 'requirements.txt'))) {
      if (await checkToolInstalled('pip-audit')) {
        try {
          const r = await runTool({
            tool: 'pip-audit',
            args: ['--format', 'json', '-r', join(path, 'requirements.txt')],
            allowNonZero: true,
          })
          const output = JSON.parse(r.stdout) as Array<Record<string, unknown>>
          for (const v of output) {
            const fixVersions = v.fix_versions as string[] | undefined
            results.push({
              ecosystem: 'pip',
              package: v.name,
              severity: 'medium',
              vulnerability: (v.id ?? v.description ?? '') as string,
              fix_version: fixVersions?.[0] ?? 'N/A',
            })
          }
        } catch (e) { ctx.log.warn(`pip-audit failed: ${(e as Error).message}`) }
      }
    }

    // trivy filesystem scan
    if (await checkToolInstalled('trivy')) {
      try {
        const r = await runTool({
          tool: 'trivy',
          args: ['fs', '--format', 'json', '--quiet', path],
          timeout: 120,
          allowNonZero: true,
        })
        const output = JSON.parse(r.stdout) as { Results?: Array<Record<string, unknown>> }
        for (const resultEntry of output.Results ?? []) {
          const vulns = (resultEntry.Vulnerabilities as Array<Record<string, unknown>>) ?? []
          for (const v of vulns) {
            results.push({
              ecosystem: (resultEntry.Type ?? 'unknown') as string,
              package: v.PkgName,
              severity: ((v.Severity as string) ?? 'medium').toLowerCase(),
              vulnerability: `${v.VulnerabilityID as string}: ${(v.Title as string) ?? ''}`,
              fix_version: (v.FixedVersion as string) ?? 'N/A',
            })
          }
        }
      } catch (e) { ctx.log.warn(`trivy failed: ${(e as Error).message}`) }
    }

    ctx.log.info(`Found ${results.length} vulnerable dependencies`)
    return results
  },
})
