/**
 * Container image vulnerability scanning adapter.
 * Wraps: trivy image (primary), grype (fallback)
 * Source: pentest-cloud-infrastructure
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { runExternalTool } from '../_utils/tool-runner.js'

interface TrivyVulnerability {
  PkgName: string
  InstalledVersion: string
  VulnerabilityID: string
  Severity: string
  FixedVersion?: string
}

interface TrivyResult {
  Vulnerabilities?: TrivyVulnerability[]
}

interface TrivyOutput {
  Results?: TrivyResult[]
}

interface GrypeMatch {
  artifact?: { name: string; version: string }
  vulnerability?: {
    id: string
    severity: string
    fix?: { versions?: string[] }
  }
}

interface GrypeOutput {
  matches?: GrypeMatch[]
}

export function parseTrivyOutput(stdout: string): Record<string, unknown>[] {
  try {
    const data = JSON.parse(stdout) as TrivyOutput
    const rows: Record<string, unknown>[] = []
    for (const result of data.Results ?? []) {
      for (const vuln of result.Vulnerabilities ?? []) {
        rows.push({
          package: vuln.PkgName,
          version: vuln.InstalledVersion,
          vulnerability: vuln.VulnerabilityID,
          severity: vuln.Severity,
          fixed_version: vuln.FixedVersion ?? '',
        })
      }
    }
    return rows
  } catch {
    return []
  }
}

export function parseGrypeOutput(stdout: string): Record<string, unknown>[] {
  try {
    const data = JSON.parse(stdout) as GrypeOutput
    return (data.matches ?? []).map((m) => ({
      package: m.artifact?.name ?? '',
      version: m.artifact?.version ?? '',
      vulnerability: m.vulnerability?.id ?? '',
      severity: m.vulnerability?.severity ?? '',
      fixed_version: m.vulnerability?.fix?.versions?.[0] ?? '',
    }))
  } catch {
    return []
  }
}

function parseOutput(stdout: string, tool: string): Record<string, unknown>[] {
  if (tool === 'trivy') {
    return parseTrivyOutput(stdout)
  }
  return parseGrypeOutput(stdout)
}

cli({
  provider: 'cloud',
  name: 'container-scan',
  description: 'Scan container images for vulnerabilities using trivy/grype',
  strategy: Strategy.FREE,
  domain: 'cloud-security',
  args: {
    image: { type: 'string', required: true, help: 'Container image to scan (e.g., nginx:latest)' },
    severity: {
      type: 'string',
      required: false,
      default: 'MEDIUM,HIGH,CRITICAL',
      help: 'Comma-separated severity levels to report',
    },
  },
  columns: ['package', 'version', 'vulnerability', 'severity', 'fixed_version'],
  timeout: 300,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const image = args.image as string
    const severity = (args.severity as string) ?? 'MEDIUM,HIGH,CRITICAL'

    const { results } = await runExternalTool({
      tools: ['trivy', 'grype'],
      buildArgs: (tool) => {
        if (tool === 'trivy') {
          return ['image', '--format', 'json', '--severity', severity, image]
        }
        // grype
        return [image, '-o', 'json']
      },
      parseOutput,
      timeout: 300,
    })

    // Filter by severity if using grype (trivy handles it natively)
    const severitySet = new Set(severity.split(',').map((s) => s.trim().toUpperCase()))
    const filtered = results.filter((r) => {
      const sev = (r.severity as string).toUpperCase()
      return severitySet.has(sev)
    })

    ctx.log.info(`Container scan found ${filtered.length} vulnerabilities in ${image}`)
    return filtered
  },
})
