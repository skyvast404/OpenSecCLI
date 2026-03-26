/**
 * Multi-source hash enrichment adapter.
 * Queries configured threat intelligence APIs in parallel and produces a consensus verdict.
 */

import { cli, Strategy, getRegistry } from '../../registry.js'
import type { AdapterResult, ExecContext, CliCommand } from '../../types.js'
import { loadAuth } from '../../auth/index.js'
import { executePipeline } from '../../pipeline/executor.js'

interface SourceResult {
  ok: boolean
  data?: unknown
  error?: string
}

async function runCommand(
  cmd: CliCommand,
  args: Record<string, unknown>,
): Promise<SourceResult> {
  try {
    const authProvider = cmd.auth ?? cmd.provider
    const auth = cmd.strategy === Strategy.FREE ? null : loadAuth(authProvider)
    const ctx: ExecContext = {
      auth,
      args,
      log: { info() {}, warn() {}, error() {}, verbose() {}, debug() {}, step() {} },
    }

    let result: unknown
    if (cmd.func) {
      result = await cmd.func(ctx, args)
    } else if (cmd.pipeline) {
      result = await executePipeline(cmd.pipeline, { args, auth })
    } else {
      return { ok: false, error: 'No func or pipeline' }
    }

    return { ok: true, data: result }
  } catch (error) {
    return { ok: false, error: (error as Error).message }
  }
}

export function inferHashVerdict(
  vtDetections: number,
  hasMalwarebazaarMatch: boolean,
): string {
  if (vtDetections > 5 || hasMalwarebazaarMatch) return 'malicious'
  if (vtDetections > 0) return 'suspicious'
  return 'clean'
}

cli({
  provider: 'enrichment',
  name: 'hash-enrich',
  description: 'Enrich file hash from multiple threat intelligence sources in parallel',
  strategy: Strategy.FREE,
  domain: 'threat-intel',
  args: {
    hash: { type: 'string', required: true, help: 'File hash to enrich (MD5, SHA1, or SHA256)' },
  },
  columns: ['hash', 'verdict', 'vt_detections', 'vt_total', 'malware_family', 'file_type', 'threatfox_hits', 'sources_queried'],

  async func(_ctx: ExecContext, args: Record<string, unknown>): Promise<AdapterResult> {
    const hash = args.hash as string
    const registry = getRegistry()
    const sourcesQueried: string[] = []

    const vtCmd = registry.get('virustotal/hash-lookup')
    const malwarebazaarCmd = registry.get('abuse.ch/malwarebazaar-query')
    const threatfoxCmd = registry.get('abuse.ch/threatfox-search')

    const queries: Promise<{ name: string; result: SourceResult }>[] = []

    if (vtCmd && (vtCmd.strategy === Strategy.FREE || loadAuth(vtCmd.auth ?? vtCmd.provider)?.api_key)) {
      queries.push(
        runCommand(vtCmd, { hash }).then(result => ({ name: 'virustotal', result })),
      )
    }

    if (malwarebazaarCmd) {
      queries.push(
        runCommand(malwarebazaarCmd, { hash }).then(result => ({ name: 'malwarebazaar', result })),
      )
    }

    if (threatfoxCmd) {
      queries.push(
        runCommand(threatfoxCmd, { ioc: hash }).then(result => ({ name: 'threatfox', result })),
      )
    }

    const settled = await Promise.allSettled(queries)

    let vtDetections = 0
    let vtTotal = 0
    let malwareFamily = ''
    let fileType = ''
    let threatfoxHits = 0
    let hasMalwarebazaarMatch = false

    for (const entry of settled) {
      if (entry.status !== 'fulfilled') continue
      const { name, result } = entry.value
      if (!result.ok) continue

      sourcesQueried.push(name)
      const data = result.data

      switch (name) {
        case 'virustotal': {
          const rows = Array.isArray(data) ? data : [data]
          const row = rows[0] as Record<string, unknown> | undefined
          if (row) {
            vtDetections = Number(row.malicious ?? 0)
            vtTotal = vtDetections + Number(row.undetected ?? 0) + Number(row.suspicious ?? 0)
            malwareFamily = String(row.name ?? row.tags ?? '')
            fileType = String(row.file_type ?? '')
          }
          break
        }
        case 'malwarebazaar': {
          const rows = Array.isArray(data) ? data : []
          if (rows.length > 0) {
            hasMalwarebazaarMatch = true
            const row = rows[0] as Record<string, unknown>
            if (!fileType) fileType = String(row.file_type ?? '')
            if (!malwareFamily) malwareFamily = String(row.signature ?? '')
          }
          break
        }
        case 'threatfox': {
          const rows = Array.isArray(data) ? data : []
          threatfoxHits = rows.length
          break
        }
      }
    }

    const verdict = inferHashVerdict(vtDetections, hasMalwarebazaarMatch)

    return [{
      hash,
      vt_detections: vtDetections,
      vt_total: vtTotal,
      malware_family: malwareFamily,
      file_type: fileType,
      threatfox_hits: threatfoxHits,
      verdict,
      sources_queried: sourcesQueried.join(', ') || 'none',
    }]
  },
})
