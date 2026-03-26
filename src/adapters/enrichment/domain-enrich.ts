/**
 * Multi-source domain enrichment adapter.
 * Queries configured threat intelligence APIs in parallel and produces a consensus verdict.
 */

import { cli, Strategy, getRegistry } from '../../registry.js'
import type { AdapterResult, ExecContext, CliCommand } from '../../types.js'
import { loadAuth } from '../../auth/index.js'
import { executePipeline } from '../../pipeline/executor.js'
import { walkPath } from '../../utils/walk-path.js'

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

export function inferDomainVerdict(
  vtMalicious: number,
  threatfoxHits: number,
  urlhausStatus: string | undefined,
): string {
  if (vtMalicious > 3 || threatfoxHits > 0) return 'malicious'
  if (vtMalicious > 0 || (urlhausStatus && urlhausStatus !== 'no_results')) return 'suspicious'
  return 'clean'
}

cli({
  provider: 'enrichment',
  name: 'domain-enrich',
  description: 'Enrich domain from multiple threat intelligence sources in parallel',
  strategy: Strategy.FREE,
  domain: 'threat-intel',
  args: {
    domain: { type: 'string', required: true, help: 'Domain to enrich' },
  },
  columns: ['domain', 'verdict', 'vt_malicious', 'threatfox_hits', 'urlhaus_status', 'cert_count', 'sources_queried'],

  async func(_ctx: ExecContext, args: Record<string, unknown>): Promise<AdapterResult> {
    const domain = args.domain as string
    const registry = getRegistry()
    const sourcesQueried: string[] = []

    const vtCmd = registry.get('virustotal/domain-lookup')
    const threatfoxCmd = registry.get('abuse.ch/threatfox-search')
    const urlhausCmd = registry.get('abuse.ch/urlhaus-query')
    const crtshCmd = registry.get('crtsh/cert-search')
    const shodanCmd = registry.get('shodan/host-lookup')

    const queries: Promise<{ name: string; result: SourceResult }>[] = []

    if (vtCmd && (vtCmd.strategy === Strategy.FREE || loadAuth(vtCmd.auth ?? vtCmd.provider)?.api_key)) {
      queries.push(
        runCommand(vtCmd, { domain }).then(result => ({ name: 'virustotal', result })),
      )
    }

    if (threatfoxCmd) {
      queries.push(
        runCommand(threatfoxCmd, { ioc: domain }).then(result => ({ name: 'threatfox', result })),
      )
    }

    if (urlhausCmd) {
      queries.push(
        runCommand(urlhausCmd, { url: `http://${domain}` }).then(result => ({ name: 'urlhaus', result })),
      )
    }

    if (crtshCmd) {
      queries.push(
        runCommand(crtshCmd, { domain, limit: 100 }).then(result => ({ name: 'crtsh', result })),
      )
    }

    if (shodanCmd && loadAuth(shodanCmd.auth ?? shodanCmd.provider)?.api_key) {
      queries.push(
        runCommand(shodanCmd, { ip: domain }).then(result => ({ name: 'shodan', result })),
      )
    }

    const settled = await Promise.allSettled(queries)

    let vtMalicious = 0
    let vtCategories = ''
    let threatfoxHits = 0
    let urlhausStatus: string | undefined
    let certCount = 0
    let ports = ''

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
            vtMalicious = Number(row.malicious ?? 0)
            vtCategories = String(row.categories ?? '')
          }
          break
        }
        case 'threatfox': {
          const rows = Array.isArray(data) ? data : []
          threatfoxHits = rows.length
          break
        }
        case 'urlhaus': {
          const rows = Array.isArray(data) ? data : [data]
          const row = rows[0] as Record<string, unknown> | undefined
          urlhausStatus = row?.status != null ? String(row.status) : walkPath(data, ['url_status']) as string | undefined
          break
        }
        case 'crtsh': {
          const rows = Array.isArray(data) ? data : []
          certCount = rows.length
          break
        }
        case 'shodan': {
          const rows = Array.isArray(data) ? data : [data]
          const row = rows[0] as Record<string, unknown> | undefined
          if (row) {
            ports = String(row.ports ?? '')
          }
          break
        }
      }
    }

    const verdict = inferDomainVerdict(vtMalicious, threatfoxHits, urlhausStatus)

    return [{
      domain,
      vt_malicious: vtMalicious,
      vt_categories: vtCategories,
      threatfox_hits: threatfoxHits,
      urlhaus_status: urlhausStatus ?? 'no_results',
      cert_count: certCount,
      ports,
      verdict,
      sources_queried: sourcesQueried.join(', ') || 'none',
    }]
  },
})
