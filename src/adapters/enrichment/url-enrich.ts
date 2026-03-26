/**
 * Multi-source URL enrichment adapter.
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

function extractDomain(url: string): string {
  try {
    return new URL(url).hostname
  } catch {
    const match = url.match(/^(?:https?:\/\/)?([^/:]+)/)
    return match ? match[1] : url
  }
}

export function inferUrlVerdict(
  urlhausStatus: string | undefined,
  threatfoxHits: number,
  vtDomainMalicious: number,
): string {
  if (threatfoxHits > 0 || vtDomainMalicious > 3) return 'malicious'
  if (
    (urlhausStatus && urlhausStatus !== 'no_results') ||
    vtDomainMalicious > 0
  ) return 'suspicious'
  return 'clean'
}

cli({
  provider: 'enrichment',
  name: 'url-enrich',
  description: 'Enrich URL from multiple threat intelligence sources in parallel',
  strategy: Strategy.FREE,
  domain: 'threat-intel',
  args: {
    url: { type: 'string', required: true, help: 'URL to enrich' },
  },
  columns: ['url', 'verdict', 'urlhaus_status', 'urlhaus_threat', 'threatfox_hits', 'vt_domain_malicious', 'sources_queried'],

  async func(_ctx: ExecContext, args: Record<string, unknown>): Promise<AdapterResult> {
    const url = args.url as string
    const domain = extractDomain(url)
    const registry = getRegistry()
    const sourcesQueried: string[] = []

    const urlhausCmd = registry.get('abuse.ch/urlhaus-query')
    const threatfoxCmd = registry.get('abuse.ch/threatfox-search')
    const vtCmd = registry.get('virustotal/domain-lookup')

    const queries: Promise<{ name: string; result: SourceResult }>[] = []

    if (urlhausCmd) {
      queries.push(
        runCommand(urlhausCmd, { url }).then(result => ({ name: 'urlhaus', result })),
      )
    }

    if (threatfoxCmd) {
      queries.push(
        runCommand(threatfoxCmd, { ioc: domain }).then(result => ({ name: 'threatfox', result })),
      )
    }

    if (vtCmd && (vtCmd.strategy === Strategy.FREE || loadAuth(vtCmd.auth ?? vtCmd.provider)?.api_key)) {
      queries.push(
        runCommand(vtCmd, { domain }).then(result => ({ name: 'virustotal', result })),
      )
    }

    const settled = await Promise.allSettled(queries)

    let urlhausStatus: string | undefined
    let urlhausThreat = ''
    let threatfoxHits = 0
    let vtDomainMalicious = 0

    for (const entry of settled) {
      if (entry.status !== 'fulfilled') continue
      const { name, result } = entry.value
      if (!result.ok) continue

      sourcesQueried.push(name)
      const data = result.data

      switch (name) {
        case 'urlhaus': {
          const rows = Array.isArray(data) ? data : [data]
          const row = rows[0] as Record<string, unknown> | undefined
          if (row) {
            urlhausStatus = row.status != null ? String(row.status) : undefined
            urlhausThreat = String(row.threat ?? '')
          }
          break
        }
        case 'threatfox': {
          const rows = Array.isArray(data) ? data : []
          threatfoxHits = rows.length
          break
        }
        case 'virustotal': {
          const rows = Array.isArray(data) ? data : [data]
          const row = rows[0] as Record<string, unknown> | undefined
          if (row) {
            vtDomainMalicious = Number(row.malicious ?? 0)
          }
          break
        }
      }
    }

    const verdict = inferUrlVerdict(urlhausStatus, threatfoxHits, vtDomainMalicious)

    return [{
      url,
      urlhaus_status: urlhausStatus ?? 'no_results',
      urlhaus_threat: urlhausThreat,
      threatfox_hits: threatfoxHits,
      vt_domain_malicious: vtDomainMalicious,
      verdict,
      sources_queried: sourcesQueried.join(', ') || 'none',
    }]
  },
})
