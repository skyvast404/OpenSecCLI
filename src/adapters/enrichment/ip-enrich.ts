/**
 * Multi-source IP enrichment adapter.
 * Queries configured threat intelligence APIs in parallel and produces a consensus verdict.
 * ThreatFox is always included (free, no key needed).
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { loadAuth } from '../../auth/index.js'
import { walkPath } from '../../utils/walk-path.js'

interface SourceConfig {
  name: string
  provider: string
  url: (ip: string) => string
  headers: (key: string) => Record<string, string>
  select?: string
  fields: Record<string, string>
}

const SOURCES: SourceConfig[] = [
  {
    name: 'AbuseIPDB',
    provider: 'abuseipdb',
    url: (ip) => `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`,
    headers: (key) => ({ Key: key, Accept: 'application/json' }),
    select: 'data',
    fields: { abuse_score: 'abuseConfidenceScore', country: 'countryCode', isp: 'isp', total_reports: 'totalReports' },
  },
  {
    name: 'VirusTotal',
    provider: 'virustotal',
    url: (ip) => `https://www.virustotal.com/api/v3/ip_addresses/${ip}`,
    headers: (key) => ({ 'x-apikey': key, Accept: 'application/json' }),
    fields: { malicious: 'data.attributes.last_analysis_stats.malicious', as_owner: 'data.attributes.as_owner' },
  },
  {
    name: 'GreyNoise',
    provider: 'greynoise',
    url: (ip) => `https://api.greynoise.io/v3/community/${ip}`,
    headers: (key) => ({ key, Accept: 'application/json' }),
    fields: { classification: 'classification', noise: 'noise', riot: 'riot' },
  },
  {
    name: 'ipinfo',
    provider: 'ipinfo',
    url: (ip) => `https://ipinfo.io/${ip}/json`,
    headers: (key) => ({ Authorization: `Bearer ${key}`, Accept: 'application/json' }),
    fields: { country: 'country', org: 'org', city: 'city' },
  },
  {
    name: 'ThreatFox',
    provider: 'abuse.ch',
    url: () => 'https://threatfox-api.abuse.ch/api/v1/',
    headers: () => ({ 'Content-Type': 'application/json' }),
    fields: { threat_type: 'data.0.threat_type', malware: 'data.0.malware_printable' },
  },
]

cli({
  provider: 'enrichment',
  name: 'ip-enrich',
  description: 'Enrich IP address from multiple threat intelligence sources in parallel',
  strategy: Strategy.FREE,
  domain: 'threat-intel',
  args: {
    ip: { type: 'string', required: true, help: 'IP address to enrich' },
  },
  columns: ['source', 'status', 'verdict', 'detail'],

  async func(ctx: ExecContext, args: Record<string, unknown>): Promise<unknown> {
    const ip = args.ip as string
    const timeout = 15_000

    const activeSources = SOURCES.filter(s => {
      if (s.provider === 'abuse.ch') return true  // Free, no key needed
      const creds = loadAuth(s.provider)
      return creds?.api_key != null
    })

    if (activeSources.length === 0) {
      return [{ source: '-', status: 'error', verdict: '-', detail: 'No API keys configured. Run: opensec auth add <provider> --api-key' }]
    }

    const results = await Promise.allSettled(
      activeSources.map(async (source) => {
        const creds = loadAuth(source.provider)
        const apiKey = creds?.api_key ?? ''

        const fetchOpts: RequestInit = {
          method: source.provider === 'abuse.ch' ? 'POST' : 'GET',
          headers: source.headers(apiKey as string),
          signal: AbortSignal.timeout(timeout),
        }

        if (source.provider === 'abuse.ch') {
          fetchOpts.body = JSON.stringify({ query: 'search_ioc', search_term: ip })
        }

        const response = await fetch(source.url(ip), fetchOpts)
        if (!response.ok) {
          return { source: source.name, status: 'error', verdict: '-', detail: `HTTP ${response.status}` }
        }

        const data = await response.json()
        let selected = data
        if (source.select) {
          selected = walkPath(data, source.select.split('.'))
        }

        const detail: string[] = []
        for (const [label, path] of Object.entries(source.fields)) {
          const val = walkPath(selected, path.split('.'))
          if (val !== undefined && val !== null) {
            detail.push(`${label}: ${val}`)
          }
        }

        const verdict = inferVerdict(source.name, selected, source.fields)

        return {
          source: source.name,
          status: 'ok',
          verdict,
          detail: detail.join(', ') || '-',
        }
      }),
    )

    return results.map((r, i) => {
      if (r.status === 'fulfilled') return r.value
      return {
        source: activeSources[i].name,
        status: 'error',
        verdict: '-',
        detail: (r.reason as Error).message,
      }
    })
  },
})

function inferVerdict(source: string, data: unknown, _fields: Record<string, string>): string {
  if (!data) return '-'

  const get = (path: string) => walkPath(data, path.split('.'))

  switch (source) {
    case 'AbuseIPDB': {
      const score = Number(get('abuseConfidenceScore') ?? 0)
      if (score >= 80) return 'Malicious'
      if (score >= 30) return 'Suspicious'
      return 'Clean'
    }
    case 'VirusTotal': {
      const mal = Number(get('data.attributes.last_analysis_stats.malicious') ?? 0)
      if (mal >= 5) return 'Malicious'
      if (mal >= 1) return 'Suspicious'
      return 'Clean'
    }
    case 'GreyNoise': {
      const cls = get('classification')
      if (cls === 'malicious') return 'Malicious'
      if (cls === 'benign') return 'Clean'
      return String(cls ?? '-')
    }
    case 'ThreatFox': {
      const threat = get('data.0.threat_type')
      return threat ? 'Known IOC' : 'Not found'
    }
    default:
      return '-'
  }
}

