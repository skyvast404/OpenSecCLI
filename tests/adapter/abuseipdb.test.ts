import { describe, it, expect, vi, beforeEach } from 'vitest'
import { executePipeline } from '../../src/pipeline/executor.js'
import YAML from 'js-yaml'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))

const MOCK_RESPONSE = {
  data: {
    ipAddress: '185.220.101.34',
    isPublic: true,
    abuseConfidenceScore: 100,
    countryCode: 'DE',
    isp: 'Hetzner Online GmbH',
    usageType: 'Data Center/Web Hosting/Transit',
    domain: 'hetzner.com',
    totalReports: 847,
    lastReportedAt: '2026-03-20T12:00:00+00:00',
  },
}

describe('abuseipdb/ip-check', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: () => Promise.resolve(MOCK_RESPONSE),
    }))
  })

  it('transforms API response into expected columns', async () => {
    const yamlPath = join(__dirname, '../../src/adapters/abuseipdb/ip-check.yaml')
    const def = YAML.load(readFileSync(yamlPath, 'utf-8')) as any

    const result = await executePipeline(def.pipeline, {
      args: { ip: '185.220.101.34', days: 90 },
      auth: { api_key: 'test-key' },
    })

    expect(result).toBeDefined()
    const row = Array.isArray(result) ? result[0] : result
    expect(row).toHaveProperty('ip', '185.220.101.34')
    expect(row).toHaveProperty('abuse_score', 100)
    expect(row).toHaveProperty('country', 'DE')
    expect(row).toHaveProperty('total_reports', 847)
  })
})
