import { describe, it, expect, vi, beforeEach } from 'vitest'
import { executeEnrich } from '../../src/pipeline/steps/enrich.js'

describe('enrich step', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
      if (url.includes('abuseipdb')) {
        return Promise.resolve({
          ok: true,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: () => Promise.resolve({ data: { abuseConfidenceScore: 95, countryCode: 'DE' } }),
        })
      }
      if (url.includes('virustotal')) {
        return Promise.resolve({
          ok: true,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: () => Promise.resolve({ data: { attributes: { last_analysis_stats: { malicious: 8 } } } }),
        })
      }
      if (url.includes('greynoise')) {
        return Promise.resolve({
          ok: true,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: () => Promise.resolve({ classification: 'malicious', noise: true }),
        })
      }
      return Promise.resolve({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: () => Promise.resolve({}),
      })
    }))
  })

  it('queries multiple sources in parallel and merges results', async () => {
    const params = {
      sources: [
        { name: 'AbuseIPDB', url: 'https://api.abuseipdb.com/api/v2/check', headers: { Key: 'k1' }, params: { ipAddress: '1.2.3.4' }, select: 'data', fields: { abuse_score: 'abuseConfidenceScore', country: 'countryCode' } },
        { name: 'VirusTotal', url: 'https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4', headers: { 'x-apikey': 'k2' }, fields: { malicious: 'data.attributes.last_analysis_stats.malicious' } },
        { name: 'GreyNoise', url: 'https://api.greynoise.io/v3/community/1.2.3.4', headers: { key: 'k3' }, fields: { classification: 'classification' } },
      ],
      timeout: 10,
    }

    const result = await executeEnrich(params, null, { args: {}, auth: {} })

    expect(Array.isArray(result)).toBe(true)
    expect(result.length).toBe(3)
    expect(result[0]).toHaveProperty('source', 'AbuseIPDB')
    expect(result[0]).toHaveProperty('abuse_score', 95)
    expect(result[1]).toHaveProperty('source', 'VirusTotal')
    expect(result[2]).toHaveProperty('source', 'GreyNoise')
    expect(result[2]).toHaveProperty('classification', 'malicious')
  })

  it('handles source failures gracefully', async () => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
      if (url.includes('fail')) return Promise.reject(new Error('Network error'))
      return Promise.resolve({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: () => Promise.resolve({ data: { score: 42 } }),
      })
    }))

    const params = {
      sources: [
        { name: 'Working', url: 'https://api.working.com/check', fields: { score: 'data.score' } },
        { name: 'Failing', url: 'https://api.fail.com/check', fields: { score: 'data.score' } },
      ],
      timeout: 5,
    }

    const result = await executeEnrich(params, null, { args: {}, auth: {} })
    expect(result.length).toBe(2)
    expect(result[0]).toHaveProperty('score', 42)
    expect(result[1]).toHaveProperty('error')
  })
})
