import { describe, it, expect, vi, beforeEach } from 'vitest'
import { executePipeline } from '../../src/pipeline/executor.js'
import YAML from 'js-yaml'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))

const MOCK_IP_RESPONSE = {
  data: {
    id: '8.8.8.8',
    attributes: {
      country: 'US',
      as_owner: 'GOOGLE',
      asn: 15169,
      last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 85, undetected: 5 },
      network: '8.8.8.0/24',
      tags: [],
    },
  },
}

describe('virustotal/ip-lookup', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: () => Promise.resolve(MOCK_IP_RESPONSE),
    }))
  })

  it('transforms VT IP response', async () => {
    const yamlPath = join(__dirname, '../../src/adapters/virustotal/ip-lookup.yaml')
    const def = YAML.load(readFileSync(yamlPath, 'utf-8')) as any

    const result = await executePipeline(def.pipeline, {
      args: { ip: '8.8.8.8' },
      auth: { api_key: 'test-key' },
    })

    const row = Array.isArray(result) ? result[0] : result
    expect(row).toHaveProperty('ip', '8.8.8.8')
    expect(row).toHaveProperty('country', 'US')
    expect(row).toHaveProperty('as_owner', 'GOOGLE')
    expect(row).toHaveProperty('malicious', 0)
  })
})
