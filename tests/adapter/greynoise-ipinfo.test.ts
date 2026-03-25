import { describe, it, expect, vi, beforeEach } from 'vitest'
import { executePipeline } from '../../src/pipeline/executor.js'
import YAML from 'js-yaml'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))

const MOCK_GREYNOISE_RESPONSE = {
  ip: '8.8.8.8',
  classification: 'benign',
  noise: true,
  riot: true,
  name: 'Google Public DNS',
  last_seen: '2024-03-25',
}

const MOCK_IPINFO_RESPONSE = {
  ip: '8.8.8.8',
  city: 'Mountain View',
  region: 'California',
  country: 'US',
  org: 'AS15169 Google LLC',
  timezone: 'America/Los_Angeles',
}

describe('greynoise/ip-check', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: () => Promise.resolve(MOCK_GREYNOISE_RESPONSE),
    }))
  })

  it('transforms response correctly', async () => {
    const yamlPath = join(__dirname, '../../src/adapters/greynoise/ip-check.yaml')
    const def = YAML.load(readFileSync(yamlPath, 'utf-8')) as any

    const result = await executePipeline(def.pipeline, {
      args: { ip: '8.8.8.8' },
      auth: { api_key: 'test-key' },
    })

    const row = Array.isArray(result) ? result[0] : result
    expect(row).toHaveProperty('ip', '8.8.8.8')
    expect(row).toHaveProperty('classification', 'benign')
    expect(row).toHaveProperty('noise', true)
    expect(row).toHaveProperty('riot', true)
    expect(row).toHaveProperty('name', 'Google Public DNS')
    expect(row).toHaveProperty('last_seen', '2024-03-25')
  })

  it('sends api_key as key header', async () => {
    const yamlPath = join(__dirname, '../../src/adapters/greynoise/ip-check.yaml')
    const def = YAML.load(readFileSync(yamlPath, 'utf-8')) as any

    await executePipeline(def.pipeline, {
      args: { ip: '8.8.8.8' },
      auth: { api_key: 'test-key' },
    })

    const fetchMock = vi.mocked(fetch)
    expect(fetchMock).toHaveBeenCalledOnce()
    const [url, options] = fetchMock.mock.calls[0]
    expect(url).toBe('https://api.greynoise.io/v3/community/8.8.8.8')
    expect((options as any).headers).toHaveProperty('key', 'test-key')
  })
})

describe('ipinfo/ip-lookup', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: () => Promise.resolve(MOCK_IPINFO_RESPONSE),
    }))
  })

  it('transforms response correctly', async () => {
    const yamlPath = join(__dirname, '../../src/adapters/ipinfo/ip-lookup.yaml')
    const def = YAML.load(readFileSync(yamlPath, 'utf-8')) as any

    const result = await executePipeline(def.pipeline, {
      args: { ip: '8.8.8.8' },
      auth: { api_key: 'test-key' },
    })

    const row = Array.isArray(result) ? result[0] : result
    expect(row).toHaveProperty('ip', '8.8.8.8')
    expect(row).toHaveProperty('city', 'Mountain View')
    expect(row).toHaveProperty('country', 'US')
    expect(row).toHaveProperty('org', 'AS15169 Google LLC')
    expect(row).toHaveProperty('region', 'California')
    expect(row).toHaveProperty('timezone', 'America/Los_Angeles')
  })

  it('sends api_key as Bearer authorization header', async () => {
    const yamlPath = join(__dirname, '../../src/adapters/ipinfo/ip-lookup.yaml')
    const def = YAML.load(readFileSync(yamlPath, 'utf-8')) as any

    await executePipeline(def.pipeline, {
      args: { ip: '8.8.8.8' },
      auth: { api_key: 'test-key' },
    })

    const fetchMock = vi.mocked(fetch)
    expect(fetchMock).toHaveBeenCalledOnce()
    const [url, options] = fetchMock.mock.calls[0]
    expect(url).toBe('https://ipinfo.io/8.8.8.8/json')
    expect((options as any).headers).toHaveProperty('Authorization', 'Bearer test-key')
  })
})
