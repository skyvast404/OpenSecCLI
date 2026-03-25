import { describe, it, expect, vi, beforeEach } from 'vitest'
import { executePipeline } from '../../src/pipeline/executor.js'
import YAML from 'js-yaml'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))

// ── crt.sh mock (array response, no auth) ──────────────────────────

const MOCK_CRTSH_RESPONSE = [
  {
    id: 12345,
    common_name: '*.example.com',
    issuer_name: "Let's Encrypt",
    not_before: '2024-01-01',
    not_after: '2025-01-01',
    name_value: 'example.com',
    serial_number: 'ABCDEF123456',
  },
]

describe('crtsh/cert-search', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: () => Promise.resolve(MOCK_CRTSH_RESPONSE),
    }))
  })

  it('transforms crt.sh certificate response', async () => {
    const yamlPath = join(__dirname, '../../src/adapters/crtsh/cert-search.yaml')
    const def = YAML.load(readFileSync(yamlPath, 'utf-8')) as any

    const result = await executePipeline(def.pipeline, {
      args: { domain: 'example.com', limit: 10 },
      auth: null,
    })

    const row = Array.isArray(result) ? result[0] : result
    expect(row).toHaveProperty('id')
    expect(row).toHaveProperty('common_name', '*.example.com')
    expect(row).toHaveProperty('issuer')
    expect(row).toHaveProperty('not_before', '2024-01-01')
  })
})

// ── NVD cve-get mock (nested object, no auth) ──────────────────────

const MOCK_NVD_CVE_GET_RESPONSE = {
  vulnerabilities: [
    {
      cve: {
        id: 'CVE-2024-3094',
        descriptions: [{ lang: 'en', value: 'XZ Utils backdoor' }],
        published: '2024-03-29T00:00:00',
        lastModified: '2024-04-01T00:00:00',
        vulnStatus: 'Analyzed',
        metrics: {
          cvssMetricV31: [
            {
              cvssData: { baseScore: 10.0, baseSeverity: 'CRITICAL' },
            },
          ],
        },
      },
    },
  ],
}

describe('nvd/cve-get', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: () => Promise.resolve(MOCK_NVD_CVE_GET_RESPONSE),
    }))
  })

  it('transforms NVD CVE detail response', async () => {
    const yamlPath = join(__dirname, '../../src/adapters/nvd/cve-get.yaml')
    const def = YAML.load(readFileSync(yamlPath, 'utf-8')) as any

    const result = await executePipeline(def.pipeline, {
      args: { cve_id: 'CVE-2024-3094' },
      auth: null,
    })

    const row = Array.isArray(result) ? result[0] : result
    expect(row).toHaveProperty('cve_id', 'CVE-2024-3094')
    expect(row).toHaveProperty('cvss_score', 10.0)
    expect(row).toHaveProperty('severity', 'CRITICAL')
    expect(row).toHaveProperty('description', 'XZ Utils backdoor')
  })
})

// ── NVD cve-search mock (multiple results, no auth) ────────────────

const MOCK_NVD_CVE_SEARCH_RESPONSE = {
  vulnerabilities: [
    {
      cve: {
        id: 'CVE-2024-3094',
        descriptions: [{ lang: 'en', value: 'XZ Utils backdoor' }],
        published: '2024-03-29T00:00:00',
        vulnStatus: 'Analyzed',
        metrics: {
          cvssMetricV31: [
            {
              cvssData: { baseScore: 10.0, baseSeverity: 'CRITICAL' },
            },
          ],
        },
      },
    },
    {
      cve: {
        id: 'CVE-2022-44268',
        descriptions: [{ lang: 'en', value: 'ImageMagick arbitrary file read' }],
        published: '2023-02-06T00:00:00',
        vulnStatus: 'Modified',
        metrics: {
          cvssMetricV31: [
            {
              cvssData: { baseScore: 6.5, baseSeverity: 'MEDIUM' },
            },
          ],
        },
      },
    },
  ],
}

describe('nvd/cve-search', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: () => Promise.resolve(MOCK_NVD_CVE_SEARCH_RESPONSE),
    }))
  })

  it('transforms NVD CVE search response', async () => {
    const yamlPath = join(__dirname, '../../src/adapters/nvd/cve-search.yaml')
    const def = YAML.load(readFileSync(yamlPath, 'utf-8')) as any

    const result = await executePipeline(def.pipeline, {
      args: { keyword: 'xz', limit: 5 },
      auth: null,
    })

    expect(Array.isArray(result)).toBe(true)
    const rows = result as any[]
    expect(rows.length).toBeGreaterThanOrEqual(1)
    expect(rows[0]).toHaveProperty('cve_id', 'CVE-2024-3094')
  })
})

// ── Shodan host-lookup mock (single object, API_KEY auth) ──────────

const MOCK_SHODAN_RESPONSE = {
  ip_str: '8.8.8.8',
  org: 'Google LLC',
  os: 'Linux',
  isp: 'Google LLC',
  country_code: 'US',
  city: 'Mountain View',
  ports: [53, 443],
  vulns: ['CVE-2021-44228'],
  last_update: '2024-03-01T00:00:00',
}

describe('shodan/host-lookup', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: () => Promise.resolve(MOCK_SHODAN_RESPONSE),
    }))
  })

  it('transforms Shodan host response', async () => {
    const yamlPath = join(__dirname, '../../src/adapters/shodan/host-lookup.yaml')
    const def = YAML.load(readFileSync(yamlPath, 'utf-8')) as any

    const result = await executePipeline(def.pipeline, {
      args: { ip: '8.8.8.8' },
      auth: { api_key: 'test-key' },
    })

    const row = Array.isArray(result) ? result[0] : result
    expect(row).toHaveProperty('ip', '8.8.8.8')
    expect(row).toHaveProperty('org', 'Google LLC')
    expect(row).toHaveProperty('ports', '53, 443')
    expect(row).toHaveProperty('vulns', 'CVE-2021-44228')
  })
})
