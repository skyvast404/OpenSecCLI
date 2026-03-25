import { describe, it, expect, vi, beforeEach } from 'vitest'
import { executePipeline } from '../../src/pipeline/executor.js'
import YAML from 'js-yaml'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ADAPTERS_DIR = join(__dirname, '../../src/adapters/abuse.ch')

/* ------------------------------------------------------------------ */
/*  threatfox-search                                                   */
/* ------------------------------------------------------------------ */

const MOCK_THREATFOX_RESPONSE = {
  query_status: 'ok',
  data: [
    {
      ioc: 'evil.com',
      ioc_type: 'domain',
      threat_type: 'botnet_cc',
      malware_printable: 'Emotet',
      confidence_level: 90,
      first_seen_utc: '2024-01-01',
      last_seen_utc: '2024-02-01',
      reporter: 'abuse_ch',
      tags: ['botnet'],
    },
  ],
}

describe('abuse.ch/threatfox-search', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: () => Promise.resolve(MOCK_THREATFOX_RESPONSE),
    }))
  })

  it('transforms ThreatFox IOC response', async () => {
    const yamlPath = join(ADAPTERS_DIR, 'threatfox-search.yaml')
    const def = YAML.load(readFileSync(yamlPath, 'utf-8')) as any

    const result = await executePipeline(def.pipeline, {
      args: { ioc: 'evil.com' },
      auth: null,
    })

    const row = Array.isArray(result) ? result[0] : result
    expect(row).toHaveProperty('ioc', 'evil.com')
    expect(row).toHaveProperty('threat_type', 'botnet_cc')
    expect(row).toHaveProperty('malware', 'Emotet')
    expect(row).toHaveProperty('confidence', 90)
    expect(row).toHaveProperty('first_seen', '2024-01-01')
    expect(row).toHaveProperty('tags', 'botnet')
  })
})

/* ------------------------------------------------------------------ */
/*  malwarebazaar-query                                                */
/* ------------------------------------------------------------------ */

const MOCK_MALWAREBAZAAR_RESPONSE = {
  query_status: 'ok',
  data: [
    {
      sha256_hash: 'abc123def456',
      file_type: 'exe',
      file_size: 123456,
      signature: 'Emotet',
      first_seen: '2024-01-01',
      last_seen: '2024-02-01',
      tags: ['trojan'],
      intelligence: { mail: 'test@mail.com' },
    },
  ],
}

describe('abuse.ch/malwarebazaar-query', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: () => Promise.resolve(MOCK_MALWAREBAZAAR_RESPONSE),
    }))
  })

  it('transforms MalwareBazaar hash lookup response', async () => {
    const yamlPath = join(ADAPTERS_DIR, 'malwarebazaar-query.yaml')
    const def = YAML.load(readFileSync(yamlPath, 'utf-8')) as any

    const result = await executePipeline(def.pipeline, {
      args: { hash: 'abc123def456' },
      auth: null,
    })

    const row = Array.isArray(result) ? result[0] : result
    expect(row).toHaveProperty('sha256', 'abc123def456')
    expect(row).toHaveProperty('file_type', 'exe')
    expect(row).toHaveProperty('signature', 'Emotet')
    expect(row).toHaveProperty('tags', 'trojan')
    expect(row).toHaveProperty('intelligence', 'test@mail.com')
  })
})

/* ------------------------------------------------------------------ */
/*  urlhaus-query                                                      */
/* ------------------------------------------------------------------ */

const MOCK_URLHAUS_RESPONSE = {
  url: 'http://evil.com/mal',
  url_status: 'online',
  threat: 'malware_download',
  tags: ['elf', 'mozi'],
  date_added: '2024-01-01',
  reporter: 'abuse_ch',
  takedown_time_seconds: 3600,
}

describe('abuse.ch/urlhaus-query', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: () => Promise.resolve(MOCK_URLHAUS_RESPONSE),
    }))
  })

  it('transforms URLhaus URL check response', async () => {
    const yamlPath = join(ADAPTERS_DIR, 'urlhaus-query.yaml')
    const def = YAML.load(readFileSync(yamlPath, 'utf-8')) as any

    const result = await executePipeline(def.pipeline, {
      args: { url: 'http://evil.com/mal' },
      auth: null,
    })

    const row = Array.isArray(result) ? result[0] : result
    expect(row).toHaveProperty('url', 'http://evil.com/mal')
    expect(row).toHaveProperty('status', 'online')
    expect(row).toHaveProperty('threat', 'malware_download')
    expect(row).toHaveProperty('reporter', 'abuse_ch')
  })
})

/* ------------------------------------------------------------------ */
/*  feodo-list                                                         */
/* ------------------------------------------------------------------ */

const MOCK_FEODO_RESPONSE = [
  {
    ip_address: '1.2.3.4',
    port: 443,
    status: 'online',
    malware: 'Dridex',
    first_seen: '2024-01-01',
    last_online: '2024-03-01',
    country: 'US',
  },
  {
    ip_address: '5.6.7.8',
    port: 8080,
    status: 'offline',
    malware: 'Emotet',
    first_seen: '2024-02-01',
    last_online: '2024-03-15',
    country: 'DE',
  },
]

describe('abuse.ch/feodo-list', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: () => Promise.resolve(MOCK_FEODO_RESPONSE),
    }))
  })

  it('transforms Feodo Tracker C2 list response', async () => {
    const yamlPath = join(ADAPTERS_DIR, 'feodo-list.yaml')
    const def = YAML.load(readFileSync(yamlPath, 'utf-8')) as any

    const result = await executePipeline(def.pipeline, {
      args: { limit: 20 },
      auth: null,
    })

    expect(Array.isArray(result)).toBe(true)
    const rows = result as any[]
    expect(rows.length).toBe(2)

    expect(rows[0]).toHaveProperty('ip', '1.2.3.4')
    expect(rows[0]).toHaveProperty('port', 443)
    expect(rows[0]).toHaveProperty('malware', 'Dridex')
    expect(rows[0]).toHaveProperty('status', 'online')
    expect(rows[0]).toHaveProperty('country', 'US')

    expect(rows[1]).toHaveProperty('ip', '5.6.7.8')
    expect(rows[1]).toHaveProperty('malware', 'Emotet')
  })
})

/* ------------------------------------------------------------------ */
/*  sslbl-search                                                       */
/* ------------------------------------------------------------------ */

const MOCK_SSLBL_RESPONSE = {
  sha1: 'abc123sha1',
  subject: 'CN=evil.com',
  issuer: 'CN=evil CA',
  reason: 'Dridex C2',
  listing_date: '2024-01-01',
}

describe('abuse.ch/sslbl-search', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: () => Promise.resolve(MOCK_SSLBL_RESPONSE),
    }))
  })

  it('transforms SSLBL certificate search response', async () => {
    const yamlPath = join(ADAPTERS_DIR, 'sslbl-search.yaml')
    const def = YAML.load(readFileSync(yamlPath, 'utf-8')) as any

    const result = await executePipeline(def.pipeline, {
      args: { hash: 'abc123sha1' },
      auth: null,
    })

    const row = Array.isArray(result) ? result[0] : result
    expect(row).toHaveProperty('sha1', 'abc123sha1')
    expect(row).toHaveProperty('reason', 'Dridex C2')
    expect(row).toHaveProperty('subject', 'CN=evil.com')
    expect(row).toHaveProperty('issuer', 'CN=evil CA')
    expect(row).toHaveProperty('listing_date', '2024-01-01')
  })
})
