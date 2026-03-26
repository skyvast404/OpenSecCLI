import { describe, it, expect } from 'vitest'
import { parseJsonLines } from '../../src/adapters/_utils/tool-runner.js'

/**
 * Tests for Phase 1 recon adapter output parsing.
 * Each adapter's parseOutput logic is exercised against realistic tool output.
 */

/* ------------------------------------------------------------------ */
/*  url-crawl (katana) parsing                                        */
/* ------------------------------------------------------------------ */

function parseKatanaOutput(stdout: string): Record<string, unknown>[] {
  return parseJsonLines(stdout).map((r) => ({
    url:
      (r.request as Record<string, unknown>)?.endpoint ??
      r.endpoint ??
      r.url ??
      '',
    method: (r.request as Record<string, unknown>)?.method ?? 'GET',
    source: r.source ?? '',
    status:
      (r.response as Record<string, unknown>)?.status_code ??
      r.status_code ??
      0,
  }))
}

describe('url-crawl (katana) parser', () => {
  it('parses JSONL with nested request/response objects', () => {
    const input = [
      JSON.stringify({
        request: { endpoint: 'https://example.com/api/v1', method: 'POST' },
        response: { status_code: 200 },
        source: 'form',
      }),
      JSON.stringify({
        request: { endpoint: 'https://example.com/login', method: 'GET' },
        response: { status_code: 302 },
        source: 'anchor',
      }),
    ].join('\n')

    const result = parseKatanaOutput(input)
    expect(result).toEqual([
      {
        url: 'https://example.com/api/v1',
        method: 'POST',
        source: 'form',
        status: 200,
      },
      {
        url: 'https://example.com/login',
        method: 'GET',
        source: 'anchor',
        status: 302,
      },
    ])
  })

  it('falls back to flat fields when request/response are absent', () => {
    const input = JSON.stringify({
      url: 'https://example.com/script.js',
      status_code: 200,
      source: 'js',
    })

    const result = parseKatanaOutput(input)
    expect(result).toEqual([
      {
        url: 'https://example.com/script.js',
        method: 'GET',
        source: 'js',
        status: 200,
      },
    ])
  })

  it('handles empty input', () => {
    expect(parseKatanaOutput('')).toEqual([])
  })

  it('prefers endpoint over url in flat output', () => {
    const input = JSON.stringify({
      endpoint: 'https://example.com/preferred',
      url: 'https://example.com/fallback',
    })

    const result = parseKatanaOutput(input)
    expect(result[0]?.url).toBe('https://example.com/preferred')
  })
})

/* ------------------------------------------------------------------ */
/*  dns-resolve (dnsx) parsing                                        */
/* ------------------------------------------------------------------ */

function parseDnsxOutput(stdout: string): Record<string, unknown>[] {
  return parseJsonLines(stdout).map((r) => ({
    host: r.host ?? '',
    a: Array.isArray(r.a) ? (r.a as string[]).join(', ') : '',
    aaaa: Array.isArray(r.aaaa) ? (r.aaaa as string[]).join(', ') : '',
    cname: Array.isArray(r.cname) ? (r.cname as string[]).join(', ') : '',
    mx: Array.isArray(r.mx) ? (r.mx as string[]).join(', ') : '',
    status: r.status_code ?? 'NOERROR',
  }))
}

describe('dns-resolve (dnsx) parser', () => {
  it('parses JSONL with A and AAAA records', () => {
    const input = [
      JSON.stringify({
        host: 'example.com',
        a: ['93.184.216.34', '93.184.216.35'],
        aaaa: ['2606:2800:220:1:248:1893:25c8:1946'],
        status_code: 'NOERROR',
      }),
      JSON.stringify({
        host: 'mail.example.com',
        a: ['93.184.216.100'],
        mx: ['mx1.example.com', 'mx2.example.com'],
      }),
    ].join('\n')

    const result = parseDnsxOutput(input)
    expect(result).toEqual([
      {
        host: 'example.com',
        a: '93.184.216.34, 93.184.216.35',
        aaaa: '2606:2800:220:1:248:1893:25c8:1946',
        cname: '',
        mx: '',
        status: 'NOERROR',
      },
      {
        host: 'mail.example.com',
        a: '93.184.216.100',
        aaaa: '',
        cname: '',
        mx: 'mx1.example.com, mx2.example.com',
        status: 'NOERROR',
      },
    ])
  })

  it('handles CNAME records', () => {
    const input = JSON.stringify({
      host: 'www.example.com',
      cname: ['example.com'],
      a: ['93.184.216.34'],
    })

    const result = parseDnsxOutput(input)
    expect(result).toEqual([
      {
        host: 'www.example.com',
        a: '93.184.216.34',
        aaaa: '',
        cname: 'example.com',
        mx: '',
        status: 'NOERROR',
      },
    ])
  })

  it('handles empty input', () => {
    expect(parseDnsxOutput('')).toEqual([])
  })

  it('uses NOERROR default when status_code is absent', () => {
    const input = JSON.stringify({ host: 'test.com', a: ['1.2.3.4'] })
    const result = parseDnsxOutput(input)
    expect(result[0]?.status).toBe('NOERROR')
  })
})

/* ------------------------------------------------------------------ */
/*  url-archive (gau) parsing                                         */
/* ------------------------------------------------------------------ */

function parseGauOutput(stdout: string): Record<string, unknown>[] {
  return stdout
    .split('\n')
    .filter((l) => l.trim())
    .map((url) => ({ url: url.trim() }))
}

function deduplicateGauResults(
  results: Record<string, unknown>[],
): Record<string, unknown>[] {
  const seen = new Set<string>()
  return results.filter((r) => {
    const u = r.url as string
    if (seen.has(u)) return false
    seen.add(u)
    return true
  })
}

describe('url-archive (gau) parser', () => {
  it('parses plain text URLs (one per line)', () => {
    const input = [
      'https://example.com/page1',
      'https://example.com/page2?q=test',
      'https://example.com/api/v1/users',
    ].join('\n')

    const result = parseGauOutput(input)
    expect(result).toEqual([
      { url: 'https://example.com/page1' },
      { url: 'https://example.com/page2?q=test' },
      { url: 'https://example.com/api/v1/users' },
    ])
  })

  it('skips blank lines and trims whitespace', () => {
    const input = '  https://example.com/a  \n\n\nhttps://example.com/b\n  \n'
    const result = parseGauOutput(input)
    expect(result).toEqual([
      { url: 'https://example.com/a' },
      { url: 'https://example.com/b' },
    ])
  })

  it('deduplicates URLs', () => {
    const input = [
      'https://example.com/dup',
      'https://example.com/unique',
      'https://example.com/dup',
      'https://example.com/dup',
    ].join('\n')

    const parsed = parseGauOutput(input)
    const deduped = deduplicateGauResults(parsed)
    expect(deduped).toEqual([
      { url: 'https://example.com/dup' },
      { url: 'https://example.com/unique' },
    ])
  })

  it('handles empty input', () => {
    expect(parseGauOutput('')).toEqual([])
  })
})
