import { describe, it, expect } from 'vitest'
import { parseDockleOutput } from '../../src/adapters/cloud/container-lint.js'
import { parseCrlfuzzOutput } from '../../src/adapters/vuln/crlf-scan.js'
import { parseCommixOutput } from '../../src/adapters/pentest/cmdi-scan.js'
import { parseRustscanOutput } from '../../src/adapters/recon/fast-scan.js'
import { parseWaybackurlsOutput } from '../../src/adapters/recon/wayback-urls.js'
import { parseGospiderOutput } from '../../src/adapters/recon/web-spider.js'

describe('cloud/container-lint (dockle)', () => {
  it('parses dockle JSON output with details', () => {
    const output = {
      details: [
        { code: 'CIS-DI-0001', level: 'WARN', title: 'Create a user for the container', alerts: ['Last user should not be root'] },
        { code: 'CIS-DI-0005', level: 'INFO', title: 'Enable Content trust', alerts: [] },
        { code: 'CIS-DI-0008', level: 'FATAL', title: 'Confirm safety of setuid/setgid files', alerts: ['/usr/bin/passwd', '/usr/bin/chsh'] },
      ],
    }

    const rows = parseDockleOutput(JSON.stringify(output))
    expect(rows).toHaveLength(3)
    expect(rows[0]).toEqual({
      code: 'CIS-DI-0001',
      level: 'high',
      title: 'Create a user for the container',
      alerts: 'Last user should not be root',
    })
    expect(rows[1]).toEqual({
      code: 'CIS-DI-0005',
      level: 'medium',
      title: 'Enable Content trust',
      alerts: '',
    })
    expect(rows[2]).toEqual({
      code: 'CIS-DI-0008',
      level: 'high',
      title: 'Confirm safety of setuid/setgid files',
      alerts: '/usr/bin/passwd; /usr/bin/chsh',
    })
  })

  it('returns empty array for invalid JSON', () => {
    expect(parseDockleOutput('not json')).toEqual([])
  })

  it('handles empty details', () => {
    expect(parseDockleOutput(JSON.stringify({ details: [] }))).toEqual([])
    expect(parseDockleOutput(JSON.stringify({}))).toEqual([])
  })

  it('maps SKIP level to info', () => {
    const output = {
      details: [
        { code: 'DKL-DI-0001', level: 'SKIP', title: 'Skipped check', alerts: [] },
      ],
    }
    const rows = parseDockleOutput(JSON.stringify(output))
    expect(rows[0]?.level).toBe('info')
  })
})

describe('vuln/crlf-scan (crlfuzz)', () => {
  it('parses crlfuzz JSONL output', () => {
    const line1 = JSON.stringify({ url: 'https://example.com', vulnerable: true, payload: '%0d%0aSet-Cookie:crlf=injection' })
    const line2 = JSON.stringify({ url: 'https://example.com/path', vulnerable: false })
    const stdout = `${line1}\n${line2}\n`

    const rows = parseCrlfuzzOutput(stdout)
    expect(rows).toHaveLength(2)
    expect(rows[0]).toEqual({
      url: 'https://example.com',
      vulnerable: true,
      payload: '%0d%0aSet-Cookie:crlf=injection',
    })
    expect(rows[1]).toEqual({
      url: 'https://example.com/path',
      vulnerable: false,
      payload: '',
    })
  })

  it('returns empty array for empty input', () => {
    expect(parseCrlfuzzOutput('')).toEqual([])
  })
})

describe('pentest/cmdi-scan (commix)', () => {
  it('parses commix stdout with injection findings', () => {
    const stdout = `
[*] Testing connection to the target URL.
[+] The (GET) parameter 'cmd' is injectable.
[+] The (results_based) command injection technique
[+] Payload: ;echo test
[+] The target operating system is "Linux"
`

    const rows = parseCommixOutput(stdout)
    expect(rows).toHaveLength(1)
    expect(rows[0]).toEqual({
      parameter: 'cmd (GET)',
      technique: 'results_based',
      payload: ';echo test',
      os: 'Linux',
    })
  })

  it('returns empty array when no injection found', () => {
    const stdout = `
[*] Testing connection to the target URL.
[!] The target URL is not injectable.
`
    expect(parseCommixOutput(stdout)).toEqual([])
  })

  it('handles injectable param without explicit payload', () => {
    const stdout = `
[+] The (POST) parameter 'input' is injectable.
[+] The (blind) command injection technique
`

    const rows = parseCommixOutput(stdout)
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({
      parameter: 'input (POST)',
      technique: 'blind',
      payload: '',
    })
  })
})

describe('recon/fast-scan (rustscan)', () => {
  it('parses rustscan greppable output', () => {
    const stdout = `192.168.1.1 -> [22,80,443]\n10.0.0.1 -> [8080]\n`

    const rows = parseRustscanOutput(stdout)
    expect(rows).toHaveLength(4)
    expect(rows[0]).toEqual({ ip: '192.168.1.1', port: 22, protocol: 'tcp', status: 'open' })
    expect(rows[1]).toEqual({ ip: '192.168.1.1', port: 80, protocol: 'tcp', status: 'open' })
    expect(rows[2]).toEqual({ ip: '192.168.1.1', port: 443, protocol: 'tcp', status: 'open' })
    expect(rows[3]).toEqual({ ip: '10.0.0.1', port: 8080, protocol: 'tcp', status: 'open' })
  })

  it('returns empty array for empty output', () => {
    expect(parseRustscanOutput('')).toEqual([])
  })

  it('handles single port result', () => {
    const stdout = `10.0.0.5 -> [3306]\n`
    const rows = parseRustscanOutput(stdout)
    expect(rows).toHaveLength(1)
    expect(rows[0]).toEqual({ ip: '10.0.0.5', port: 3306, protocol: 'tcp', status: 'open' })
  })
})

describe('recon/wayback-urls (waybackurls)', () => {
  it('parses plain text URL output and deduplicates', () => {
    const stdout = `https://example.com/page1
https://example.com/page2
https://example.com/page1
https://example.com/api/v1
https://example.com/page2
`

    const rows = parseWaybackurlsOutput(stdout)
    expect(rows).toHaveLength(3)
    expect(rows[0]).toEqual({ url: 'https://example.com/page1' })
    expect(rows[1]).toEqual({ url: 'https://example.com/page2' })
    expect(rows[2]).toEqual({ url: 'https://example.com/api/v1' })
  })

  it('returns empty array for empty input', () => {
    expect(parseWaybackurlsOutput('')).toEqual([])
  })
})

describe('recon/web-spider (gospider)', () => {
  it('parses gospider JSONL output', () => {
    const line1 = JSON.stringify({ output: 'https://example.com/about', type: 'href', source: 'https://example.com/', status_code: 200 })
    const line2 = JSON.stringify({ output: 'https://example.com/robots.txt', type: 'robotstxt', source: 'https://example.com/', status_code: 200 })
    const stdout = `${line1}\n${line2}\n`

    const rows = parseGospiderOutput(stdout)
    expect(rows).toHaveLength(2)
    expect(rows[0]).toEqual({
      url: 'https://example.com/about',
      source: 'https://example.com/',
      type: 'href',
      status: 200,
    })
    expect(rows[1]).toEqual({
      url: 'https://example.com/robots.txt',
      source: 'https://example.com/',
      type: 'robotstxt',
      status: 200,
    })
  })

  it('returns empty array for empty input', () => {
    expect(parseGospiderOutput('')).toEqual([])
  })

  it('handles entries with missing fields', () => {
    const line = JSON.stringify({ output: 'https://example.com/page' })
    const rows = parseGospiderOutput(line)
    expect(rows).toHaveLength(1)
    expect(rows[0]).toEqual({
      url: 'https://example.com/page',
      source: '',
      type: '',
      status: 0,
    })
  })
})
