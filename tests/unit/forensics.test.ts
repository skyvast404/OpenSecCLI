import { describe, it, expect } from 'vitest'
import {
  filterInterestingStrings,
  parseExiftoolOutput,
  parseFileOutput,
  parseBinwalkOutput,
} from '../../src/adapters/forensics/file-analyze.js'
import {
  normalizeStatus,
  parseChecksecJson,
  parseChecksecText,
} from '../../src/adapters/forensics/binary-check.js'
import {
  parseProtocolHierarchy,
  parseDnsQueries,
  parseConversations,
} from '../../src/adapters/forensics/pcap-summary.js'

describe('forensics/file-analyze', () => {
  it('filters interesting strings', () => {
    const raw = [
      'https://evil.com/payload',
      'just normal text',
      'password=hunter2',
      'ab',
      'flag{test_flag}',
    ].join('\n')

    const results = filterInterestingStrings(raw)
    expect(results.length).toBeGreaterThanOrEqual(3)
    expect(results.every((r) => r.tool === 'strings')).toBe(true)
  })

  it('parses exiftool JSON output', () => {
    const input = JSON.stringify([
      {
        FileName: 'test.jpg',
        FileSize: '1234',
        ImageWidth: 640,
        ImageHeight: 480,
        Artist: 'Hacker',
        ExifToolVersion: '12.0',
      },
    ])

    const results = parseExiftoolOutput(input)
    expect(results.some((r) => r.key === 'Artist')).toBe(true)
    // Should skip internal fields
    expect(results.some((r) => r.key === 'ExifToolVersion')).toBe(false)
    expect(results.some((r) => r.key === 'FileName')).toBe(false)
  })

  it('parses file command output', () => {
    const results = parseFileOutput('/tmp/test.bin: ELF 64-bit LSB executable')
    expect(results).toHaveLength(1)
    expect(results[0]).toEqual({
      tool: 'file',
      key: 'type',
      value: 'ELF 64-bit LSB executable',
    })
  })

  it('parses binwalk output', () => {
    const raw = [
      'DECIMAL       HEXADECIMAL     DESCRIPTION',
      '--------------------------------------------------------------------------------',
      '0             0x0             ELF, 64-bit LSB executable',
      '1024          0x400           gzip compressed data',
    ].join('\n')

    const results = parseBinwalkOutput(raw)
    expect(results).toHaveLength(2)
    expect(results[0].tool).toBe('binwalk')
  })
})

describe('forensics/binary-check', () => {
  it('normalizes protection status values', () => {
    expect(normalizeStatus('yes')).toBe('ENABLED')
    expect(normalizeStatus('Full')).toBe('ENABLED')
    expect(normalizeStatus('Full RELRO')).toBe('ENABLED')
    expect(normalizeStatus('no')).toBe('DISABLED')
    expect(normalizeStatus('disabled')).toBe('DISABLED')
    expect(normalizeStatus('Partial')).toBe('PARTIAL')
    expect(normalizeStatus('Partial RELRO')).toBe('PARTIAL')
  })

  it('parses checksec JSON output', () => {
    const input = JSON.stringify({
      '/bin/ls': {
        relro: 'full',
        canary: 'yes',
        nx: 'yes',
        pie: 'yes',
        rpath: 'no',
        runpath: 'no',
        symbols: 'no',
        fortify_source: 'yes',
        fortified: '5',
        fortifiable: '10',
      },
    })

    const rows = parseChecksecJson(input)
    expect(rows.length).toBeGreaterThan(0)
    expect(rows.find((r) => r.protection === 'RELRO')).toBeTruthy()
    expect(rows.find((r) => r.protection === 'NX (No-Execute)')).toBeTruthy()
  })

  it('returns empty on invalid JSON', () => {
    expect(parseChecksecJson('not json')).toEqual([])
  })

  it('parses checksec text output', () => {
    const raw = [
      'RELRO: Full RELRO',
      'Stack Canary: Enabled',
      'NX: Enabled',
    ].join('\n')

    const rows = parseChecksecText(raw)
    expect(rows).toHaveLength(3)
    expect(rows[0]).toMatchObject({
      protection: 'RELRO',
      status: 'ENABLED',
    })
  })
})

describe('forensics/pcap-summary', () => {
  it('parses DNS queries and counts duplicates', () => {
    const raw = [
      'example.com',
      'evil.com',
      'example.com',
      'example.com',
      'evil.com',
    ].join('\n')

    const rows = parseDnsQueries(raw)
    expect(rows).toHaveLength(2)
    // Sorted by count descending
    expect(rows[0]).toMatchObject({
      category: 'dns',
      key: 'example.com',
      count: '3',
    })
    expect(rows[1]).toMatchObject({
      category: 'dns',
      key: 'evil.com',
      count: '2',
    })
  })

  it('parses protocol hierarchy output', () => {
    const raw = [
      'Protocol Hierarchy Statistics',
      'Filter:',
      '',
      'eth                  frames:100  bytes:50000',
      '  ip                 frames:95   bytes:48000',
    ].join('\n')

    const rows = parseProtocolHierarchy(raw)
    expect(rows.length).toBeGreaterThanOrEqual(1)
    expect(rows.every((r) => r.category === 'protocol')).toBe(true)
  })

  it('parses IP conversations', () => {
    const raw = '192.168.1.1 <-> 10.0.0.1  50  5000  40  4000  90  9000  0.000  120.000'

    const rows = parseConversations(raw)
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({
      category: 'conversation',
      key: '192.168.1.1 <-> 10.0.0.1',
    })
  })
})
