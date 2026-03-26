import { describe, it, expect } from 'vitest'
import { inferDomainVerdict } from '../../src/adapters/enrichment/domain-enrich.js'
import { inferHashVerdict } from '../../src/adapters/enrichment/hash-enrich.js'
import { inferUrlVerdict } from '../../src/adapters/enrichment/url-enrich.js'

describe('domain-enrich verdict', () => {
  it('returns malicious when vt_malicious > 3', () => {
    expect(inferDomainVerdict(5, 0, undefined)).toBe('malicious')
  })

  it('returns malicious when threatfox has hits', () => {
    expect(inferDomainVerdict(0, 2, undefined)).toBe('malicious')
  })

  it('returns suspicious when vt_malicious > 0 but <= 3', () => {
    expect(inferDomainVerdict(2, 0, undefined)).toBe('suspicious')
  })

  it('returns suspicious when urlhaus has results', () => {
    expect(inferDomainVerdict(0, 0, 'online')).toBe('suspicious')
  })

  it('returns clean when no indicators', () => {
    expect(inferDomainVerdict(0, 0, undefined)).toBe('clean')
  })

  it('returns clean when urlhaus status is no_results', () => {
    expect(inferDomainVerdict(0, 0, 'no_results')).toBe('clean')
  })
})

describe('hash-enrich verdict', () => {
  it('returns malicious when vt_detections > 5', () => {
    expect(inferHashVerdict(10, false)).toBe('malicious')
  })

  it('returns malicious when malwarebazaar has match', () => {
    expect(inferHashVerdict(0, true)).toBe('malicious')
  })

  it('returns suspicious when vt_detections > 0 but <= 5', () => {
    expect(inferHashVerdict(3, false)).toBe('suspicious')
  })

  it('returns clean when no indicators', () => {
    expect(inferHashVerdict(0, false)).toBe('clean')
  })
})

describe('url-enrich verdict', () => {
  it('returns malicious when threatfox has hits', () => {
    expect(inferUrlVerdict(undefined, 3, 0)).toBe('malicious')
  })

  it('returns malicious when vt_domain_malicious > 3', () => {
    expect(inferUrlVerdict(undefined, 0, 5)).toBe('malicious')
  })

  it('returns suspicious when urlhaus has results', () => {
    expect(inferUrlVerdict('online', 0, 0)).toBe('suspicious')
  })

  it('returns suspicious when vt_domain_malicious > 0 but <= 3', () => {
    expect(inferUrlVerdict(undefined, 0, 2)).toBe('suspicious')
  })

  it('returns clean when no indicators', () => {
    expect(inferUrlVerdict(undefined, 0, 0)).toBe('clean')
  })

  it('returns clean when urlhaus is no_results', () => {
    expect(inferUrlVerdict('no_results', 0, 0)).toBe('clean')
  })
})
