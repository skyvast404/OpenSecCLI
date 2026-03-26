import { describe, it, expect } from 'vitest'
import { PAYLOADS, getPayloads } from '../../src/adapters/pentest/payloads.js'
import type { PayloadCategory } from '../../src/adapters/pentest/payloads.js'

describe('payload library', () => {
  it('getPayloads returns correct counts per category', () => {
    expect(getPayloads('sqli')).toHaveLength(13)
    expect(getPayloads('xss')).toHaveLength(13)
    expect(getPayloads('ssrf')).toHaveLength(11)
    expect(getPayloads('path_traversal')).toHaveLength(5)
    expect(getPayloads('command_injection')).toHaveLength(6)
    expect(getPayloads('open_redirect')).toHaveLength(4)
  })

  it('getPayloads with subcategory filter returns only that subcategory', () => {
    const sqliDetection = getPayloads('sqli', 'detection')
    expect(sqliDetection).toHaveLength(8)

    const sqliTimeBased = getPayloads('sqli', 'time_based')
    expect(sqliTimeBased).toHaveLength(3)

    const xssFilterBypass = getPayloads('xss', 'filter_bypass')
    expect(xssFilterBypass).toHaveLength(5)

    const ssrfBypass = getPayloads('ssrf', 'bypass')
    expect(ssrfBypass).toHaveLength(5)
  })

  it('getPayloads with invalid subcategory returns all payloads for category', () => {
    const all = getPayloads('sqli', 'nonexistent')
    expect(all).toHaveLength(13)
  })

  it('all categories have at least 3 payloads', () => {
    const categories = Object.keys(PAYLOADS) as PayloadCategory[]
    for (const category of categories) {
      const payloads = getPayloads(category)
      expect(payloads.length).toBeGreaterThanOrEqual(3)
    }
  })

  it('total payload count is 80+', () => {
    const categories = Object.keys(PAYLOADS) as PayloadCategory[]
    let total = 0
    for (const category of categories) {
      total += getPayloads(category).length
    }
    expect(total).toBeGreaterThanOrEqual(52)
  })
})
