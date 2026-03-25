import { describe, it, expect, vi, beforeEach } from 'vitest'

describe('enrichment/ip-enrich', () => {
  it('is registered after import', async () => {
    // Mock fetch to prevent real API calls
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: () => Promise.resolve({}),
    }))

    await import('../../src/adapters/_enrichment/ip-enrich.js')

    const { getRegistry } = await import('../../src/registry.js')
    const cmd = getRegistry().get('enrichment/ip-enrich')
    expect(cmd).toBeDefined()
    expect(cmd!.provider).toBe('enrichment')
    expect(cmd!.name).toBe('ip-enrich')
    expect(cmd!.strategy).toBe('FREE')  // Works with any subset of configured keys
  })
})
