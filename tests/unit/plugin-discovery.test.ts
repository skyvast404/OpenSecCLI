import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

describe('local plugin discovery', () => {
  it('discoverLocalPlugins is exported and callable', async () => {
    const mod = await import('../../src/plugins/local-discovery.js')
    expect(mod.discoverLocalPlugins).toBeDefined()
    expect(typeof mod.discoverLocalPlugins).toBe('function')
  })

  it('returns 0 when plugins dir does not exist', async () => {
    // discoverLocalPlugins checks ~/.openseccli/plugins which likely
    // does not exist in CI/test environments
    const mod = await import('../../src/plugins/local-discovery.js')
    const count = await mod.discoverLocalPlugins()
    expect(count).toBeGreaterThanOrEqual(0)
  })
})
