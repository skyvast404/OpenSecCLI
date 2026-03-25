// tests/unit/auth-store.test.ts
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { saveAuth, loadAuth, removeAuth, listAuth } from '../../src/auth/store.js'
import { mkdirSync, rmSync, existsSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'

describe('auth store', () => {
  const origHome = process.env['HOME']
  const testHome = join(tmpdir(), `opensec-test-${Date.now()}`)

  beforeEach(() => {
    mkdirSync(testHome, { recursive: true })
    process.env['HOME'] = testHome
  })

  afterEach(() => {
    process.env['HOME'] = origHome
    if (existsSync(testHome)) rmSync(testHome, { recursive: true, force: true })
  })

  it('saves and loads credentials', () => {
    saveAuth('testprovider', { api_key: 'sk-123' })
    const creds = loadAuth('testprovider')
    expect(creds).toEqual({ api_key: 'sk-123' })
  })

  it('returns null for missing provider', () => {
    expect(loadAuth('nonexistent')).toBeNull()
  })

  it('prefers env var over file', () => {
    saveAuth('testprovider', { api_key: 'from-file' })
    process.env['OPENSECCLI_TESTPROVIDER_API_KEY'] = 'from-env'
    const creds = loadAuth('testprovider')
    expect(creds).toEqual({ api_key: 'from-env' })
    delete process.env['OPENSECCLI_TESTPROVIDER_API_KEY']
  })

  it('removes credentials', () => {
    saveAuth('testprovider', { api_key: 'sk-123' })
    expect(removeAuth('testprovider')).toBe(true)
    expect(loadAuth('testprovider')).toBeNull()
  })

  it('lists configured providers', () => {
    saveAuth('provider-a', { api_key: 'a' })
    saveAuth('provider-b', { api_key: 'b' })
    const providers = listAuth()
    expect(providers).toContain('provider-a')
    expect(providers).toContain('provider-b')
  })
})
