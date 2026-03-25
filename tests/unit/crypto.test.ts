import { describe, it, expect } from 'vitest'
import { identifyHash } from '../../src/adapters/crypto/hash-id.js'

describe('crypto hash-id', () => {
  it('identifies MD5', () => {
    const result = identifyHash('5d41402abc4b2a76b9719d911017c592')
    expect(result.some((r) => r.algorithm === 'MD5')).toBe(true)
  })

  it('identifies SHA-256', () => {
    const result = identifyHash('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    expect(result.some((r) => r.algorithm === 'SHA-256')).toBe(true)
  })

  it('identifies bcrypt', () => {
    const result = identifyHash('$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy')
    expect(result.some((r) => r.algorithm === 'bcrypt')).toBe(true)
  })

  it('returns unknown for unrecognized input', () => {
    const result = identifyHash('not-a-hash')
    expect(result[0].algorithm).toBe('unknown')
  })
})
