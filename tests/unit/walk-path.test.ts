import { describe, it, expect } from 'vitest'
import { walkPath } from '../../src/utils/walk-path.js'

describe('walkPath', () => {
  it('resolves nested object paths', () => {
    const obj = { a: { b: { c: 42 } } }
    expect(walkPath(obj, ['a', 'b', 'c'])).toBe(42)
  })

  it('resolves array indices', () => {
    const obj = { items: [{ name: 'first' }, { name: 'second' }] }
    expect(walkPath(obj, ['items', '1', 'name'])).toBe('second')
  })

  it('returns undefined for missing keys', () => {
    const obj = { a: { b: 1 } }
    expect(walkPath(obj, ['a', 'x', 'y'])).toBeUndefined()
  })

  it('returns undefined for null/undefined in chain', () => {
    expect(walkPath(null, ['a'])).toBeUndefined()
    expect(walkPath(undefined, ['a'])).toBeUndefined()
  })

  it('returns root value for empty segments', () => {
    expect(walkPath(42, [])).toBe(42)
  })
})
