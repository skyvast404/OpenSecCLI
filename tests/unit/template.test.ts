// tests/unit/template.test.ts
import { describe, it, expect } from 'vitest'
import { renderTemplate, evaluateExpression } from '../../src/pipeline/template.js'

describe('template engine', () => {
  const ctx = {
    args: { ip: '1.2.3.4', limit: 10 },
    auth: { api_key: 'test-key' },
    item: {
      data: {
        attributes: {
          last_analysis_stats: { malicious: 5, suspicious: 2 },
          tags: ['malware', 'trojan'],
        },
      },
      nested: [{ name: 'first' }, { name: 'second' }],
    },
    index: 0,
  }

  it('resolves deep nested paths', () => {
    const result = evaluateExpression('item.data.attributes.last_analysis_stats.malicious', ctx)
    expect(result).toBe(5)
  })

  it('resolves array index in path', () => {
    const result = evaluateExpression('item.nested.0.name', ctx)
    expect(result).toBe('first')
  })

  it('renders template with nested access', () => {
    const result = renderTemplate('score={{ item.data.attributes.last_analysis_stats.malicious }}', ctx)
    expect(result).toBe('score=5')
  })

  it('applies join filter to array', () => {
    const result = renderTemplate('{{ item.data.attributes.tags | join(", ") }}', ctx)
    expect(result).toBe('malware, trojan')
  })

  it('handles missing paths gracefully', () => {
    const result = evaluateExpression('item.data.nonexistent.deep.path', ctx)
    expect(result).toBeUndefined()
  })

  it('resolves args and auth', () => {
    expect(evaluateExpression('args.ip', ctx)).toBe('1.2.3.4')
    expect(evaluateExpression('auth.api_key', ctx)).toBe('test-key')
  })

  it('evaluates ternary', () => {
    const result = evaluateExpression("item.data.attributes.last_analysis_stats.malicious > 3 ? 'HIGH' : 'LOW'", ctx)
    expect(result).toBe('HIGH')
  })

  it('evaluates logical OR default', () => {
    const result = evaluateExpression("item.data.nonexistent || 'N/A'", ctx)
    expect(result).toBe('N/A')
  })
})
