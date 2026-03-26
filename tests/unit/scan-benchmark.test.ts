import { describe, it, expect } from 'vitest'
import {
  normalizeCwe,
  scoreStrict,
  scoreLoose,
  calcMetrics,
} from '../../src/adapters/scan/benchmark.js'

describe('normalizeCwe', () => {
  it('strips leading zeros and uppercases', () => {
    expect(normalizeCwe('cwe-089')).toBe('CWE-89')
  })

  it('keeps already-normalized CWEs unchanged', () => {
    expect(normalizeCwe('CWE-79')).toBe('CWE-79')
  })

  it('handles mixed case with leading zeros', () => {
    expect(normalizeCwe('Cwe-0079')).toBe('CWE-79')
  })

  it('handles single digit CWE', () => {
    expect(normalizeCwe('cwe-001')).toBe('CWE-1')
  })

  it('returns uppercased string for non-standard input', () => {
    expect(normalizeCwe('not-a-cwe')).toBe('NOT-A-CWE')
  })
})

describe('scoreStrict', () => {
  it('counts exact CWE match as TP', () => {
    const result = scoreStrict(['CWE-89'], ['CWE-89'])
    expect(result.tp).toBe(1)
    expect(result.fp).toBe(0)
    expect(result.fn).toBe(0)
  })

  it('counts mismatch as FP and FN', () => {
    const result = scoreStrict(['CWE-79'], ['CWE-89'])
    expect(result.tp).toBe(0)
    expect(result.fp).toBe(1)
    expect(result.fn).toBe(1)
  })

  it('handles multiple predictions and truths', () => {
    const result = scoreStrict(['CWE-89', 'CWE-79', 'CWE-22'], ['CWE-89', 'CWE-78'])
    expect(result.tp).toBe(1)
    expect(result.fp).toBe(2)
    expect(result.fn).toBe(1)
  })

  it('normalizes before comparing', () => {
    const result = scoreStrict(['cwe-089'], ['CWE-89'])
    expect(result.tp).toBe(1)
    expect(result.fp).toBe(0)
    expect(result.fn).toBe(0)
  })

  it('handles empty predictions', () => {
    const result = scoreStrict([], ['CWE-89'])
    expect(result.tp).toBe(0)
    expect(result.fp).toBe(0)
    expect(result.fn).toBe(1)
  })

  it('handles empty truths', () => {
    const result = scoreStrict(['CWE-89'], [])
    expect(result.tp).toBe(0)
    expect(result.fp).toBe(1)
    expect(result.fn).toBe(0)
  })
})

describe('scoreLoose', () => {
  it('matches equivalent CWEs via equivalence map', () => {
    // CWE-943 ↔ CWE-89
    const result = scoreLoose(['CWE-943'], ['CWE-89'])
    expect(result.tp).toBe(1)
    expect(result.fp).toBe(0)
    expect(result.fn).toBe(0)
  })

  it('matches exact CWEs just like strict', () => {
    const result = scoreLoose(['CWE-79'], ['CWE-79'])
    expect(result.tp).toBe(1)
    expect(result.fp).toBe(0)
    expect(result.fn).toBe(0)
  })

  it('handles non-equivalent mismatch', () => {
    const result = scoreLoose(['CWE-79'], ['CWE-89'])
    expect(result.tp).toBe(0)
    expect(result.fp).toBe(1)
    expect(result.fn).toBe(1)
  })

  it('matches CWE-94 ↔ CWE-96 equivalence', () => {
    const result = scoreLoose(['CWE-94'], ['CWE-96'])
    expect(result.tp).toBe(1)
    expect(result.fp).toBe(0)
    expect(result.fn).toBe(0)
  })

  it('matches CWE-915 ↔ CWE-1321 equivalence', () => {
    const result = scoreLoose(['CWE-1321'], ['CWE-915'])
    expect(result.tp).toBe(1)
    expect(result.fp).toBe(0)
    expect(result.fn).toBe(0)
  })

  it('normalizes before equivalence check', () => {
    const result = scoreLoose(['cwe-0943'], ['cwe-089'])
    expect(result.tp).toBe(1)
    expect(result.fp).toBe(0)
    expect(result.fn).toBe(0)
  })

  it('does not double-match a single truth to multiple predictions', () => {
    // Both CWE-94 and CWE-96 are equivalent to CWE-96,
    // but only one should match the single truth CWE-96
    const result = scoreLoose(['CWE-94', 'CWE-96'], ['CWE-96'])
    expect(result.tp).toBe(1)
    expect(result.fp).toBe(1)
    expect(result.fn).toBe(0)
  })
})

describe('calcMetrics', () => {
  it('calculates precision, recall, and F1', () => {
    const metrics = calcMetrics(8, 2, 3)
    expect(metrics.precision).toBe(0.8)
    expect(metrics.recall).toBeCloseTo(0.7273, 3)
    expect(metrics.f1).toBeCloseTo(0.7619, 3)
  })

  it('handles perfect scores', () => {
    const metrics = calcMetrics(10, 0, 0)
    expect(metrics.precision).toBe(1)
    expect(metrics.recall).toBe(1)
    expect(metrics.f1).toBe(1)
  })

  it('handles zero TP', () => {
    const metrics = calcMetrics(0, 5, 3)
    expect(metrics.precision).toBe(0)
    expect(metrics.recall).toBe(0)
    expect(metrics.f1).toBe(0)
  })

  it('handles all zeros', () => {
    const metrics = calcMetrics(0, 0, 0)
    expect(metrics.precision).toBe(0)
    expect(metrics.recall).toBe(0)
    expect(metrics.f1).toBe(0)
  })

  it('handles no false positives', () => {
    const metrics = calcMetrics(5, 0, 5)
    expect(metrics.precision).toBe(1)
    expect(metrics.recall).toBe(0.5)
    expect(metrics.f1).toBeCloseTo(0.6667, 3)
  })

  it('handles no false negatives', () => {
    const metrics = calcMetrics(5, 5, 0)
    expect(metrics.precision).toBe(0.5)
    expect(metrics.recall).toBe(1)
    expect(metrics.f1).toBeCloseTo(0.6667, 3)
  })
})
