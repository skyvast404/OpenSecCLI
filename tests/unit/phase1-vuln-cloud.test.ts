import { describe, it, expect } from 'vitest'
import { parseDalfoxOutput } from '../../src/adapters/vuln/xss-scan.js'
import { parseHadolintOutput } from '../../src/adapters/cloud/dockerfile-lint.js'
import { parseKubescapeOutput } from '../../src/adapters/cloud/kube-security.js'

describe('vuln/xss-scan', () => {
  it('parses dalfox JSONL output with vuln findings', () => {
    const line1 = JSON.stringify({
      type: 'vuln',
      data: 'https://example.com/search?q=test',
      payload: '<script>alert(1)</script>',
      evidence: 'reflected in response body',
    })
    const line2 = JSON.stringify({
      type: 'reflected',
      data: 'https://example.com/page?id=1',
      payload: '"><img src=x>',
      evidence: 'parameter reflected',
    })
    const input = `${line1}\n${line2}\n`

    const rows = parseDalfoxOutput(input)
    expect(rows).toHaveLength(2)
    expect(rows[0]).toEqual({
      type: 'vuln',
      url: 'https://example.com/search?q=test',
      payload: '<script>alert(1)</script>',
      evidence: 'reflected in response body',
      severity: 'high',
    })
    expect(rows[1]).toEqual({
      type: 'reflected',
      url: 'https://example.com/page?id=1',
      payload: '"><img src=x>',
      evidence: 'parameter reflected',
      severity: 'medium',
    })
  })

  it('returns empty array for empty input', () => {
    expect(parseDalfoxOutput('')).toEqual([])
  })

  it('skips non-JSON lines in mixed output', () => {
    const validLine = JSON.stringify({
      type: 'grep',
      data: 'https://example.com/api',
      payload: 'test',
      evidence: 'potential sink',
    })
    const input = `[*] scanning target...\n${validLine}\n[*] done\n`

    const rows = parseDalfoxOutput(input)
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({
      type: 'grep',
      severity: 'low',
    })
  })
})

describe('cloud/dockerfile-lint', () => {
  it('parses hadolint JSON output with severity mapping', () => {
    const data = [
      {
        level: 'error',
        code: 'DL3006',
        message: 'Always tag the version of an image explicitly',
        line: 1,
        column: 1,
        file: 'Dockerfile',
      },
      {
        level: 'warning',
        code: 'DL3008',
        message: 'Pin versions in apt get install',
        line: 3,
        column: 1,
        file: 'Dockerfile',
      },
      {
        level: 'info',
        code: 'DL3059',
        message: 'Multiple consecutive RUN instructions',
        line: 5,
        column: 1,
        file: 'Dockerfile',
      },
      {
        level: 'style',
        code: 'DL3004',
        message: 'Do not use sudo as it leads to unpredictable behavior',
        line: 7,
        column: 1,
        file: 'Dockerfile',
      },
    ]

    const rows = parseHadolintOutput(data)
    expect(rows).toHaveLength(4)
    expect(rows[0]).toEqual({
      rule: 'DL3006',
      severity: 'high',
      line: 1,
      message: 'Always tag the version of an image explicitly',
    })
    expect(rows[1]).toMatchObject({ rule: 'DL3008', severity: 'medium' })
    expect(rows[2]).toMatchObject({ rule: 'DL3059', severity: 'low' })
    expect(rows[3]).toMatchObject({ rule: 'DL3004', severity: 'info' })
  })

  it('returns empty array for empty input', () => {
    expect(parseHadolintOutput([])).toEqual([])
  })
})

describe('cloud/kube-security', () => {
  it('parses kubescape JSON output with controls', () => {
    const input = JSON.stringify({
      results: [
        {
          resourceID: 'apps/v1/Deployment/default/nginx',
          controls: [
            {
              controlID: 'C-0034',
              name: 'Automatic mapping of service account',
              severity: { scoreFactor: 7.5 },
              status: { status: 'failed' },
            },
            {
              controlID: 'C-0017',
              name: 'Immutable container filesystem',
              severity: { scoreFactor: 5.0 },
              status: { status: 'failed' },
            },
          ],
        },
      ],
      summaryDetails: {
        frameworks: [{ name: 'NSA' }],
      },
    })

    const rows = parseKubescapeOutput(input)
    expect(rows).toHaveLength(2)
    expect(rows[0]).toEqual({
      control_id: 'C-0034',
      control_name: 'Automatic mapping of service account',
      severity: 'high',
      status: 'failed',
      resource: 'apps/v1/Deployment/default/nginx',
      framework: 'NSA',
    })
    expect(rows[1]).toMatchObject({
      control_id: 'C-0017',
      severity: 'medium',
    })
  })

  it('returns empty array on invalid JSON', () => {
    expect(parseKubescapeOutput('not json at all')).toEqual([])
  })

  it('maps severity scores correctly', () => {
    const input = JSON.stringify({
      results: [
        {
          resourceID: 'core/v1/Pod/default/test',
          controls: [
            { controlID: 'C-0001', name: 'Critical', severity: { scoreFactor: 9.5 }, status: { status: 'failed' } },
            { controlID: 'C-0002', name: 'High', severity: { scoreFactor: 7.0 }, status: { status: 'failed' } },
            { controlID: 'C-0003', name: 'Medium', severity: { scoreFactor: 4.0 }, status: { status: 'failed' } },
            { controlID: 'C-0004', name: 'Low', severity: { scoreFactor: 2.0 }, status: { status: 'passed' } },
          ],
        },
      ],
    })

    const rows = parseKubescapeOutput(input)
    expect(rows).toHaveLength(4)
    expect(rows[0]).toMatchObject({ severity: 'critical' })
    expect(rows[1]).toMatchObject({ severity: 'high' })
    expect(rows[2]).toMatchObject({ severity: 'medium' })
    expect(rows[3]).toMatchObject({ severity: 'low' })
  })
})
