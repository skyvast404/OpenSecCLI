import { describe, it, expect } from 'vitest'
import { parseTrufflehogOutput } from '../../src/adapters/secrets/trufflehog-scan.js'

describe('secrets parsers', () => {
  it('parses trufflehog JSON output', () => {
    const input = JSON.stringify({
      SourceMetadata: { Data: { Git: { file: 'config.py', commit: 'abc123', line: 42 } } },
      DetectorName: 'AWS',
      DecoderName: 'PLAIN',
      Verified: true,
      Raw: 'AKIA...',
      RawV2: 'AKIAIOSFODNN7EXAMPLE',
      ExtraData: { account: '123456789' },
    }) + '\n'
    const result = parseTrufflehogOutput(input)
    expect(result).toHaveLength(1)
    expect(result[0]).toMatchObject({
      detector: 'AWS',
      file: 'config.py',
      verified: true,
      severity: 'critical',
    })
  })

  it('assigns high severity to unverified secrets', () => {
    const input = JSON.stringify({
      SourceMetadata: { Data: { Git: { file: 'env.sh', commit: 'def456', line: 10 } } },
      DetectorName: 'GenericAPI',
      Verified: false,
      Raw: 'sk_test_abc123def456',
    }) + '\n'
    const result = parseTrufflehogOutput(input)
    expect(result).toHaveLength(1)
    expect(result[0]).toMatchObject({
      detector: 'GenericAPI',
      file: 'env.sh',
      commit: 'def456',
      line: 10,
      verified: false,
      severity: 'high',
      raw_preview: 'sk_test_abc123def456...',
    })
  })

  it('handles missing metadata gracefully', () => {
    const input = JSON.stringify({
      DetectorName: 'Slack',
      Verified: false,
      Raw: 'xoxb-token-value',
    }) + '\n'
    const result = parseTrufflehogOutput(input)
    expect(result).toHaveLength(1)
    expect(result[0]).toMatchObject({
      detector: 'Slack',
      file: '',
      commit: '',
      line: 0,
      verified: false,
      severity: 'high',
    })
  })

  it('parses multiple JSONL lines', () => {
    const line1 = JSON.stringify({
      SourceMetadata: { Data: { Git: { file: 'a.py', commit: 'c1', line: 1 } } },
      DetectorName: 'AWS',
      Verified: true,
      Raw: 'AKIAIOSFODNN7EXAMPLE',
    })
    const line2 = JSON.stringify({
      SourceMetadata: { Data: { Git: { file: 'b.py', commit: 'c2', line: 5 } } },
      DetectorName: 'GitHub',
      Verified: false,
      Raw: 'ghp_xxxxxxxxxxxx',
    })
    const result = parseTrufflehogOutput(line1 + '\n' + line2 + '\n')
    expect(result).toHaveLength(2)
    expect(result[0].severity).toBe('critical')
    expect(result[1].severity).toBe('high')
  })
})
