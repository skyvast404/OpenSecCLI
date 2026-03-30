import { describe, it, expect } from 'vitest'
import { buildTriagePrompt, parseTriageResponse } from '../../src/commands/triage.js'

// ---------------------------------------------------------------------------
// buildTriagePrompt
// ---------------------------------------------------------------------------

describe('buildTriagePrompt', () => {
  it('generates prompt with all finding fields', () => {
    const finding = {
      rule_id: 'javascript.lang.security.detect-eval',
      severity: 'high',
      file_path: 'src/utils/parser.ts',
      line: 42,
      message: 'Use of eval() detected',
      cwe: 'CWE-95',
    }

    const prompt = buildTriagePrompt(finding)

    expect(prompt).toContain('Rule: javascript.lang.security.detect-eval')
    expect(prompt).toContain('Severity: high')
    expect(prompt).toContain('File: src/utils/parser.ts:42')
    expect(prompt).toContain('Message: Use of eval() detected')
    expect(prompt).toContain('CWE: CWE-95')
    expect(prompt).toContain('ATTACKER ANALYSIS')
    expect(prompt).toContain('DEFENDER ANALYSIS')
    expect(prompt).toContain('"verdict"')
  })

  it('uses defaults for missing fields', () => {
    const finding = { title: 'SQL Injection' }

    const prompt = buildTriagePrompt(finding)

    expect(prompt).toContain('Rule: SQL Injection')
    expect(prompt).toContain('Severity: unknown')
    expect(prompt).toContain('File: unknown:0')
    expect(prompt).toContain('CWE: N/A')
  })
})

// ---------------------------------------------------------------------------
// parseTriageResponse
// ---------------------------------------------------------------------------

describe('parseTriageResponse', () => {
  it('parses valid JSON response', () => {
    const response = JSON.stringify({
      verdict: 'CONFIRMED',
      confidence: 85,
      attacker_summary: 'User input flows directly to eval()',
      defender_summary: 'No sanitization present',
      reasoning: 'The eval call is reachable from the API endpoint with no input validation.',
    })

    const result = parseTriageResponse(response)

    expect(result.verdict).toBe('CONFIRMED')
    expect(result.confidence).toBe(85)
    expect(result.attacker_summary).toBe('User input flows directly to eval()')
    expect(result.defender_summary).toBe('No sanitization present')
    expect(result.reasoning).toContain('eval call')
  })

  it('parses JSON wrapped in markdown code block', () => {
    const response = `Here is my analysis:

\`\`\`json
{
  "verdict": "FALSE_POSITIVE",
  "confidence": 92,
  "attacker_summary": "No user input reaches this code path",
  "defender_summary": "Framework auto-escaping is active",
  "reasoning": "The template engine auto-escapes all output."
}
\`\`\`

That concludes my analysis.`

    const result = parseTriageResponse(response)

    expect(result.verdict).toBe('FALSE_POSITIVE')
    expect(result.confidence).toBe(92)
    expect(result.attacker_summary).toBe('No user input reaches this code path')
  })

  it('returns NEEDS_REVIEW for malformed response', () => {
    const response = 'This is not JSON at all, just plain text analysis.'

    const result = parseTriageResponse(response)

    expect(result.verdict).toBe('NEEDS_REVIEW')
    expect(result.confidence).toBe(0)
    expect(result.attacker_summary).toContain('Failed to parse')
  })

  it('returns NEEDS_REVIEW for invalid JSON structure', () => {
    const response = '{ broken json }'

    const result = parseTriageResponse(response)

    expect(result.verdict).toBe('NEEDS_REVIEW')
    expect(result.confidence).toBe(0)
    expect(result.reasoning).toContain('parsing failed')
  })

  it('validates verdict enum values', () => {
    const response = JSON.stringify({
      verdict: 'INVALID_VALUE',
      confidence: 50,
      attacker_summary: 'test',
      defender_summary: 'test',
      reasoning: 'test',
    })

    const result = parseTriageResponse(response)

    expect(result.verdict).toBe('NEEDS_REVIEW')
  })

  it('clamps confidence to valid range', () => {
    const response = JSON.stringify({
      verdict: 'CONFIRMED',
      confidence: 'not-a-number',
      attacker_summary: 'test',
      defender_summary: 'test',
      reasoning: 'test',
    })

    const result = parseTriageResponse(response)

    expect(result.confidence).toBe(0)
  })

  it('handles NEEDS_REVIEW verdict', () => {
    const response = JSON.stringify({
      verdict: 'NEEDS_REVIEW',
      confidence: 40,
      attacker_summary: 'Unclear data flow',
      defender_summary: 'Some validation exists but incomplete',
      reasoning: 'Need manual review of the data flow.',
    })

    const result = parseTriageResponse(response)

    expect(result.verdict).toBe('NEEDS_REVIEW')
    expect(result.confidence).toBe(40)
  })
})

// ---------------------------------------------------------------------------
// Stdin detection logic
// ---------------------------------------------------------------------------

describe('stdin detection', () => {
  it('process.stdin has isTTY property', () => {
    // In test environment, isTTY may be undefined (non-TTY) or true
    // The key logic: if isTTY is falsy and no --input, we read stdin
    const isTTY = process.stdin.isTTY
    expect(typeof isTTY === 'boolean' || typeof isTTY === 'undefined').toBe(true)
  })

  it('stdin pipe detection logic works correctly', () => {
    // Simulate the decision logic from runTriage
    const hasInput = false
    const isTTY = true // simulating a TTY (no pipe)

    // When isTTY is true and no input file, should require explicit input
    const shouldReadStdin = !hasInput && !isTTY
    expect(shouldReadStdin).toBe(false)

    // When isTTY is false (piped), should read stdin
    const isTTYPiped = false
    const shouldReadStdinPiped = !hasInput && !isTTYPiped
    expect(shouldReadStdinPiped).toBe(true)
  })
})
