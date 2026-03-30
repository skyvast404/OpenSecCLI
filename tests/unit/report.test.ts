import { describe, it, expect } from 'vitest'
import { normalizeInput, buildHtml } from '../../src/commands/report.js'
import type { NormalizedReport } from '../../src/commands/report.js'

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

const mockAutopilotReport = {
  target: 'https://example.com',
  targetType: 'url',
  depth: 'standard',
  startedAt: '2026-03-30T10:00:00.000Z',
  finishedAt: '2026-03-30T10:05:00.000Z',
  durationMs: 300000,
  grade: 'B',
  score: 82,
  steps: [
    {
      label: 'Header Audit',
      commandId: 'vuln/header-audit',
      status: 'completed' as const,
      findings: [
        { severity: 'medium', source: 'Header Audit', title: 'Missing X-Frame-Options' },
        { severity: 'low', source: 'Header Audit', title: 'Missing X-Content-Type-Options' },
      ],
      durationMs: 1200,
    },
    {
      label: 'Nuclei Scan',
      commandId: 'vuln/nuclei-scan',
      status: 'skipped' as const,
      skipReason: 'nuclei not installed',
      findings: [],
      durationMs: 5,
    },
    {
      label: 'CORS Check',
      commandId: 'vuln/cors-check',
      status: 'completed' as const,
      findings: [
        { severity: 'high', source: 'CORS Check', title: 'Wildcard CORS policy' },
      ],
      durationMs: 800,
    },
  ],
  findings: [
    { severity: 'medium', source: 'Header Audit', title: 'Missing X-Frame-Options' },
    { severity: 'low', source: 'Header Audit', title: 'Missing X-Content-Type-Options' },
    { severity: 'high', source: 'CORS Check', title: 'Wildcard CORS policy' },
  ],
  summary: { total: 3, critical: 0, high: 1, medium: 1, low: 1, info: 0 },
  stepsCompleted: 2,
  stepsSkipped: 1,
  stepsTotal: 3,
  skippedReasons: ['nuclei not installed'],
}

const mockRawFindings = [
  { severity: 'critical', title: 'SQL Injection', source: 'SAST', description: 'Unsanitized input in query', recommendation: 'Use parameterized queries' },
  { severity: 'high', title: 'XSS', source: 'SAST', description: 'Reflected XSS in search', recommendation: 'Escape user input' },
  { severity: 'info', title: 'Debug mode on', source: 'Config', description: 'Debug is enabled' },
]

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('normalizeInput', () => {
  it('detects autopilot report and preserves structure', () => {
    const result = normalizeInput(mockAutopilotReport, 'Test Report')

    expect(result.isAutopilot).toBe(true)
    expect(result.grade).toBe('B')
    expect(result.score).toBe(82)
    expect(result.target).toBe('https://example.com')
    expect(result.findings).toHaveLength(3)
    expect(result.steps).toHaveLength(3)
    expect(result.stepsCompleted).toBe(2)
    expect(result.stepsSkipped).toBe(1)
    expect(result.title).toBe('Test Report')
  })

  it('normalizes raw findings array and computes score/grade', () => {
    const result = normalizeInput(mockRawFindings, 'Findings Report')

    expect(result.isAutopilot).toBe(false)
    expect(result.steps).toBeNull()
    expect(result.findings).toHaveLength(3)
    expect(result.summary.critical).toBe(1)
    expect(result.summary.high).toBe(1)
    expect(result.summary.info).toBe(1)
    // Score: 100 - 15 (critical) - 8 (high) = 77 => grade C
    expect(result.score).toBe(77)
    expect(result.grade).toBe('C')
    expect(result.title).toBe('Findings Report')
  })

  it('handles a single finding object (not array)', () => {
    const single = { severity: 'low', title: 'Minor issue', source: 'test' }
    const result = normalizeInput(single, 'Single Finding')

    expect(result.isAutopilot).toBe(false)
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].severity).toBe('low')
    expect(result.score).toBe(99)
    expect(result.grade).toBe('A')
  })
})

describe('buildHtml', () => {
  it('generates a standalone HTML document with required sections', () => {
    const report = normalizeInput(mockAutopilotReport, 'Security Assessment')
    const html = buildHtml(report)

    // Must be a valid HTML document
    expect(html).toContain('<!DOCTYPE html>')
    expect(html).toContain('</html>')

    // Header with title and target
    expect(html).toContain('Security Assessment')
    expect(html).toContain('https://example.com')

    // Grade badge
    expect(html).toContain('B')

    // Severity colors inlined
    expect(html).toContain('#dc2626')  // critical color
    expect(html).toContain('#ea580c')  // high color
    expect(html).toContain('#d97706')  // medium color

    // Findings table
    expect(html).toContain('Missing X-Frame-Options')
    expect(html).toContain('Wildcard CORS policy')

    // Steps section (autopilot)
    expect(html).toContain('Scan Steps')
    expect(html).toContain('Header Audit')
    expect(html).toContain('nuclei not installed')

    // Footer
    expect(html).toContain('Generated by OpenSecCLI')
  })

  it('generates HTML for raw findings without steps section', () => {
    const report = normalizeInput(mockRawFindings, 'SAST Report')
    const html = buildHtml(report)

    expect(html).toContain('<!DOCTYPE html>')
    expect(html).toContain('SQL Injection')
    expect(html).toContain('Use parameterized queries')

    // No steps section for non-autopilot
    expect(html).not.toContain('Scan Steps')
    expect(html).toContain('Generated by OpenSecCLI')
  })

  it('renders inline SVG pie chart', () => {
    const report = normalizeInput(mockRawFindings, 'Chart Test')
    const html = buildHtml(report)

    expect(html).toContain('<svg')
    expect(html).toContain('</svg>')
  })

  it('handles empty findings gracefully', () => {
    const report: NormalizedReport = {
      target: 'https://safe.example.com',
      date: '2026-03-30T12:00:00.000Z',
      grade: 'A',
      score: 100,
      findings: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      steps: null,
      stepsCompleted: null,
      stepsSkipped: null,
      stepsTotal: null,
      isAutopilot: false,
      title: 'Clean Report',
    }
    const html = buildHtml(report)

    expect(html).toContain('No findings')
    expect(html).toContain('Clean Report')
    expect(html).toContain('Generated by OpenSecCLI')
  })

  it('escapes HTML special characters in finding titles', () => {
    const maliciousFindings = [
      { severity: 'high', title: '<script>alert("xss")</script>', source: 'test' },
    ]
    const report = normalizeInput(maliciousFindings, 'XSS Test')
    const html = buildHtml(report)

    expect(html).not.toContain('<script>alert("xss")</script>')
    expect(html).toContain('&lt;script&gt;')
  })
})
