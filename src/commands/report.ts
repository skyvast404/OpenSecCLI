/**
 * Report generator — produces standalone HTML reports from scan results.
 * opensec report autopilot-report.json
 * opensec report findings.json -o my-report.html
 */

import { readFile, writeFile } from 'node:fs/promises'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

interface Finding {
  readonly severity: Severity
  readonly source: string
  readonly title: string
  readonly detail?: string
  readonly description?: string
  readonly recommendation?: string
  readonly [key: string]: unknown
}

interface SeveritySummary {
  readonly total: number
  readonly critical: number
  readonly high: number
  readonly medium: number
  readonly low: number
  readonly info: number
}

interface StepResult {
  readonly label: string
  readonly commandId: string
  readonly status: 'completed' | 'skipped' | 'failed'
  readonly skipReason?: string
  readonly error?: string
  readonly findings: readonly Finding[]
  readonly durationMs: number
}

interface AutopilotReport {
  readonly target: string
  readonly targetType: string
  readonly depth: string
  readonly startedAt: string
  readonly finishedAt: string
  readonly durationMs: number
  readonly grade: string
  readonly score: number
  readonly steps: readonly StepResult[]
  readonly findings: readonly Finding[]
  readonly summary: SeveritySummary
  readonly stepsCompleted: number
  readonly stepsSkipped: number
  readonly stepsTotal: number
  readonly skippedReasons: readonly string[]
}

export interface NormalizedReport {
  readonly target: string
  readonly date: string
  readonly grade: string
  readonly score: number
  readonly findings: readonly Finding[]
  readonly summary: SeveritySummary
  readonly steps: readonly StepResult[] | null
  readonly stepsCompleted: number | null
  readonly stepsSkipped: number | null
  readonly stepsTotal: number | null
  readonly isAutopilot: boolean
  readonly title: string
}

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#2563eb',
  info: '#6b7280',
}

const GRADE_COLORS: Record<string, string> = {
  A: '#16a34a',
  B: '#65a30d',
  C: '#d97706',
  D: '#ea580c',
  F: '#dc2626',
}

// ---------------------------------------------------------------------------
// Format detection & normalization
// ---------------------------------------------------------------------------

function normalizeSeverity(raw: unknown): Severity {
  const value = String(raw ?? 'info').toLowerCase()
  if (value.includes('critical') || value.includes('crit')) return 'critical'
  if (value.includes('high') || value === 'error') return 'high'
  if (value.includes('medium') || value.includes('med') || value === 'warning') return 'medium'
  if (value.includes('low')) return 'low'
  return 'info'
}

function normalizeFinding(row: Record<string, unknown>): Finding {
  const severity = normalizeSeverity(row['severity'] ?? row['risk'] ?? row['level'] ?? 'info')
  const title = String(
    row['title'] ?? row['name'] ?? row['rule_id'] ?? row['rule'] ??
    row['header'] ?? row['issue'] ?? row['message'] ?? row['description'] ?? 'Finding',
  )
  const source = String(row['source'] ?? 'unknown')
  const detail = typeof row['detail'] === 'string' ? row['detail'] : undefined
  const description = typeof row['description'] === 'string' ? row['description'] : undefined
  const recommendation = typeof row['recommendation'] === 'string' ? row['recommendation'] : undefined

  return { ...row, severity, title, source, detail, description, recommendation }
}

function buildSummary(findings: readonly Finding[]): SeveritySummary {
  return {
    total: findings.length,
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    info: findings.filter(f => f.severity === 'info').length,
  }
}

function computeScore(findings: readonly Finding[]): number {
  let score = 100
  for (const f of findings) {
    switch (f.severity) {
      case 'critical': score -= 15; break
      case 'high': score -= 8; break
      case 'medium': score -= 4; break
      case 'low': score -= 1; break
    }
  }
  return Math.max(0, Math.min(100, score))
}

function scoreToGrade(score: number): string {
  if (score >= 90) return 'A'
  if (score >= 80) return 'B'
  if (score >= 70) return 'C'
  if (score >= 60) return 'D'
  return 'F'
}

function isAutopilotReport(data: unknown): data is AutopilotReport {
  if (typeof data !== 'object' || data === null) return false
  const obj = data as Record<string, unknown>
  return Array.isArray(obj['steps']) && typeof obj['grade'] === 'string'
}

export function normalizeInput(data: unknown, title: string): NormalizedReport {
  if (isAutopilotReport(data)) {
    return {
      target: data.target,
      date: data.startedAt,
      grade: data.grade,
      score: data.score,
      findings: data.findings,
      summary: data.summary,
      steps: data.steps,
      stepsCompleted: data.stepsCompleted,
      stepsSkipped: data.stepsSkipped,
      stepsTotal: data.stepsTotal,
      isAutopilot: true,
      title,
    }
  }

  // Raw findings array
  const rawFindings: Record<string, unknown>[] = Array.isArray(data) ? data : [data as Record<string, unknown>]
  const findings = rawFindings.map(normalizeFinding)
  const sortedFindings = [...findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  )
  const score = computeScore(sortedFindings)

  return {
    target: 'N/A',
    date: new Date().toISOString(),
    grade: scoreToGrade(score),
    score,
    findings: sortedFindings,
    summary: buildSummary(sortedFindings),
    steps: null,
    stepsCompleted: null,
    stepsSkipped: null,
    stepsTotal: null,
    isAutopilot: false,
    title,
  }
}

// ---------------------------------------------------------------------------
// SVG Pie Chart
// ---------------------------------------------------------------------------

function buildPieChartSvg(summary: SeveritySummary): string {
  const entries: Array<{ label: string; count: number; color: string }> = [
    { label: 'Critical', count: summary.critical, color: SEVERITY_COLORS.critical },
    { label: 'High', count: summary.high, color: SEVERITY_COLORS.high },
    { label: 'Medium', count: summary.medium, color: SEVERITY_COLORS.medium },
    { label: 'Low', count: summary.low, color: SEVERITY_COLORS.low },
    { label: 'Info', count: summary.info, color: SEVERITY_COLORS.info },
  ].filter(e => e.count > 0)

  if (entries.length === 0) {
    return '<svg width="200" height="200" viewBox="0 0 200 200"><circle cx="100" cy="100" r="80" fill="#e5e7eb"/><text x="100" y="105" text-anchor="middle" font-size="14" fill="#6b7280">No findings</text></svg>'
  }

  const total = entries.reduce((sum, e) => sum + e.count, 0)
  const cx = 100
  const cy = 100
  const r = 80
  let currentAngle = -Math.PI / 2
  const paths: string[] = []

  for (const entry of entries) {
    const fraction = entry.count / total
    const angle = fraction * 2 * Math.PI

    if (entries.length === 1) {
      paths.push(`<circle cx="${cx}" cy="${cy}" r="${r}" fill="${entry.color}"/>`)
    } else {
      const x1 = cx + r * Math.cos(currentAngle)
      const y1 = cy + r * Math.sin(currentAngle)
      const x2 = cx + r * Math.cos(currentAngle + angle)
      const y2 = cy + r * Math.sin(currentAngle + angle)
      const largeArc = angle > Math.PI ? 1 : 0

      paths.push(
        `<path d="M ${cx} ${cy} L ${x1.toFixed(2)} ${y1.toFixed(2)} A ${r} ${r} 0 ${largeArc} 1 ${x2.toFixed(2)} ${y2.toFixed(2)} Z" fill="${entry.color}"/>`,
      )
    }
    currentAngle += angle
  }

  // Legend
  const legendItems = entries.map((e, i) => {
    const y = 210 + i * 22
    return `<rect x="10" y="${y}" width="14" height="14" rx="2" fill="${e.color}"/><text x="30" y="${y + 12}" font-size="12" fill="#374151">${e.label}: ${e.count}</text>`
  })

  const svgHeight = 210 + entries.length * 22 + 10

  return `<svg width="200" height="${svgHeight}" viewBox="0 0 200 ${svgHeight}" xmlns="http://www.w3.org/2000/svg">${paths.join('')}${legendItems.join('')}</svg>`
}

// ---------------------------------------------------------------------------
// HTML Template
// ---------------------------------------------------------------------------

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function severityBadge(severity: Severity): string {
  const color = SEVERITY_COLORS[severity]
  return `<span style="display:inline-block;padding:2px 10px;border-radius:9999px;font-size:12px;font-weight:600;color:#fff;background:${color};text-transform:uppercase;">${severity}</span>`
}

function gradeBadge(grade: string): string {
  const color = GRADE_COLORS[grade] ?? '#6b7280'
  return `<span style="display:inline-flex;align-items:center;justify-content:center;width:56px;height:56px;border-radius:50%;font-size:28px;font-weight:700;color:#fff;background:${color};">${escapeHtml(grade)}</span>`
}

function buildFindingsTableRows(findings: readonly Finding[]): string {
  const sorted = [...findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  )

  if (sorted.length === 0) {
    return '<tr><td colspan="4" style="text-align:center;padding:24px;color:#6b7280;">No findings detected.</td></tr>'
  }

  return sorted.map((f, i) => {
    const bg = i % 2 === 0 ? '#fff' : '#f9fafb'
    const desc = escapeHtml(f.description ?? f.detail ?? '-')
    const rec = escapeHtml(f.recommendation ?? '-')

    return `<tr style="background:${bg};">
      <td style="padding:10px 12px;">${severityBadge(f.severity)}</td>
      <td style="padding:10px 12px;font-weight:500;">${escapeHtml(f.title)}</td>
      <td style="padding:10px 12px;color:#4b5563;font-size:13px;">${desc}</td>
      <td style="padding:10px 12px;color:#4b5563;font-size:13px;">${rec}</td>
    </tr>`
  }).join('\n')
}

function buildStepsSection(report: NormalizedReport): string {
  if (!report.isAutopilot || !report.steps) return ''

  const stepRows = report.steps.map((step, i) => {
    const bg = i % 2 === 0 ? '#fff' : '#f9fafb'
    const statusColor = step.status === 'completed' ? '#16a34a'
      : step.status === 'skipped' ? '#d97706'
        : '#dc2626'
    const statusLabel = step.status.charAt(0).toUpperCase() + step.status.slice(1)
    const note = step.status === 'skipped' ? escapeHtml(step.skipReason ?? '')
      : step.status === 'failed' ? escapeHtml(step.error ?? '')
        : `${step.findings.length} finding(s)`
    const duration = (step.durationMs / 1000).toFixed(1)

    return `<tr style="background:${bg};">
      <td style="padding:8px 12px;">${escapeHtml(step.label)}</td>
      <td style="padding:8px 12px;"><span style="color:${statusColor};font-weight:600;">${statusLabel}</span></td>
      <td style="padding:8px 12px;color:#4b5563;font-size:13px;">${note}</td>
      <td style="padding:8px 12px;color:#6b7280;font-size:13px;">${duration}s</td>
    </tr>`
  }).join('\n')

  return `
    <div style="margin-top:32px;">
      <h2 style="font-size:20px;font-weight:600;margin-bottom:12px;color:#1f2937;">Scan Steps</h2>
      <p style="margin-bottom:8px;color:#4b5563;">
        Completed: <strong>${report.stepsCompleted}</strong> |
        Skipped: <strong>${report.stepsSkipped}</strong> |
        Total: <strong>${report.stepsTotal}</strong>
      </p>
      <table style="width:100%;border-collapse:collapse;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;">
        <thead>
          <tr style="background:#f3f4f6;">
            <th style="padding:10px 12px;text-align:left;font-size:13px;font-weight:600;color:#374151;border-bottom:1px solid #e5e7eb;">Step</th>
            <th style="padding:10px 12px;text-align:left;font-size:13px;font-weight:600;color:#374151;border-bottom:1px solid #e5e7eb;">Status</th>
            <th style="padding:10px 12px;text-align:left;font-size:13px;font-weight:600;color:#374151;border-bottom:1px solid #e5e7eb;">Note</th>
            <th style="padding:10px 12px;text-align:left;font-size:13px;font-weight:600;color:#374151;border-bottom:1px solid #e5e7eb;">Duration</th>
          </tr>
        </thead>
        <tbody>
          ${stepRows}
        </tbody>
      </table>
    </div>`
}

export function buildHtml(report: NormalizedReport): string {
  const dateStr = new Date(report.date).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })

  const pieChart = buildPieChartSvg(report.summary)
  const findingsRows = buildFindingsTableRows(report.findings)
  const stepsSection = buildStepsSection(report)

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(report.title)}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; color: #1f2937; background: #f3f4f6; line-height: 1.6; }
  .header { background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); color: #fff; padding: 32px 40px; }
  .header-inner { max-width: 960px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px; }
  .logo-area { display: flex; align-items: center; gap: 14px; }
  .logo-placeholder { width: 40px; height: 40px; background: #3b82f6; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 18px; color: #fff; }
  .header h1 { font-size: 22px; font-weight: 700; }
  .header-meta { font-size: 13px; color: #94a3b8; text-align: right; }
  .container { max-width: 960px; margin: 0 auto; padding: 32px 24px 48px; }
  .card { background: #fff; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); padding: 24px; margin-bottom: 24px; }
  .summary-grid { display: grid; grid-template-columns: auto 1fr auto; gap: 32px; align-items: center; }
  .severity-counts { display: flex; gap: 16px; flex-wrap: wrap; }
  .sev-box { text-align: center; min-width: 72px; }
  .sev-box .count { font-size: 28px; font-weight: 700; }
  .sev-box .label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #6b7280; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; font-size: 13px; font-weight: 600; color: #374151; padding: 10px 12px; border-bottom: 2px solid #e5e7eb; background: #f9fafb; }
  .footer { text-align: center; padding: 24px; color: #9ca3af; font-size: 13px; }
  @media (max-width: 640px) {
    .summary-grid { grid-template-columns: 1fr; }
    .header-inner { flex-direction: column; text-align: center; }
    .header-meta { text-align: center; }
  }
</style>
</head>
<body>

<div class="header">
  <div class="header-inner">
    <div class="logo-area">
      <div class="logo-placeholder">OS</div>
      <div>
        <h1>${escapeHtml(report.title)}</h1>
        <div style="font-size:13px;color:#94a3b8;margin-top:2px;">Target: ${escapeHtml(report.target)}</div>
      </div>
    </div>
    <div class="header-meta">
      <div>${dateStr}</div>
      <div style="margin-top:2px;">Score: ${report.score}/100</div>
    </div>
  </div>
</div>

<div class="container">

  <!-- Executive Summary -->
  <div class="card">
    <h2 style="font-size:20px;font-weight:600;margin-bottom:16px;color:#1f2937;">Executive Summary</h2>
    <div class="summary-grid">
      <div style="text-align:center;">
        ${gradeBadge(report.grade)}
        <div style="margin-top:6px;font-size:13px;color:#6b7280;">Grade</div>
      </div>
      <div class="severity-counts">
        <div class="sev-box"><div class="count" style="color:${SEVERITY_COLORS.critical}">${report.summary.critical}</div><div class="label">Critical</div></div>
        <div class="sev-box"><div class="count" style="color:${SEVERITY_COLORS.high}">${report.summary.high}</div><div class="label">High</div></div>
        <div class="sev-box"><div class="count" style="color:${SEVERITY_COLORS.medium}">${report.summary.medium}</div><div class="label">Medium</div></div>
        <div class="sev-box"><div class="count" style="color:${SEVERITY_COLORS.low}">${report.summary.low}</div><div class="label">Low</div></div>
        <div class="sev-box"><div class="count" style="color:${SEVERITY_COLORS.info}">${report.summary.info}</div><div class="label">Info</div></div>
      </div>
      <div>
        ${pieChart}
      </div>
    </div>
  </div>

  <!-- Findings Table -->
  <div class="card">
    <h2 style="font-size:20px;font-weight:600;margin-bottom:12px;color:#1f2937;">Findings (${report.summary.total})</h2>
    <div style="overflow-x:auto;">
      <table>
        <thead>
          <tr>
            <th style="width:110px;">Severity</th>
            <th>Title</th>
            <th>Description</th>
            <th>Recommendation</th>
          </tr>
        </thead>
        <tbody>
          ${findingsRows}
        </tbody>
      </table>
    </div>
  </div>

  <!-- Finding Details -->
  ${report.findings.length > 0 ? `
  <div class="card">
    <h2 style="font-size:20px;font-weight:600;margin-bottom:16px;color:#1f2937;">Finding Details</h2>
    ${[...report.findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]).map((f, i) => `
    <div style="border:1px solid #e5e7eb;border-radius:8px;padding:16px;margin-bottom:12px;${i % 2 === 0 ? '' : 'background:#f9fafb;'}">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
        ${severityBadge(f.severity)}
        <span style="font-weight:600;font-size:15px;">${escapeHtml(f.title)}</span>
      </div>
      ${f.source ? `<div style="font-size:12px;color:#6b7280;margin-bottom:6px;">Source: ${escapeHtml(f.source)}</div>` : ''}
      ${f.description || f.detail ? `<div style="margin-bottom:6px;color:#374151;font-size:14px;">${escapeHtml(f.description ?? f.detail ?? '')}</div>` : ''}
      ${f.recommendation ? `<div style="background:#f0fdf4;border-left:3px solid #16a34a;padding:8px 12px;border-radius:4px;font-size:13px;color:#166534;"><strong>Recommendation:</strong> ${escapeHtml(f.recommendation)}</div>` : ''}
    </div>`).join('\n')}
  </div>` : ''}

  <!-- Steps (Autopilot only) -->
  ${stepsSection}

</div>

<div class="footer">
  Generated by OpenSecCLI
</div>

</body>
</html>`
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export type ReportFormat = 'html'

export async function generateReport(
  inputPath: string,
  outputPath: string,
  format: ReportFormat = 'html',
  title = 'OpenSecCLI Security Assessment',
): Promise<string> {
  const raw = await readFile(inputPath, 'utf-8')

  let data: unknown
  try {
    data = JSON.parse(raw)
  } catch {
    throw new Error(`Failed to parse input file as JSON: ${inputPath}`)
  }

  const report = normalizeInput(data, title)

  if (format !== 'html') {
    throw new Error(`Unsupported report format: ${format}. Supported: html`)
  }

  const html = buildHtml(report)
  await writeFile(outputPath, html, 'utf-8')

  return outputPath
}
