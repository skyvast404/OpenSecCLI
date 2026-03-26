/**
 * Content-Security-Policy deep parser and analyzer.
 * Parses CSP directives and detects misconfigurations with A-F grading.
 */

export interface CSPDirectives {
  [directive: string]: string[]
}

export interface CSPFinding {
  id: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  directive: string
  message: string
}

export interface CSPAnalysis {
  directives: CSPDirectives
  findings: CSPFinding[]
  grade: string // A, B, C, D, F
  score: number // 0-100
}

export function parseCSP(policy: string): CSPDirectives {
  const directives: CSPDirectives = {}
  for (const part of policy.split(';')) {
    const trimmed = part.trim()
    if (!trimmed) continue
    const [directive, ...values] = trimmed.split(/\s+/)
    directives[directive.toLowerCase()] = values
  }
  return directives
}

const CSP_CHECKS: ReadonlyArray<{
  id: string
  severity: CSPFinding['severity']
  check: (directives: CSPDirectives) => CSPFinding | null
}> = [
  {
    id: 'CSP-UNSAFE-INLINE',
    severity: 'high',
    check: (d) => {
      for (const [dir, vals] of Object.entries(d)) {
        if (
          ['script-src', 'script-src-elem', 'default-src'].includes(dir) &&
          vals.includes("'unsafe-inline'")
        ) {
          return {
            id: 'CSP-UNSAFE-INLINE',
            severity: 'high',
            directive: dir,
            message: `'unsafe-inline' in ${dir} allows inline script execution, defeating CSP's XSS protection`,
          }
        }
      }
      return null
    },
  },
  {
    id: 'CSP-UNSAFE-EVAL',
    severity: 'high',
    check: (d) => {
      for (const [dir, vals] of Object.entries(d)) {
        if (
          ['script-src', 'default-src'].includes(dir) &&
          vals.includes("'unsafe-eval'")
        ) {
          return {
            id: 'CSP-UNSAFE-EVAL',
            severity: 'high',
            directive: dir,
            message: `'unsafe-eval' in ${dir} allows eval() and Function(), enabling code injection`,
          }
        }
      }
      return null
    },
  },
  {
    id: 'CSP-WILDCARD',
    severity: 'critical',
    check: (d) => {
      for (const [dir, vals] of Object.entries(d)) {
        if (
          ['script-src', 'default-src', 'connect-src'].includes(dir) &&
          vals.includes('*')
        ) {
          return {
            id: 'CSP-WILDCARD',
            severity: 'critical',
            directive: dir,
            message: `Wildcard (*) in ${dir} allows loading from any origin`,
          }
        }
      }
      return null
    },
  },
  {
    id: 'CSP-DATA-SCHEME',
    severity: 'high',
    check: (d) => {
      for (const [dir, vals] of Object.entries(d)) {
        if (
          ['script-src', 'default-src'].includes(dir) &&
          vals.includes('data:')
        ) {
          return {
            id: 'CSP-DATA-SCHEME',
            severity: 'high',
            directive: dir,
            message: `data: scheme in ${dir} allows inline data execution`,
          }
        }
      }
      return null
    },
  },
  {
    id: 'CSP-HTTP-SOURCE',
    severity: 'medium',
    check: (d) => {
      for (const [dir, vals] of Object.entries(d)) {
        if (vals.some((v) => v.startsWith('http://'))) {
          return {
            id: 'CSP-HTTP-SOURCE',
            severity: 'medium',
            directive: dir,
            message: `HTTP source in ${dir} allows mixed content loading`,
          }
        }
      }
      return null
    },
  },
  {
    id: 'CSP-NO-BASE-URI',
    severity: 'medium',
    check: (d) =>
      !d['base-uri']
        ? {
            id: 'CSP-NO-BASE-URI',
            severity: 'medium',
            directive: 'base-uri',
            message:
              'Missing base-uri directive. Attackers can inject <base> tags to hijack relative URLs.',
          }
        : null,
  },
  {
    id: 'CSP-NO-OBJECT-SRC',
    severity: 'medium',
    check: (d) => {
      if (!d['object-src'] && !d['default-src']?.includes("'none'")) {
        return {
          id: 'CSP-NO-OBJECT-SRC',
          severity: 'medium',
          directive: 'object-src',
          message:
            'Missing object-src directive. Flash/Java plugins may bypass CSP.',
        }
      }
      return null
    },
  },
]

export function analyzeCSP(policy: string): CSPAnalysis {
  const directives = parseCSP(policy)
  const findings: CSPFinding[] = []

  for (const check of CSP_CHECKS) {
    const finding = check.check(directives)
    if (finding) findings.push(finding)
  }

  let score = 100
  for (const f of findings) {
    if (f.severity === 'critical') score -= 30
    else if (f.severity === 'high') score -= 20
    else if (f.severity === 'medium') score -= 10
  }
  score = Math.max(0, score)

  const grade =
    score >= 90
      ? 'A'
      : score >= 70
        ? 'B'
        : score >= 50
          ? 'C'
          : score >= 30
            ? 'D'
            : 'F'

  return { directives, findings, grade, score }
}
