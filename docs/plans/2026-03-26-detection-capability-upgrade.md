# Detection Capability Upgrade Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Upgrade 5 core adapters from toy-level regex matching to professional-grade security detection — make them actually find real vulnerabilities.

**Architecture:** Three parallel tracks: (1) header-audit → full security posture scorer with CSP parsing, cookie analysis, and A-F grading; (2) scan/analyze → curated semgrep security rules + custom rules for top frameworks; (3) pentest tooling → payload library + parameter fuzzing + response analysis. All pure TypeScript, zero new dependencies.

**Tech Stack:** TypeScript, Vitest, node:http (fetch)

---

## Track 1: header-audit → Professional Security Posture Scanner

Current: checks 7 headers for existence. Target: Mozilla Observatory-grade analysis with A-F scoring.

### Task 1: CSP Deep Parser

**Files:**
- Create: `src/adapters/vuln/csp-parser.ts`
- Test: `tests/unit/csp-parser.test.ts`

**Step 1: Write failing tests**

```typescript
// tests/unit/csp-parser.test.ts
import { describe, it, expect } from 'vitest'
import { parseCSP, analyzeCSP } from '../../src/adapters/vuln/csp-parser.js'

describe('CSP parser', () => {
  it('parses directives into structured object', () => {
    const csp = "default-src 'self'; script-src 'self' cdn.example.com; style-src 'unsafe-inline'"
    const parsed = parseCSP(csp)
    expect(parsed['default-src']).toEqual(["'self'"])
    expect(parsed['script-src']).toEqual(["'self'", 'cdn.example.com'])
    expect(parsed['style-src']).toEqual(["'unsafe-inline'"])
  })

  it('detects unsafe-inline in script-src as critical', () => {
    const result = analyzeCSP("script-src 'self' 'unsafe-inline'")
    const issue = result.findings.find(f => f.id === 'CSP-UNSAFE-INLINE')
    expect(issue).toBeDefined()
    expect(issue!.severity).toBe('high')
  })

  it('detects unsafe-eval as critical', () => {
    const result = analyzeCSP("script-src 'self' 'unsafe-eval'")
    expect(result.findings.some(f => f.id === 'CSP-UNSAFE-EVAL')).toBe(true)
  })

  it('detects wildcard sources', () => {
    const result = analyzeCSP("script-src *")
    expect(result.findings.some(f => f.id === 'CSP-WILDCARD')).toBe(true)
  })

  it('detects missing base-uri', () => {
    const result = analyzeCSP("default-src 'self'")
    expect(result.findings.some(f => f.id === 'CSP-NO-BASE-URI')).toBe(true)
  })

  it('detects missing object-src', () => {
    const result = analyzeCSP("default-src 'self'")
    expect(result.findings.some(f => f.id === 'CSP-NO-OBJECT-SRC')).toBe(true)
  })

  it('detects overly broad script-src (data: scheme)', () => {
    const result = analyzeCSP("script-src 'self' data:")
    expect(result.findings.some(f => f.id === 'CSP-DATA-SCHEME')).toBe(true)
  })

  it('detects http: in script-src (mixed content)', () => {
    const result = analyzeCSP("script-src http://cdn.example.com")
    expect(result.findings.some(f => f.id === 'CSP-HTTP-SOURCE')).toBe(true)
  })

  it('passes strict CSP with no findings', () => {
    const result = analyzeCSP("default-src 'none'; script-src 'self'; style-src 'self'; base-uri 'none'; object-src 'none'; form-action 'self'")
    expect(result.findings).toHaveLength(0)
    expect(result.grade).toBe('A')
  })

  it('grades CSP from A to F', () => {
    expect(analyzeCSP("default-src 'none'; script-src 'self'; base-uri 'none'; object-src 'none'").grade).toBe('A')
    expect(analyzeCSP("default-src 'self'").grade).toBe('C') // missing base-uri, object-src
    expect(analyzeCSP("script-src *").grade).toBe('F')
  })
})
```

**Step 2: Implement CSP parser**

```typescript
// src/adapters/vuln/csp-parser.ts
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
  grade: string  // A, B, C, D, F
  score: number  // 0-100
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

const CSP_CHECKS: Array<{
  id: string
  severity: CSPFinding['severity']
  check: (directives: CSPDirectives) => CSPFinding | null
}> = [
  {
    id: 'CSP-UNSAFE-INLINE',
    severity: 'high',
    check: (d) => {
      for (const [dir, vals] of Object.entries(d)) {
        if (['script-src', 'script-src-elem', 'default-src'].includes(dir) && vals.includes("'unsafe-inline'")) {
          return { id: 'CSP-UNSAFE-INLINE', severity: 'high', directive: dir, message: `'unsafe-inline' in ${dir} allows inline script execution, defeating CSP's XSS protection` }
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
        if (['script-src', 'default-src'].includes(dir) && vals.includes("'unsafe-eval'")) {
          return { id: 'CSP-UNSAFE-EVAL', severity: 'high', directive: dir, message: `'unsafe-eval' in ${dir} allows eval() and Function(), enabling code injection` }
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
        if (['script-src', 'default-src', 'connect-src'].includes(dir) && vals.includes('*')) {
          return { id: 'CSP-WILDCARD', severity: 'critical', directive: dir, message: `Wildcard (*) in ${dir} allows loading from any origin` }
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
        if (['script-src', 'default-src'].includes(dir) && vals.includes('data:')) {
          return { id: 'CSP-DATA-SCHEME', severity: 'high', directive: dir, message: `data: scheme in ${dir} allows inline data execution` }
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
        if (vals.some(v => v.startsWith('http://'))) {
          return { id: 'CSP-HTTP-SOURCE', severity: 'medium', directive: dir, message: `HTTP source in ${dir} allows mixed content loading` }
        }
      }
      return null
    },
  },
  {
    id: 'CSP-NO-BASE-URI',
    severity: 'medium',
    check: (d) => (!d['base-uri'] ? { id: 'CSP-NO-BASE-URI', severity: 'medium', directive: 'base-uri', message: 'Missing base-uri directive. Attackers can inject <base> tags to hijack relative URLs.' } : null),
  },
  {
    id: 'CSP-NO-OBJECT-SRC',
    severity: 'medium',
    check: (d) => {
      if (!d['object-src'] && !d['default-src']?.includes("'none'")) {
        return { id: 'CSP-NO-OBJECT-SRC', severity: 'medium', directive: 'object-src', message: 'Missing object-src directive. Flash/Java plugins may bypass CSP.' }
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
  // Score: 100 - deductions
  let score = 100
  for (const f of findings) {
    if (f.severity === 'critical') score -= 30
    else if (f.severity === 'high') score -= 20
    else if (f.severity === 'medium') score -= 10
  }
  score = Math.max(0, score)
  const grade = score >= 90 ? 'A' : score >= 70 ? 'B' : score >= 50 ? 'C' : score >= 30 ? 'D' : 'F'
  return { directives, findings, grade, score }
}
```

**Step 3: Run tests, commit**

```bash
npx vitest run tests/unit/csp-parser.test.ts
git add src/adapters/vuln/csp-parser.ts tests/unit/csp-parser.test.ts
git commit -m "feat(vuln): add CSP deep parser with A-F grading"
```

---

### Task 2: Cookie Security Analyzer

**Files:**
- Create: `src/adapters/vuln/cookie-analyzer.ts`
- Test: `tests/unit/cookie-analyzer.test.ts`

**Step 1: Write failing tests**

```typescript
// tests/unit/cookie-analyzer.test.ts
import { describe, it, expect } from 'vitest'
import { analyzeCookies } from '../../src/adapters/vuln/cookie-analyzer.js'

describe('cookie analyzer', () => {
  it('flags missing Secure flag', () => {
    const results = analyzeCookies('session=abc; Path=/; HttpOnly')
    expect(results.some(r => r.issue === 'MISSING_SECURE')).toBe(true)
  })

  it('flags missing HttpOnly on session cookie', () => {
    const results = analyzeCookies('session=abc; Path=/; Secure')
    expect(results.some(r => r.issue === 'MISSING_HTTPONLY')).toBe(true)
  })

  it('flags missing SameSite', () => {
    const results = analyzeCookies('session=abc; Path=/; Secure; HttpOnly')
    expect(results.some(r => r.issue === 'MISSING_SAMESITE')).toBe(true)
  })

  it('flags SameSite=None without Secure', () => {
    const results = analyzeCookies('session=abc; SameSite=None')
    expect(results.some(r => r.issue === 'SAMESITE_NONE_NO_SECURE')).toBe(true)
  })

  it('flags overly broad Path=/', () => {
    const results = analyzeCookies('admin_token=xyz; Path=/; Secure; HttpOnly; SameSite=Strict')
    // This is acceptable for most cookies, only flag if cookie name suggests restriction
    expect(results).toBeDefined()
  })

  it('flags low entropy session values', () => {
    const results = analyzeCookies('session=123; Secure; HttpOnly; SameSite=Lax')
    expect(results.some(r => r.issue === 'LOW_ENTROPY')).toBe(true)
  })

  it('passes well-configured cookie', () => {
    const results = analyzeCookies('session=a3f8d2e91b7c4502; Secure; HttpOnly; SameSite=Lax; Path=/app')
    const issues = results.filter(r => r.severity !== 'info')
    expect(issues).toHaveLength(0)
  })
})
```

**Step 2: Implement**

```typescript
// src/adapters/vuln/cookie-analyzer.ts
export interface CookieFinding {
  cookie_name: string
  issue: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  detail: string
}

export function analyzeCookies(setCookieHeader: string): CookieFinding[] {
  const findings: CookieFinding[] = []
  const parts = setCookieHeader.split(';').map(p => p.trim())
  const nameValue = parts[0]?.split('=') ?? []
  const name = nameValue[0] ?? 'unknown'
  const value = nameValue.slice(1).join('=') ?? ''
  const flags = parts.slice(1).map(p => p.toLowerCase())

  const hasSecure = flags.some(f => f === 'secure')
  const hasHttpOnly = flags.some(f => f === 'httponly')
  const sameSite = flags.find(f => f.startsWith('samesite='))?.split('=')[1]
  const isSession = /session|token|auth|jwt|sid/i.test(name)

  if (!hasSecure) {
    findings.push({ cookie_name: name, issue: 'MISSING_SECURE', severity: isSession ? 'high' : 'medium', detail: 'Cookie transmitted over HTTP. Add Secure flag.' })
  }

  if (!hasHttpOnly && isSession) {
    findings.push({ cookie_name: name, issue: 'MISSING_HTTPONLY', severity: 'high', detail: 'Session cookie accessible via JavaScript. Add HttpOnly flag.' })
  }

  if (!sameSite) {
    findings.push({ cookie_name: name, issue: 'MISSING_SAMESITE', severity: 'medium', detail: 'Missing SameSite attribute. Vulnerable to CSRF. Add SameSite=Lax or Strict.' })
  }

  if (sameSite === 'none' && !hasSecure) {
    findings.push({ cookie_name: name, issue: 'SAMESITE_NONE_NO_SECURE', severity: 'high', detail: 'SameSite=None requires Secure flag. Cookie will be rejected by modern browsers.' })
  }

  // Entropy check: session cookies should have high entropy
  if (isSession && value.length > 0) {
    const uniqueChars = new Set(value).size
    const entropy = uniqueChars / Math.max(value.length, 1)
    if (value.length < 16 || entropy < 0.3) {
      findings.push({ cookie_name: name, issue: 'LOW_ENTROPY', severity: 'medium', detail: `Session value appears predictable (length=${value.length}, char diversity=${(entropy * 100).toFixed(0)}%). Use cryptographically random tokens.` })
    }
  }

  return findings
}
```

**Step 3: Commit**

```bash
git add src/adapters/vuln/cookie-analyzer.ts tests/unit/cookie-analyzer.test.ts
git commit -m "feat(vuln): add cookie security analyzer"
```

---

### Task 3: Upgrade header-audit to use CSP parser + cookie analyzer + A-F grading

**Files:**
- Modify: `src/adapters/vuln/header-audit.ts`
- Modify: `src/adapters/vuln/parsers.ts`
- Test: `tests/unit/vuln.test.ts`

**Step 1: Add more header checks to parsers.ts**

Add to the `SECURITY_HEADERS` array:

```typescript
// New headers to check
{
  header: 'Cross-Origin-Opener-Policy',
  severity: 'medium',
  recommendation: 'Add: Cross-Origin-Opener-Policy: same-origin',
},
{
  header: 'Cross-Origin-Resource-Policy',
  severity: 'medium',
  recommendation: 'Add: Cross-Origin-Resource-Policy: same-origin',
},
{
  header: 'Cross-Origin-Embedder-Policy',
  severity: 'low',
  recommendation: 'Add: Cross-Origin-Embedder-Policy: require-corp',
},
```

**Step 2: Upgrade header-audit.ts func()**

```typescript
import { analyzeCSP } from './csp-parser.js'
import { analyzeCookies } from './cookie-analyzer.js'

// In the func:
// 1. Run existing header checks (as before)
// 2. If CSP header exists, run deep CSP analysis
// 3. Analyze all Set-Cookie headers
// 4. Compute overall grade (A-F) based on all findings
// 5. Return unified results

async func(ctx, args) {
  const url = args.url as string
  const response = await fetch(url, { method: 'GET', redirect: 'follow', signal: AbortSignal.timeout(15_000) })

  // Header presence checks (existing)
  const headerResults = auditHeaders(url, headerMap)

  // CSP deep analysis
  const cspValue = response.headers.get('content-security-policy')
  if (cspValue) {
    const cspAnalysis = analyzeCSP(cspValue)
    for (const finding of cspAnalysis.findings) {
      results.push({ header: `CSP: ${finding.directive}`, status: 'WEAK', value: finding.message, severity: finding.severity, recommendation: `Fix ${finding.directive} directive` })
    }
  }

  // Cookie analysis
  const cookies = response.headers.getSetCookie?.() ?? []
  for (const cookie of cookies) {
    const cookieFindings = analyzeCookies(cookie)
    for (const f of cookieFindings) {
      results.push({ header: `Cookie: ${f.cookie_name}`, status: 'WEAK', value: f.detail, severity: f.severity, recommendation: '' })
    }
  }

  // Overall grade
  const score = computeOverallScore(results)
  results.unshift({ header: 'OVERALL GRADE', status: score.grade, value: `${score.score}/100`, severity: 'info', recommendation: '' })
}
```

**Step 3: Add tests for the upgraded audit**

**Step 4: Commit**

```bash
git commit -m "feat(vuln): upgrade header-audit with CSP deep analysis, cookie security, A-F grading"
```

---

## Track 2: scan/analyze → Curated Security Rules

### Task 4: Semgrep security rule curation

**Files:**
- Modify: `src/adapters/scan/analyze.ts`

**Change:** Replace `--config auto` with curated security-focused rule sets:

```typescript
const SEMGREP_SECURITY_CONFIGS = [
  'p/security-audit',       // Semgrep's security audit ruleset
  'p/owasp-top-ten',        // OWASP Top 10 specific rules
  'p/command-injection',    // Command injection patterns
  'p/sql-injection',        // SQL injection patterns
  'p/xss',                  // Cross-site scripting
  'p/jwt',                  // JWT security issues
  'p/secrets',              // Hardcoded secrets
  'p/insecure-transport',   // HTTP/TLS misconfig
]

// Build args:
const configArgs = SEMGREP_SECURITY_CONFIGS.flatMap(c => ['--config', c])
const semgrepArgs = ['scan', '--json', ...configArgs, repoPath]
```

Add `--severity WARNING` to filter out INFO-level noise.

**Step 1: Write test for config construction**

**Step 2: Update and test**

**Step 3: Commit**

```bash
git commit -m "feat(scan): upgrade semgrep to curated security rulesets (OWASP, injection, XSS, JWT)"
```

---

### Task 5: Custom semgrep rules for common gaps

**Files:**
- Create: `src/adapters/scan/rules/` directory
- Create: `src/adapters/scan/rules/opensec-flask-sqli.yaml`
- Create: `src/adapters/scan/rules/opensec-express-xss.yaml`
- Create: `src/adapters/scan/rules/opensec-django-raw.yaml`
- Create: `src/adapters/scan/rules/opensec-path-traversal.yaml`
- Create: `src/adapters/scan/rules/opensec-ssrf.yaml`

**Custom semgrep rules that catch what `auto` misses:**

```yaml
# src/adapters/scan/rules/opensec-flask-sqli.yaml
rules:
  - id: opensec-flask-sqli-fstring
    patterns:
      - pattern: |
          $QUERY = f"...{$INPUT}..."
          ...
          $DB.execute($QUERY, ...)
      - pattern-not: |
          $DB.execute($QUERY, $PARAMS)
    message: "SQL injection via f-string in Flask. Use parameterized queries: db.execute('SELECT ... WHERE id = ?', (id,))"
    severity: ERROR
    languages: [python]
    metadata:
      cwe: CWE-89
      owasp: A03:2021

  - id: opensec-flask-sqli-format
    pattern: |
      $DB.execute("..." % $INPUT)
    message: "SQL injection via % formatting. Use parameterized queries."
    severity: ERROR
    languages: [python]
    metadata:
      cwe: CWE-89
```

```yaml
# src/adapters/scan/rules/opensec-express-xss.yaml
rules:
  - id: opensec-express-raw-html
    patterns:
      - pattern: res.send($INPUT)
      - pattern-not: res.send($STATIC_STRING)
      - pattern-inside: |
          function $HANDLER(req, res, ...) { ... }
    message: "Potential XSS: user-controlled input sent directly via res.send(). Use template engine with auto-escaping."
    severity: WARNING
    languages: [javascript, typescript]
    metadata:
      cwe: CWE-79

  - id: opensec-express-innerHTML
    pattern: $EL.innerHTML = $INPUT
    message: "DOM XSS via innerHTML assignment. Use textContent or a sanitization library."
    severity: ERROR
    languages: [javascript, typescript]
    metadata:
      cwe: CWE-79
```

```yaml
# src/adapters/scan/rules/opensec-path-traversal.yaml
rules:
  - id: opensec-path-traversal-join
    patterns:
      - pattern: |
          $PATH = path.join(..., $INPUT, ...)
          ...
          fs.readFile($PATH, ...)
      - pattern-not: |
          $PATH = path.resolve(...)
          if (!$PATH.startsWith(...)) { ... }
    message: "Path traversal: user input in path.join() without containment check. Validate with path.resolve() + startsWith()."
    severity: ERROR
    languages: [javascript, typescript]
    metadata:
      cwe: CWE-22

  - id: opensec-path-traversal-python
    pattern: |
      open(os.path.join(..., $INPUT, ...), ...)
    message: "Path traversal: user input in os.path.join() without realpath check."
    severity: ERROR
    languages: [python]
    metadata:
      cwe: CWE-22
```

```yaml
# src/adapters/scan/rules/opensec-ssrf.yaml
rules:
  - id: opensec-ssrf-fetch
    patterns:
      - pattern: fetch($URL, ...)
      - pattern-where-python: |
          $URL is not a string literal
    message: "SSRF: user-controlled URL passed to fetch(). Validate against allowlist."
    severity: WARNING
    languages: [javascript, typescript]
    metadata:
      cwe: CWE-918

  - id: opensec-ssrf-requests
    pattern: requests.get($URL, ...)
    message: "SSRF: user-controlled URL passed to requests.get(). Validate against allowlist."
    severity: WARNING
    languages: [python]
    metadata:
      cwe: CWE-918
```

**Step 1: Modify scan/analyze.ts to include custom rules**

```typescript
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync } from 'node:fs'

const __dirname = dirname(fileURLToPath(import.meta.url))
const CUSTOM_RULES_DIR = join(__dirname, 'rules')

// In runSemgrep:
const configArgs = SEMGREP_SECURITY_CONFIGS.flatMap(c => ['--config', c])
if (existsSync(CUSTOM_RULES_DIR)) {
  configArgs.push('--config', CUSTOM_RULES_DIR)
}
```

**Step 2: Copy rules to dist during build** — Add to scripts/copy-yaml.cjs

**Step 3: Test with known vulnerable code samples**

**Step 4: Commit**

```bash
git commit -m "feat(scan): add custom semgrep rules for Flask SQLi, Express XSS, path traversal, SSRF"
```

---

## Track 3: Pentest Tooling → Real Detection Capability

### Task 6: Payload Library

**Files:**
- Create: `src/adapters/pentest/payloads.ts`
- Test: `tests/unit/payloads.test.ts`

```typescript
// src/adapters/pentest/payloads.ts
export const PAYLOADS = {
  sqli: {
    detection: [
      "' OR '1'='1",
      "' OR '1'='1' --",
      "1 UNION SELECT NULL--",
      "1' AND SLEEP(5)--",
      "' OR 1=1#",
      "admin'--",
      "1; SELECT 1--",
      "' OR ''='",
    ],
    error_based: [
      "' AND 1=CONVERT(int,(SELECT @@version))--",
      "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
    ],
    time_based: [
      "'; WAITFOR DELAY '0:0:5'--",
      "1' AND SLEEP(5)#",
      "1' AND pg_sleep(5)--",
    ],
  },
  xss: {
    detection: [
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
      '"><img src=x onerror=alert(1)>',
      "'-alert(1)-'",
      'javascript:alert(1)',
    ],
    filter_bypass: [
      '<img/src=x onerror=alert(1)>',
      '<ScRiPt>alert(1)</sCrIpT>',
      '&#x3C;script&#x3E;alert(1)',
      '<svg/onload=alert`1`>',
      '<details open ontoggle=alert(1)>',
    ],
    dom: [
      '#<img src=x onerror=alert(1)>',
      'javascript:alert(document.domain)',
    ],
  },
  ssrf: {
    detection: [
      'http://127.0.0.1',
      'http://localhost',
      'http://0.0.0.0',
      'http://[::1]',
      'http://169.254.169.254/latest/meta-data/',
      'http://metadata.google.internal/',
    ],
    bypass: [
      'http://0x7f.0x0.0x0.0x1',          // hex IP
      'http://2130706433',                  // decimal IP
      'http://127.1',                       // short IP
      'http://0177.0.0.1',                 // octal IP
      'http://localtest.me',               // DNS rebinding
    ],
  },
  path_traversal: {
    detection: [
      '../../../etc/passwd',
      '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
      '....//....//....//etc/passwd',
      '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      '..%252f..%252f..%252fetc/passwd',
    ],
  },
  command_injection: {
    detection: [
      '; id',
      '| id',
      '`id`',
      '$(id)',
      '; sleep 5',
      '| sleep 5',
    ],
  },
  open_redirect: {
    detection: [
      'https://evil.com',
      '//evil.com',
      '/\\evil.com',
      'https:evil.com',
    ],
  },
}

export type PayloadCategory = keyof typeof PAYLOADS
export type PayloadSubcategory<C extends PayloadCategory> = keyof typeof PAYLOADS[C]

export function getPayloads(category: PayloadCategory, subcategory?: string): string[] {
  const cat = PAYLOADS[category]
  if (subcategory && subcategory in cat) {
    return (cat as Record<string, string[]>)[subcategory]
  }
  return Object.values(cat).flat()
}
```

**Step 1: Test payloads**

**Step 2: Commit**

```bash
git commit -m "feat(pentest): add payload library for SQLi, XSS, SSRF, path traversal, command injection"
```

---

### Task 7: Parameter Fuzzer

**Files:**
- Create: `src/adapters/pentest/fuzz.ts`
- Test: `tests/unit/pentest-fuzz.test.ts`

```typescript
// src/adapters/pentest/fuzz.ts — opensec pentest fuzz
cli({
  provider: 'pentest',
  name: 'fuzz',
  description: 'Fuzz URL parameters with security payloads and detect anomalies',
  strategy: Strategy.FREE,
  domain: 'pentest',
  args: {
    url: { type: 'string', required: true, help: 'Target URL with parameters (e.g., https://example.com/search?q=test)' },
    payloads: { type: 'string', default: 'sqli,xss', help: 'Payload categories: sqli, xss, ssrf, path_traversal, command_injection, open_redirect' },
    param: { type: 'string', required: false, help: 'Specific parameter to fuzz (default: all query params)' },
    headers: { type: 'string', required: false, help: 'Custom headers as JSON' },
    match: { type: 'string', required: false, help: 'Regex pattern to match in response (indicates vulnerability)' },
    threads: { type: 'number', default: 5, help: 'Concurrent requests' },
  },
  columns: ['param', 'payload_type', 'payload', 'status', 'length', 'anomaly', 'evidence'],

  async func(ctx, args) {
    // 1. Parse URL and extract parameters
    // 2. For each param × payload combination:
    //    - Replace param value with payload
    //    - Send request
    //    - Compare response to baseline (original value)
    //    - Flag anomalies: status code change, significant length change, error keywords, reflection
    // 3. Return findings with evidence
  }
})
```

Anomaly detection logic:
- **Status change**: baseline 200 → payload 500 = likely error-based injection
- **Length anomaly**: response length differs by >20% from baseline = data extraction or error
- **Error signatures**: `SQL syntax`, `mysql_`, `pg_`, `ORA-`, `unclosed quotation`, `syntax error`
- **Reflection**: payload appears in response body (XSS candidate)
- **Time anomaly**: response time >5s when baseline <1s (time-based injection)

**Step 1: Implement with proper batching**

**Step 2: Commit**

```bash
git commit -m "feat(pentest): add parameter fuzzer with anomaly detection"
```

---

### Task 8: Upgrade CORS checker

**Files:**
- Modify: `src/adapters/vuln/cors-check.ts`

Add these tests that the current 5 don't cover:

```typescript
// New CORS tests to add:
{ name: 'prefix-match', origin: (domain) => `https://${domain}.evil.com`, severity: 'high' },
{ name: 'suffix-match', origin: (domain) => `https://evil${domain}`, severity: 'high' },
{ name: 'wildcard-credentials', origin: () => 'https://anything.com', severity: 'critical' },
// Check: acao === '*' AND acac === 'true' — impossible per spec but some frameworks misconfigure
{ name: 'preflight-cache', origin: (domain) => `https://evil-${domain}`, severity: 'medium' },
// Send OPTIONS request, check Access-Control-Max-Age for excessive caching
```

Also add preflight check:
```typescript
// Send OPTIONS request with Access-Control-Request-Method
const preflightResponse = await fetch(url, {
  method: 'OPTIONS',
  headers: {
    Origin: 'https://evil.com',
    'Access-Control-Request-Method': 'PUT',
    'Access-Control-Request-Headers': 'X-Custom',
  },
})
// Check if PUT/DELETE are allowed from cross-origin
```

**Step 1: Implement, test**

**Step 2: Commit**

```bash
git commit -m "feat(vuln): upgrade CORS checker with preflight, prefix/suffix, and 9 test vectors"
```

---

## Task 9: Final Build + Verification

```bash
npx tsc --noEmit
npx vitest run
rm -rf dist && npx tsc --incremental false && npm run copy-yaml && npm run build-manifest
# Smoke test
node dist/main.js vuln header-audit --url https://example.com --format json | head -20
node dist/main.js crypto hash-id --hash 5d41402abc4b2a76b9719d911017c592
```

```bash
git add -A && git push origin main
```

---

## Impact Summary

| Adapter | Before | After |
|---------|--------|-------|
| header-audit | 7 headers, exists/missing | **15+ checks, CSP parser, cookie analyzer, A-F grade** |
| scan/analyze | `semgrep --config auto` | **8 curated security rulesets + 10 custom rules** |
| pentest | bare fetch() | **Payload library (80+ payloads) + parameter fuzzer + anomaly detection** |
| cors-check | 5 Origin tests | **9+ tests + preflight analysis + prefix/suffix bypass** |

## Unresolved Questions

1. Should the payload fuzzer respect rate limiting by default? (Probably yes — add `--delay` flag)
2. Should custom semgrep rules ship with the npm package? (Yes — copy-yaml.cjs needs to also copy rules/)
3. Should header-audit make a GET request instead of HEAD? (GET reveals more: Set-Cookie headers, body for CSP meta tags)
