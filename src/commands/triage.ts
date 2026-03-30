/**
 * AI-powered finding triage.
 * Uses Claude API to perform attacker/defender analysis on each finding.
 * Requires ANTHROPIC_API_KEY env var.
 *
 * Usage:
 *   opensec scan analyze --path . --format json | opensec triage
 *   opensec triage --input scan-results.json
 *   opensec db list --format json | opensec triage
 */

import { readFile } from 'node:fs/promises'
import chalk from 'chalk'
import { render } from '../output.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Finding {
  readonly rule_id?: string
  readonly severity?: string
  readonly file_path?: string
  readonly line?: number
  readonly message?: string
  readonly cwe?: string
  readonly title?: string
  readonly [key: string]: unknown
}

interface TriageVerdict {
  readonly verdict: 'CONFIRMED' | 'FALSE_POSITIVE' | 'NEEDS_REVIEW'
  readonly confidence: number
  readonly attacker_summary: string
  readonly defender_summary: string
  readonly reasoning: string
}

interface TriageResult {
  readonly title: string
  readonly severity: string
  readonly verdict: string
  readonly confidence: number
  readonly attacker_summary: string
  readonly defender_summary: string
}

interface TriageOptions {
  readonly input?: string
  readonly model?: string
  readonly maxFindings?: string
}

interface ClaudeMessageResponse {
  readonly content?: ReadonlyArray<{
    readonly type: string
    readonly text?: string
  }>
  readonly error?: {
    readonly message: string
  }
}

// ---------------------------------------------------------------------------
// Prompt construction (exported for testing)
// ---------------------------------------------------------------------------

export function buildTriagePrompt(finding: Finding): string {
  const ruleId = finding.rule_id ?? finding.title ?? 'unknown'
  const severity = finding.severity ?? 'unknown'
  const filePath = finding.file_path ?? 'unknown'
  const line = finding.line ?? 0
  const message = finding.message ?? finding.title ?? ''
  const cwe = finding.cwe ?? 'N/A'

  return `You are a security triage expert. Analyze this finding and determine if it's a real vulnerability or a false positive.

Finding:
- Rule: ${ruleId}
- Severity: ${severity}
- File: ${filePath}:${line}
- Message: ${message}
- CWE: ${cwe}

Perform two analyses:

ATTACKER ANALYSIS (try to prove it's exploitable):
1. Is there a concrete data flow from user input to this sink?
2. Can existing sanitization be bypassed?
3. What's the worst-case impact?

DEFENDER ANALYSIS (try to prove it's mitigated):
1. Are there framework-level protections (ORM, auto-escaping, CSRF tokens)?
2. Is the code actually reachable from a public endpoint?
3. Are there input validation or output encoding controls?

Based on both analyses, provide your verdict.

Respond in this exact JSON format:
{
  "verdict": "CONFIRMED" | "FALSE_POSITIVE" | "NEEDS_REVIEW",
  "confidence": 0-100,
  "attacker_summary": "one sentence",
  "defender_summary": "one sentence",
  "reasoning": "2-3 sentences explaining the verdict"
}`
}

// ---------------------------------------------------------------------------
// Response parsing (exported for testing)
// ---------------------------------------------------------------------------

export function parseTriageResponse(text: string): TriageVerdict {
  // Extract JSON from the response — Claude may wrap it in markdown code blocks
  const jsonMatch = text.match(/\{[\s\S]*\}/)
  if (!jsonMatch) {
    return {
      verdict: 'NEEDS_REVIEW',
      confidence: 0,
      attacker_summary: 'Failed to parse AI response',
      defender_summary: 'Failed to parse AI response',
      reasoning: 'Could not extract JSON from response',
    }
  }

  try {
    const parsed = JSON.parse(jsonMatch[0]) as Record<string, unknown>

    const verdict = validateVerdict(parsed.verdict)
    const confidence = validateConfidence(parsed.confidence)

    return {
      verdict,
      confidence,
      attacker_summary: typeof parsed.attacker_summary === 'string'
        ? parsed.attacker_summary
        : 'No attacker summary provided',
      defender_summary: typeof parsed.defender_summary === 'string'
        ? parsed.defender_summary
        : 'No defender summary provided',
      reasoning: typeof parsed.reasoning === 'string'
        ? parsed.reasoning
        : 'No reasoning provided',
    }
  } catch {
    return {
      verdict: 'NEEDS_REVIEW',
      confidence: 0,
      attacker_summary: 'Failed to parse AI response',
      defender_summary: 'Failed to parse AI response',
      reasoning: 'JSON parsing failed',
    }
  }
}

function validateVerdict(value: unknown): TriageVerdict['verdict'] {
  const valid = ['CONFIRMED', 'FALSE_POSITIVE', 'NEEDS_REVIEW'] as const
  if (typeof value === 'string' && valid.includes(value as typeof valid[number])) {
    return value as TriageVerdict['verdict']
  }
  return 'NEEDS_REVIEW'
}

function validateConfidence(value: unknown): number {
  if (typeof value === 'number' && value >= 0 && value <= 100) {
    return Math.round(value)
  }
  return 0
}

// ---------------------------------------------------------------------------
// Claude API call
// ---------------------------------------------------------------------------

async function callClaude(
  prompt: string,
  apiKey: string,
  model: string,
): Promise<string> {
  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model,
      max_tokens: 500,
      messages: [{ role: 'user', content: prompt }],
    }),
  })

  if (!response.ok) {
    const errorText = await response.text()
    throw new Error(`Claude API returned ${response.status}: ${errorText}`)
  }

  const data = (await response.json()) as ClaudeMessageResponse

  if (data.error) {
    throw new Error(`Claude API error: ${data.error.message}`)
  }

  const textBlock = data.content?.find(b => b.type === 'text')
  if (!textBlock?.text) {
    throw new Error('No text content in Claude API response')
  }

  return textBlock.text
}

// ---------------------------------------------------------------------------
// Stdin reading (exported for testing)
// ---------------------------------------------------------------------------

export async function readFindingsFromStdin(): Promise<readonly Finding[]> {
  const chunks: Buffer[] = []
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer)
  }
  const raw = Buffer.concat(chunks).toString('utf-8')
  return JSON.parse(raw) as Finding[]
}

// ---------------------------------------------------------------------------
// Delay helper
// ---------------------------------------------------------------------------

function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

// ---------------------------------------------------------------------------
// Finding title extraction
// ---------------------------------------------------------------------------

function extractFindingTitle(finding: Finding): string {
  return finding.title
    ?? finding.rule_id
    ?? finding.message?.slice(0, 60)
    ?? 'Unknown finding'
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

export async function runTriage(opts: TriageOptions): Promise<void> {
  const apiKey = process.env['ANTHROPIC_API_KEY']
  if (!apiKey) {
    process.stderr.write(chalk.red('\nError: ANTHROPIC_API_KEY environment variable is not set.\n'))
    process.stderr.write(chalk.gray('  Set it with: export ANTHROPIC_API_KEY=sk-ant-...\n'))
    process.stderr.write(chalk.gray('  Get a key at: https://console.anthropic.com/\n\n'))
    process.exit(1)
  }

  const model = opts.model ?? 'claude-sonnet-4-20250514'
  const maxFindings = parseInt(opts.maxFindings ?? '10', 10)

  // Load findings from file or stdin
  let findings: readonly Finding[]

  if (opts.input) {
    const raw = await readFile(opts.input, 'utf-8')
    findings = JSON.parse(raw) as Finding[]
  } else if (!process.stdin.isTTY) {
    findings = await readFindingsFromStdin()
  } else {
    process.stderr.write(chalk.red('\nError: No input provided.\n'))
    process.stderr.write(chalk.gray('  Pipe findings: opensec scan analyze --path . --format json | opensec triage\n'))
    process.stderr.write(chalk.gray('  Or use --input: opensec triage --input scan-results.json\n\n'))
    process.exit(1)
  }

  if (!Array.isArray(findings) || findings.length === 0) {
    process.stderr.write(chalk.yellow('\nNo findings to triage.\n\n'))
    return
  }

  const triageCount = Math.min(findings.length, maxFindings)
  const findingsToTriage = findings.slice(0, triageCount)

  process.stderr.write('\n')
  process.stderr.write(chalk.bold('  OpenSecCLI AI Triage\n'))
  process.stderr.write(chalk.gray(`  Model: ${model}\n`))
  process.stderr.write(chalk.gray(`  Findings: ${triageCount} of ${findings.length}\n`))
  process.stderr.write('\n')

  const results: TriageResult[] = []

  for (let i = 0; i < findingsToTriage.length; i++) {
    const finding = findingsToTriage[i]
    const title = extractFindingTitle(finding)
    process.stderr.write(chalk.cyan(`  [${i + 1}/${triageCount}]`) + ` Triaging: ${title}...\n`)

    try {
      const prompt = buildTriagePrompt(finding)
      const responseText = await callClaude(prompt, apiKey, model)
      const verdict = parseTriageResponse(responseText)

      results.push({
        title,
        severity: finding.severity ?? 'unknown',
        verdict: verdict.verdict,
        confidence: verdict.confidence,
        attacker_summary: verdict.attacker_summary,
        defender_summary: verdict.defender_summary,
      })

      const verdictColor = verdict.verdict === 'CONFIRMED'
        ? chalk.red
        : verdict.verdict === 'FALSE_POSITIVE'
          ? chalk.green
          : chalk.yellow

      process.stderr.write(
        `           ${verdictColor(verdict.verdict)} (${verdict.confidence}%)\n`,
      )
    } catch (error) {
      process.stderr.write(chalk.red(`           Error: ${(error as Error).message}\n`))

      results.push({
        title,
        severity: finding.severity ?? 'unknown',
        verdict: 'NEEDS_REVIEW',
        confidence: 0,
        attacker_summary: 'API call failed',
        defender_summary: (error as Error).message,
      })
    }

    // Rate limit: 500ms delay between calls (skip after last)
    if (i < findingsToTriage.length - 1) {
      await delay(500)
    }
  }

  process.stderr.write('\n')

  render(results, {
    columns: ['title', 'severity', 'verdict', 'confidence', 'attacker_summary', 'defender_summary'],
  })
}
