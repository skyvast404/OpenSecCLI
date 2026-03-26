/**
 * Triage memory manager for false-positive tracking and skip logic.
 * Stores decisions in ~/.openseccli/triage-memory.json for persistent
 * cross-session triage state.
 *
 * Strategy: FREE — pure TypeScript, no external tools required.
 */

import { cli, Strategy } from '../../registry.js'
import type { AdapterResult, ExecContext } from '../../types.js'
import { readFileSync, writeFileSync, mkdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'

// --- Types ---

export interface TriageRecord {
  fingerprint: string
  decision: string
  confidence: number
  consecutive_fps: number
  should_skip: boolean
  updated_at: string
  [key: string]: unknown
}

export interface TriageMemory {
  records: Record<string, TriageRecord>
}

// --- Storage ---

function getMemoryPath(): string {
  return join(homedir(), '.openseccli', 'triage-memory.json')
}

export function loadMemory(memoryPath?: string): TriageMemory {
  const path = memoryPath ?? getMemoryPath()
  try {
    const raw = readFileSync(path, 'utf-8')
    const parsed = JSON.parse(raw) as TriageMemory
    return { records: parsed.records ?? {} }
  } catch {
    return { records: {} }
  }
}

export function saveMemory(memory: TriageMemory, memoryPath?: string): void {
  const path = memoryPath ?? getMemoryPath()
  const dir = join(path, '..')
  try {
    mkdirSync(dir, { recursive: true })
  } catch {
    // Directory already exists
  }
  writeFileSync(path, JSON.stringify(memory, null, 2), 'utf-8')
}

// --- Skip Logic ---

/**
 * Determine if a finding should be auto-skipped.
 * Skip when consecutive false positives >= 3 AND last confidence < 40.
 */
export function shouldSkip(record: TriageRecord): boolean {
  return record.consecutive_fps >= 3 && record.confidence < 40
}

// --- Actions ---

export function queryFingerprint(
  memory: TriageMemory,
  fingerprint: string,
): TriageRecord | null {
  const record = memory.records[fingerprint]
  if (!record) return null

  return {
    ...record,
    should_skip: shouldSkip(record),
  }
}

export function updateFingerprint(
  memory: TriageMemory,
  fingerprint: string,
  verdict: string,
  confidence: number,
): TriageMemory {
  const existing = memory.records[fingerprint]
  const now = new Date().toISOString()

  let consecutiveFps = existing?.consecutive_fps ?? 0

  // Reset FP streak on high confidence + vulnerable
  if (confidence > 70 && verdict === 'vulnerable') {
    consecutiveFps = 0
  }
  // Increment on low confidence + safe/needs_review
  else if (confidence < 40 && (verdict === 'safe' || verdict === 'needs_review')) {
    consecutiveFps = consecutiveFps + 1
  }
  // Preserve streak on 40-70 confidence (no change)

  const newRecord: TriageRecord = {
    fingerprint,
    decision: verdict,
    confidence,
    consecutive_fps: consecutiveFps,
    should_skip: false, // computed on read
    updated_at: now,
  }
  newRecord.should_skip = shouldSkip(newRecord)

  return {
    records: {
      ...memory.records,
      [fingerprint]: newRecord,
    },
  }
}

export function listRecords(memory: TriageMemory): TriageRecord[] {
  return Object.values(memory.records).map((r) => ({
    ...r,
    should_skip: shouldSkip(r),
  }))
}

export function pruneMemory(memory: TriageMemory, memoryPath?: string): TriageMemory {
  const path = memoryPath ?? getMemoryPath()

  // Check file size
  let fileSize = 0
  try {
    const stat = statSync(path)
    fileSize = stat.size
  } catch {
    return memory
  }

  const TEN_MB = 10 * 1024 * 1024
  if (fileSize < TEN_MB) {
    return memory
  }

  // Remove oldest 50% by updated_at
  const entries = Object.entries(memory.records)
  const sorted = [...entries].sort(
    (a, b) => new Date(a[1].updated_at).getTime() - new Date(b[1].updated_at).getTime(),
  )

  const halfIndex = Math.ceil(sorted.length / 2)
  const kept = sorted.slice(halfIndex)

  const pruned: TriageMemory = {
    records: Object.fromEntries(kept),
  }

  return pruned
}

// --- CLI Registration ---

cli({
  provider: 'scan',
  name: 'triage-memory',
  description:
    'Manage triage memory for false-positive tracking and skip logic',
  strategy: Strategy.FREE,
  domain: 'code-security',
  args: {
    action: {
      type: 'string',
      required: true,
      choices: ['query', 'update', 'list', 'prune'],
      help: 'Action to perform',
    },
    fingerprint: {
      type: 'string',
      required: false,
      help: 'Finding fingerprint (file|rule_id|CWE|snippet_prefix)',
    },
    verdict: {
      type: 'string',
      required: false,
      choices: ['vulnerable', 'safe', 'needs_review'],
      help: 'Triage verdict',
    },
    confidence: {
      type: 'number',
      required: false,
      help: 'Confidence score 0-100',
    },
  },
  columns: [
    'fingerprint',
    'decision',
    'confidence',
    'consecutive_fps',
    'should_skip',
    'updated_at',
  ],

  async func(ctx: ExecContext, args: Record<string, unknown>): Promise<AdapterResult> {
    const action = args.action as string
    const fingerprint = args.fingerprint as string | undefined
    const verdict = args.verdict as string | undefined
    const confidence = args.confidence as number | undefined

    const memory = loadMemory()

    switch (action) {
      case 'query': {
        if (!fingerprint) {
          throw new Error('fingerprint is required for query action')
        }

        const record = queryFingerprint(memory, fingerprint)
        if (!record) {
          ctx.log.info(`No triage record found for: ${fingerprint}`)
          return []
        }

        ctx.log.info(
          `Found record: ${record.decision} (confidence: ${record.confidence}, skip: ${record.should_skip})`,
        )
        return [record]
      }

      case 'update': {
        if (!fingerprint) {
          throw new Error('fingerprint is required for update action')
        }
        if (!verdict) {
          throw new Error('verdict is required for update action')
        }
        if (confidence === undefined || confidence === null) {
          throw new Error('confidence is required for update action')
        }

        const updated = updateFingerprint(memory, fingerprint, verdict, confidence)
        saveMemory(updated)

        const record = updated.records[fingerprint]
        ctx.log.info(
          `Updated: ${fingerprint} -> ${verdict} (confidence: ${confidence}, fps: ${record.consecutive_fps})`,
        )
        return [record]
      }

      case 'list': {
        const records = listRecords(memory)
        ctx.log.info(`${records.length} triage records`)
        return records
      }

      case 'prune': {
        const pruned = pruneMemory(memory)
        const beforeCount = Object.keys(memory.records).length
        const afterCount = Object.keys(pruned.records).length

        if (beforeCount !== afterCount) {
          saveMemory(pruned)
          ctx.log.info(`Pruned: ${beforeCount} -> ${afterCount} records`)
        } else {
          ctx.log.info('No pruning needed (file under 10MB)')
        }

        return listRecords(pruned)
      }

      default:
        throw new Error(`Unknown action: ${action}`)
    }
  },
})
