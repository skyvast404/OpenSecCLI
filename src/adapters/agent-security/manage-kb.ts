/**
 * Knowledge base manager for agent security.
 * Reads YAML-based attack patterns, detection rules, and defense playbooks.
 * Pure TypeScript — uses js-yaml for parsing.
 */

import { cli, Strategy } from '../../registry.js'
import type { AdapterResult, ExecContext } from '../../types.js'
import { readdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import YAML from 'js-yaml'

type RecordType = 'attack' | 'detection' | 'defense'

interface KbRecord {
  id: string
  type: RecordType
  name: string
  tactic?: string
  mapped_to?: string[]
  status?: string
  [key: string]: unknown
}

const SUBDIR_MAP: Record<RecordType, string> = {
  attack: 'attack_patterns',
  detection: 'detection_rules',
  defense: 'defense_playbooks',
}

async function readYamlDir(dirPath: string, type: RecordType): Promise<KbRecord[]> {
  const records: KbRecord[] = []

  let files: string[]
  try {
    files = await readdir(dirPath)
  } catch {
    return records
  }

  const yamlFiles = files.filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'))

  const contents = await Promise.all(
    yamlFiles.map(async (f) => {
      const raw = await readFile(join(dirPath, f), 'utf-8')
      return YAML.load(raw) as Record<string, unknown> | null
    }),
  )

  for (const doc of contents) {
    if (!doc || typeof doc !== 'object') continue
    records.push({
      ...doc,
      id: (doc.id as string) ?? '',
      type,
      name: (doc.name as string) ?? '',
      tactic: (doc.tactic as string) ?? '',
      mapped_to: (doc.mapped_to as string[]) ?? [],
      status: (doc.status as string) ?? '',
    })
  }

  return records
}

async function loadAllRecords(
  kbDir: string,
  typeFilter?: RecordType,
): Promise<KbRecord[]> {
  const types: RecordType[] = typeFilter ? [typeFilter] : ['attack', 'detection', 'defense']

  const results = await Promise.all(
    types.map((t) => readYamlDir(join(kbDir, SUBDIR_MAP[t]), t)),
  )

  return results.flat()
}

export function validateMappings(records: KbRecord[]): Record<string, unknown>[] {
  const attacks = records.filter((r) => r.type === 'attack')
  const detections = records.filter((r) => r.type === 'detection')
  const defenses = records.filter((r) => r.type === 'defense')

  const detectionIds = new Set(detections.map((d) => d.id))
  const defenseIds = new Set(defenses.map((d) => d.id))

  const rows: Record<string, unknown>[] = []

  for (const attack of attacks) {
    const mappedTo = attack.mapped_to ?? []
    const hasDetection = mappedTo.some((m) => detectionIds.has(m))
    const hasDefense = mappedTo.some((m) => defenseIds.has(m))

    const status = hasDetection && hasDefense ? 'complete' : 'incomplete'
    const missing: string[] = []
    if (!hasDetection) missing.push('detection')
    if (!hasDefense) missing.push('defense')

    rows.push({
      id: attack.id,
      type: attack.type,
      name: attack.name,
      tactic: attack.tactic ?? '',
      mapped_to: mappedTo.join(', '),
      status: status + (missing.length > 0 ? ` (missing: ${missing.join(', ')})` : ''),
    })
  }

  return rows
}

cli({
  provider: 'agent-security',
  name: 'manage-kb',
  description:
    'Manage agent security knowledge base (attack patterns, detection rules, defense playbooks)',
  strategy: Strategy.FREE,
  domain: 'agent-security',
  args: {
    action: {
      type: 'string',
      required: true,
      choices: ['list', 'get', 'validate'],
      help: 'Action to perform',
    },
    kb_dir: {
      type: 'string',
      required: true,
      help: 'Path to knowledge base directory',
    },
    type: {
      type: 'string',
      choices: ['attack', 'detection', 'defense'],
      help: 'Record type filter',
    },
    id: {
      type: 'string',
      help: 'Record ID (required for get action)',
    },
  },
  columns: ['id', 'type', 'name', 'tactic', 'mapped_to', 'status'],

  async func(ctx: ExecContext, args: Record<string, unknown>): Promise<AdapterResult> {
    const action = args.action as string
    const kbDir = args.kb_dir as string
    const typeFilter = args.type as RecordType | undefined

    ctx.log.info(`Running manage-kb action=${action} on ${kbDir}`)

    const records = await loadAllRecords(kbDir, typeFilter)

    switch (action) {
      case 'list': {
        return records.map((r) => ({
          id: r.id,
          type: r.type,
          name: r.name,
          tactic: r.tactic ?? '',
          mapped_to: (r.mapped_to ?? []).join(', '),
          status: r.status ?? '',
        }))
      }

      case 'get': {
        const targetId = args.id as string | undefined
        if (!targetId) {
          throw new Error('--id is required for get action')
        }
        const found = records.find((r) => r.id === targetId)
        if (!found) {
          throw new Error(`Record not found: ${targetId}`)
        }
        return [
          {
            id: found.id,
            type: found.type,
            name: found.name,
            tactic: found.tactic ?? '',
            mapped_to: (found.mapped_to ?? []).join(', '),
            status: found.status ?? '',
          },
        ]
      }

      case 'validate': {
        const allRecords = await loadAllRecords(kbDir)
        const rows = validateMappings(allRecords)
        ctx.log.info(`Validated ${rows.length} attack patterns`)
        return rows
      }

      default:
        throw new Error(`Unknown action: ${action}`)
    }
  },
})
