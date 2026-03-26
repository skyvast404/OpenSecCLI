/**
 * Normalizer for raw security test sources into canonical attack case format.
 * Reads source YAMLs, extracts metadata, writes canonical case YAMLs.
 * Pure TypeScript — uses js-yaml.
 */

import { cli, Strategy } from '../../registry.js'
import type { AdapterResult, ExecContext } from '../../types.js'
import { readdir, readFile, writeFile, mkdir } from 'node:fs/promises'
import { join, basename, extname } from 'node:path'
import YAML from 'js-yaml'

interface SourceDoc {
  id?: string
  category?: string
  attack_surface?: string
  expected_risk?: string
  name?: string
  description?: string
  [key: string]: unknown
}

interface CanonicalCase {
  case_id: string
  source_ref: string
  category: string
  attack_surface: string
  expected_risk: string
  name: string
  description: string
  status: string
}

function generateCaseId(sourceId: string, index: number): string {
  return `case-${sourceId || `src${index}`}`
}

function buildCanonicalCase(source: SourceDoc, index: number): CanonicalCase {
  const sourceId = source.id ?? `src-${index}`
  return {
    case_id: generateCaseId(sourceId, index),
    source_ref: sourceId,
    category: source.category ?? 'uncategorized',
    attack_surface: source.attack_surface ?? 'unknown',
    expected_risk: source.expected_risk ?? 'unknown',
    name: source.name ?? '',
    description: source.description ?? '',
    status: 'experimental',
  }
}

cli({
  provider: 'agent-security',
  name: 'normalize-cases',
  description: 'Normalize raw security test sources into canonical attack case format',
  strategy: Strategy.FREE,
  domain: 'agent-security',
  args: {
    sources_dir: {
      type: 'string',
      required: true,
      help: 'Path to sources directory',
    },
    output_dir: {
      type: 'string',
      required: true,
      help: 'Path to output cases directory',
    },
  },
  columns: ['source_id', 'case_id', 'category', 'status'],

  async func(ctx: ExecContext, args: Record<string, unknown>): Promise<AdapterResult> {
    const sourcesDir = args.sources_dir as string
    const outputDir = args.output_dir as string

    ctx.log.info(`Normalizing cases from ${sourcesDir} to ${outputDir}`)

    await mkdir(outputDir, { recursive: true })

    let files: string[]
    try {
      files = await readdir(sourcesDir)
    } catch (error) {
      throw new Error(`Cannot read sources directory: ${(error as Error).message}`)
    }

    const yamlFiles = files.filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'))
    const results: Record<string, unknown>[] = []

    for (let i = 0; i < yamlFiles.length; i++) {
      const file = yamlFiles[i]
      const raw = await readFile(join(sourcesDir, file), 'utf-8')
      const source = YAML.load(raw) as SourceDoc | null

      if (!source || typeof source !== 'object') {
        ctx.log.warn(`Skipping invalid source: ${file}`)
        continue
      }

      const canonical = buildCanonicalCase(source, i)
      const outFileName = `${basename(file, extname(file))}.case.yaml`
      const outPath = join(outputDir, outFileName)

      await writeFile(outPath, YAML.dump(canonical))

      results.push({
        source_id: canonical.source_ref,
        case_id: canonical.case_id,
        category: canonical.category,
        status: canonical.status,
      })
    }

    ctx.log.info(`Normalized ${results.length} cases to ${outputDir}`)
    return results
  },
})
