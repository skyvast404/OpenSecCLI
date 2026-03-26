/**
 * Variant generator for agent security test suites.
 * Expands suite manifests into concrete mutated test cases using mutation rules.
 * Pure TypeScript — uses js-yaml.
 */

import { cli, Strategy } from '../../registry.js'
import type { AdapterResult, ExecContext } from '../../types.js'
import { readdir, readFile, writeFile } from 'node:fs/promises'
import { join, dirname } from 'node:path'
import { mkdir } from 'node:fs/promises'
import YAML from 'js-yaml'

interface SuiteManifest {
  suite_id?: string
  cases?: Array<{
    case_id: string
    [key: string]: unknown
  }>
  [key: string]: unknown
}

interface MutationRule {
  rule_id?: string
  name?: string
  transform?: string
  [key: string]: unknown
}

interface Variant {
  variant_id: string
  parent_case_id: string
  mutation_rule_id: string
  [key: string]: unknown
}

async function loadMutationRules(mutationsDir: string): Promise<MutationRule[]> {
  let files: string[]
  try {
    files = await readdir(mutationsDir)
  } catch {
    return []
  }

  const yamlFiles = files.filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'))
  const rules: MutationRule[] = []

  for (const file of yamlFiles) {
    const raw = await readFile(join(mutationsDir, file), 'utf-8')
    const doc = YAML.load(raw) as MutationRule | null
    if (doc && typeof doc === 'object') {
      rules.push({
        ...doc,
        rule_id: doc.rule_id ?? file.replace(/\.(yaml|yml)$/, ''),
      })
    }
  }

  return rules
}

function generateVariants(
  cases: SuiteManifest['cases'],
  rules: MutationRule[],
): { variants: Variant[]; summary: Record<string, unknown>[] } {
  const variants: Variant[] = []
  const summary: Record<string, unknown>[] = []

  for (const testCase of cases ?? []) {
    let variantCount = 0

    for (const rule of rules) {
      const ruleId = rule.rule_id ?? 'unknown'
      const variantId = `${testCase.case_id}-${ruleId}`

      variants.push({
        variant_id: variantId,
        parent_case_id: testCase.case_id,
        mutation_rule_id: ruleId,
        mutation_name: rule.name ?? '',
        transform: rule.transform ?? '',
        ...testCase,
        case_id: variantId,
      })

      variantCount++
    }

    summary.push({
      case_id: testCase.case_id,
      parent_case_id: testCase.case_id,
      mutation_rule: rules.map((r) => r.rule_id).join(', '),
      variant_count: variantCount,
    })
  }

  return { variants, summary }
}

cli({
  provider: 'agent-security',
  name: 'generate-variants',
  description: 'Expand suite manifests into concrete mutated test cases',
  strategy: Strategy.FREE,
  domain: 'agent-security',
  args: {
    suite: {
      type: 'string',
      required: true,
      help: 'Path to suite manifest YAML',
    },
    mutations_dir: {
      type: 'string',
      required: true,
      help: 'Path to mutations directory',
    },
    output: {
      type: 'string',
      required: true,
      help: 'Output file path for expanded suite',
    },
  },
  columns: ['case_id', 'parent_case_id', 'mutation_rule', 'variant_count'],

  async func(ctx: ExecContext, args: Record<string, unknown>): Promise<AdapterResult> {
    const suitePath = args.suite as string
    const mutationsDir = args.mutations_dir as string
    const outputPath = args.output as string

    ctx.log.info(`Expanding suite ${suitePath} with mutations from ${mutationsDir}`)

    const suiteRaw = await readFile(suitePath, 'utf-8')
    const suite = YAML.load(suiteRaw) as SuiteManifest | null

    if (!suite || typeof suite !== 'object') {
      throw new Error(`Invalid suite manifest: ${suitePath}`)
    }

    const rules = await loadMutationRules(mutationsDir)
    if (rules.length === 0) {
      throw new Error(`No mutation rules found in ${mutationsDir}`)
    }

    ctx.log.info(`Loaded ${rules.length} mutation rules`)

    const { variants, summary } = generateVariants(suite.cases, rules)

    const outputDir = dirname(outputPath)
    await mkdir(outputDir, { recursive: true })

    const expandedSuite = {
      suite_id: suite.suite_id ?? 'expanded',
      source_suite: suitePath,
      total_variants: variants.length,
      variants,
    }

    await writeFile(outputPath, JSON.stringify(expandedSuite, null, 2))

    ctx.log.info(`Generated ${variants.length} variants, written to ${outputPath}`)
    return summary
  },
})
