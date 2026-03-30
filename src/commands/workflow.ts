/**
 * Declarative workflow engine.
 * opensec workflow run web-audit.yaml --target example.com
 */

import { readFileSync } from 'node:fs'
import YAML from 'js-yaml'
import { getRegistry } from '../registry.js'
import { log } from '../logger.js'

interface WorkflowStep {
  name: string
  command: string    // registry key like "vuln/header-audit"
  args: Record<string, string>
  on_error?: 'stop' | 'continue' | 'skip'  // default: continue
}

interface WorkflowDef {
  name: string
  description?: string
  variables?: Record<string, string>
  steps: WorkflowStep[]
}

export interface StepResult {
  name: string
  command: string
  status: 'completed' | 'failed' | 'skipped'
  findings: number
  duration_ms: number
  error?: string
  data?: unknown
}

/** Simple template interpolation: {{ variable }} */
export function interpolate(template: string, vars: Record<string, string>): string {
  return template.replace(/\{\{\s*(\w+)\s*\}\}/g, (_, key) => vars[key] ?? '')
}

function interpolateArgs(
  args: Record<string, string>,
  vars: Record<string, string>,
): Record<string, unknown> {
  const result: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(args)) {
    result[k] = typeof v === 'string' ? interpolate(v, vars) : v
  }
  return result
}

export function parseWorkflowYaml(content: string): WorkflowDef {
  const raw = YAML.load(content)
  if (!raw || typeof raw !== 'object') {
    throw new Error('Invalid workflow YAML: expected an object')
  }
  const def = raw as Record<string, unknown>
  if (!def['name'] || typeof def['name'] !== 'string') {
    throw new Error('Invalid workflow YAML: missing "name" field')
  }
  if (!Array.isArray(def['steps']) || def['steps'].length === 0) {
    throw new Error('Invalid workflow YAML: "steps" must be a non-empty array')
  }
  return raw as WorkflowDef
}

export function resolveVariables(
  workflowVars: Record<string, string> | undefined,
  userVars: Record<string, string>,
): Record<string, string> {
  const vars: Record<string, string> = {}
  if (workflowVars) {
    for (const [k, v] of Object.entries(workflowVars)) {
      vars[k] = interpolate(v, userVars)
    }
  }
  // User variables override workflow-defined ones
  return { ...vars, ...userVars }
}

export async function runWorkflow(
  filePath: string,
  variables: Record<string, string>,
): Promise<StepResult[]> {
  const content = readFileSync(filePath, 'utf-8')
  const def = parseWorkflowYaml(content)

  const vars = resolveVariables(def.variables, variables)
  const registry = getRegistry()
  const results: StepResult[] = []

  log.info(`Running workflow: ${def.name} (${def.steps.length} steps)`)

  for (let i = 0; i < def.steps.length; i++) {
    const step = def.steps[i]
    const stepNum = i + 1
    const total = def.steps.length

    log.info(`[${stepNum}/${total}] ${step.name}...`)

    const cmd = registry.get(step.command)
    if (!cmd) {
      log.warn(`[${stepNum}/${total}] command not found: ${step.command}`)
      results.push({
        name: step.name,
        command: step.command,
        status: 'skipped',
        findings: 0,
        duration_ms: 0,
        error: 'Command not found',
      })
      continue
    }

    const start = Date.now()
    const args = interpolateArgs(step.args ?? {}, vars)

    try {
      const ctx = { auth: null, args, log }
      const result = cmd.func ? await cmd.func(ctx, args) : []
      const findings = Array.isArray(result) ? result.length : 1
      const duration = Date.now() - start

      log.info(`[${stepNum}/${total}] ${step.name} (${(duration / 1000).toFixed(1)}s) — ${findings} finding(s)`)
      results.push({
        name: step.name,
        command: step.command,
        status: 'completed',
        findings,
        duration_ms: duration,
        data: result,
      })
    } catch (err) {
      const duration = Date.now() - start
      const errorMsg = (err as Error).message
      log.warn(`[${stepNum}/${total}] ${step.name} — ${errorMsg}`)

      results.push({
        name: step.name,
        command: step.command,
        status: 'failed',
        findings: 0,
        duration_ms: duration,
        error: errorMsg,
      })

      if (step.on_error === 'stop') {
        log.error('Workflow stopped due to step failure (on_error: stop)')
        break
      }
    }
  }

  // Summary
  const completed = results.filter(r => r.status === 'completed').length
  const totalFindings = results.reduce((sum, r) => sum + r.findings, 0)
  const totalDuration = results.reduce((sum, r) => sum + r.duration_ms, 0)

  log.info(`\nWorkflow complete: ${completed}/${results.length} steps, ${totalFindings} findings, ${(totalDuration / 1000).toFixed(1)}s`)

  return results
}
