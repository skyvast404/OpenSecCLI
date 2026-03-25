/**
 * Pipeline executor for OpenSecCLI.
 * Mirrors OpenCLI's pipeline/executor.ts — sequential step chain with retry.
 */

import { PipelineError } from '../errors.js'
import { log } from '../logger.js'
import type { PipelineStep, AuthCredentials } from '../types.js'
import { executeRequest } from './steps/request.js'
import { executeSelect, executeMap, executeFilter, executeSort, executeLimit } from './steps/transform.js'
import { executeEnrich } from './steps/enrich.js'

export interface PipelineContext {
  args: Record<string, unknown>
  auth: AuthCredentials | null
  debug?: boolean
}

const RETRYABLE_STEPS = new Set(['request'])
const MAX_RETRIES = 2
const RETRY_DELAY_MS = 1000

export async function executePipeline(
  pipeline: PipelineStep[],
  ctx: PipelineContext,
): Promise<unknown> {
  let data: unknown = null
  const stepCtx = { args: ctx.args, auth: (ctx.auth ?? {}) as Record<string, unknown> }
  const total = pipeline.length

  for (let i = 0; i < pipeline.length; i++) {
    const step = pipeline[i]
    const stepName = Object.keys(step)[0]
    const stepParams = step[stepName]

    log.step(i + 1, total, stepName)

    const maxRetries = RETRYABLE_STEPS.has(stepName) ? MAX_RETRIES : 0
    let lastError: Error | undefined

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        data = await executeStep(stepName, stepParams, data, stepCtx)

        if (ctx.debug) {
          log.debug(`Step ${i + 1} (${stepName}) result: ${JSON.stringify(data).slice(0, 200)}`)
        }

        break
      } catch (error) {
        lastError = error as Error

        const isTransient = isTransientError(error as Error)
        if (isTransient && attempt < maxRetries) {
          log.verbose(`Step "${stepName}" failed (attempt ${attempt + 1}/${maxRetries + 1}), retrying...`)
          await sleep(RETRY_DELAY_MS)
          continue
        }

        throw error instanceof PipelineError
          ? error
          : new PipelineError(stepName, (error as Error).message)
      }
    }
  }

  return data
}

async function executeStep(
  name: string,
  params: Record<string, unknown>,
  data: unknown,
  ctx: { args: Record<string, unknown>; auth: Record<string, unknown> },
): Promise<unknown> {
  switch (name) {
    case 'request':
      return executeRequest(params as any, data, ctx)

    case 'select':
      return executeSelect(params as any, data)

    case 'map':
      return executeMap(params as any, data, ctx)

    case 'filter':
      return executeFilter(params as any, data, ctx)

    case 'sort':
      return executeSort(params as any, data)

    case 'limit':
      return executeLimit(params as any, data, ctx)

    case 'enrich':
      return executeEnrich(params as any, data, ctx)

    default:
      throw new PipelineError(name, `Unknown pipeline step: ${name}`)
  }
}

function isTransientError(error: Error): boolean {
  const message = error.message?.toLowerCase() ?? ''
  return (
    message.includes('fetch failed') ||
    message.includes('network') ||
    message.includes('econnreset') ||
    message.includes('econnrefused') ||
    message.includes('timeout') ||
    message.includes('socket hang up')
  )
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}
