/**
 * Runtime configuration for OpenSecCLI.
 * Mirrors OpenCLI's runtime.ts — timeout enforcement, env-based config.
 */

import { TimeoutError } from './errors.js'
import { DEFAULT_COMMAND_TIMEOUT, DEFAULT_ENRICH_TIMEOUT } from './constants.js'

export function getCommandTimeout(): number {
  const env = process.env['OPENSECCLI_TIMEOUT']
  return env ? parseInt(env, 10) : DEFAULT_COMMAND_TIMEOUT
}

export function getEnrichTimeout(): number {
  const env = process.env['OPENSECCLI_ENRICH_TIMEOUT']
  return env ? parseInt(env, 10) : DEFAULT_ENRICH_TIMEOUT
}

export async function runWithTimeout<T>(
  promise: Promise<T>,
  seconds: number,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout>

  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new TimeoutError(seconds)),
      seconds * 1000,
    )
  })

  try {
    return await Promise.race([promise, timeout])
  } finally {
    clearTimeout(timer!)
  }
}
