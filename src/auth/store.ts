/**
 * Credential store for OpenSecCLI.
 * Replaces OpenCLI's browser session management — file-based auth storage.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync, readdirSync } from 'fs'
import { join } from 'path'
import { homedir } from 'os'
import { CONFIG_DIR_NAME } from '../constants.js'
import type { AuthCredentials } from '../types.js'

function getAuthDir(): string {
  const dir = join(homedir(), CONFIG_DIR_NAME, 'auth')
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  return dir
}

function getAuthPath(provider: string): string {
  return join(getAuthDir(), `${provider}.json`)
}

export function loadAuth(provider: string): AuthCredentials | null {
  // 1. Check environment variable first
  const envKey = `OPENSECCLI_${provider.toUpperCase().replace(/[^A-Z0-9]/g, '_')}_API_KEY`
  const envValue = process.env[envKey]
  if (envValue) {
    return { api_key: envValue }
  }

  // 2. Check stored credentials file
  const path = getAuthPath(provider)
  if (!existsSync(path)) return null

  try {
    const content = readFileSync(path, 'utf-8')
    return JSON.parse(content) as AuthCredentials
  } catch {
    return null
  }
}

export function saveAuth(provider: string, credentials: AuthCredentials): void {
  const path = getAuthPath(provider)
  writeFileSync(path, JSON.stringify(credentials, null, 2), { mode: 0o600 })
}

export function removeAuth(provider: string): boolean {
  const path = getAuthPath(provider)
  if (!existsSync(path)) return false

  unlinkSync(path)
  return true
}

export function listAuth(): string[] {
  const dir = getAuthDir()
  if (!existsSync(dir)) return []

  return (readdirSync(dir) as string[])
    .filter(f => f.endsWith('.json'))
    .map(f => f.replace('.json', ''))
}
