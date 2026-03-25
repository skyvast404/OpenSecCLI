/**
 * Hash type identifier.
 * Pure TypeScript — no external dependencies.
 * Source: pentest-ctf-crypto
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'

interface HashPattern {
  name: string
  regex: RegExp
  hashcat_mode: number
  john_format: string
}

const HASH_PATTERNS: HashPattern[] = [
  { name: 'MD5', regex: /^[a-f0-9]{32}$/i, hashcat_mode: 0, john_format: 'raw-md5' },
  { name: 'SHA-1', regex: /^[a-f0-9]{40}$/i, hashcat_mode: 100, john_format: 'raw-sha1' },
  { name: 'SHA-256', regex: /^[a-f0-9]{64}$/i, hashcat_mode: 1400, john_format: 'raw-sha256' },
  { name: 'SHA-512', regex: /^[a-f0-9]{128}$/i, hashcat_mode: 1700, john_format: 'raw-sha512' },
  { name: 'NTLM', regex: /^[a-f0-9]{32}$/i, hashcat_mode: 1000, john_format: 'nt' },
  { name: 'bcrypt', regex: /^\$2[aby]?\$\d{2}\$.{53}$/, hashcat_mode: 3200, john_format: 'bcrypt' },
  { name: 'SHA-512 Crypt', regex: /^\$6\$.{8,16}\$[a-zA-Z0-9/.]{86}$/, hashcat_mode: 1800, john_format: 'sha512crypt' },
  { name: 'SHA-256 Crypt', regex: /^\$5\$.{8,16}\$[a-zA-Z0-9/.]{43}$/, hashcat_mode: 7400, john_format: 'sha256crypt' },
  { name: 'MD5 Crypt', regex: /^\$1\$.{8}\$[a-zA-Z0-9/.]{22}$/, hashcat_mode: 500, john_format: 'md5crypt' },
  { name: 'MySQL 4.1+', regex: /^\*[A-F0-9]{40}$/i, hashcat_mode: 300, john_format: 'mysql-sha1' },
  { name: 'CRC32', regex: /^[a-f0-9]{8}$/i, hashcat_mode: -1, john_format: '' },
  { name: 'Base64', regex: /^[A-Za-z0-9+/]+=*$/, hashcat_mode: -1, john_format: '' },
]

export function identifyHash(hash: string): Record<string, unknown>[] {
  const trimmed = hash.trim()
  const matches: Record<string, unknown>[] = []

  for (const pattern of HASH_PATTERNS) {
    if (pattern.regex.test(trimmed)) {
      matches.push({
        hash_preview: trimmed.length > 40 ? trimmed.slice(0, 40) + '...' : trimmed,
        algorithm: pattern.name,
        hashcat_mode: pattern.hashcat_mode >= 0 ? pattern.hashcat_mode : 'N/A',
        john_format: pattern.john_format || 'N/A',
        length: trimmed.length,
      })
    }
  }

  if (matches.length === 0) {
    matches.push({
      hash_preview: trimmed.slice(0, 40),
      algorithm: 'unknown',
      hashcat_mode: 'N/A',
      john_format: 'N/A',
      length: trimmed.length,
    })
  }

  return matches
}

cli({
  provider: 'crypto',
  name: 'hash-id',
  description: 'Identify hash type and suggest hashcat/john formats',
  strategy: Strategy.FREE,
  args: {
    hash: { type: 'string', required: true, help: 'Hash string to identify' },
  },
  columns: ['algorithm', 'hashcat_mode', 'john_format', 'length', 'hash_preview'],

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const hash = args.hash as string
    return identifyHash(hash)
  },
})
