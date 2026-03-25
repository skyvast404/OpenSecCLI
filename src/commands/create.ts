/**
 * Scaffold command for creating new adapters.
 * opensec create adapter <name> [--type yaml|typescript] [--provider <name>] [--strategy free|api_key]
 */

import { mkdirSync, writeFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { SECURITY_DOMAINS } from '../constants/domains.js'

interface CreateOptions {
  type: 'yaml' | 'typescript'
  provider?: string
  strategy: 'free' | 'api_key'
  domain?: string
  output: string
}

const YAML_TEMPLATE = (provider: string, name: string, strategy: string, domain: string) => `\
provider: ${provider}
name: ${name}
description: "TODO: Describe what this adapter does"
strategy: ${strategy.toUpperCase()}
domain: ${domain}
${strategy === 'api_key' ? `auth: ${provider}\n` : ''}
args:
  target:
    type: string
    required: true
    help: "TODO: Describe this argument"

pipeline:
  - request:
      url: "https://api.example.com/v1/endpoint"
      method: GET
${strategy === 'api_key' ? '      headers:\n        Authorization: "Bearer {{ auth.api_key }}"' : ''}

  - map:
      template:
        id: "{{ item.id }}"
        result: "{{ item.result }}"

columns: [id, result]
`

const TS_TEMPLATE = (provider: string, name: string, strategy: string, domain: string) => `\
/**
 * ${provider}/${name} adapter.
 * TODO: Describe what this adapter does.
 */

import { cli, Strategy } from 'openseccli/registry'
import type { ExecContext, AdapterResult } from 'openseccli/registry'

cli({
  provider: '${provider}',
  name: '${name}',
  description: 'TODO: Describe what this adapter does',
  strategy: Strategy.${strategy.toUpperCase()},
  domain: '${domain}',
  args: {
    target: { type: 'string', required: true, help: 'Target to scan' },
  },
  columns: ['target', 'result'],

  async func(ctx: ExecContext, args: Record<string, unknown>): Promise<AdapterResult> {
    const target = args.target as string
    ctx.log.info(\`Running ${name} on \${target}\`)

    // TODO: Implement your adapter logic here
    return [{ target, result: 'TODO' }]
  },
})
`

export function createAdapter(name: string, opts: CreateOptions): string {
  const parts = name.split('/')
  const provider = opts.provider ?? (parts.length > 1 ? parts[0] : name.split('-')[0])
  const adapterName = parts.length > 1 ? parts[1] : (parts[0].includes('-') ? parts[0].split('-').slice(1).join('-') : parts[0])
  const domain = opts.domain ?? 'recon'

  const dir = join(opts.output, provider)
  mkdirSync(dir, { recursive: true })

  const ext = opts.type === 'yaml' ? 'yaml' : 'ts'
  const filePath = join(dir, `${adapterName}.${ext}`)

  if (existsSync(filePath)) {
    throw new Error(`File already exists: ${filePath}`)
  }

  const content = opts.type === 'yaml'
    ? YAML_TEMPLATE(provider, adapterName, opts.strategy, domain)
    : TS_TEMPLATE(provider, adapterName, opts.strategy, domain)

  writeFileSync(filePath, content)
  return filePath
}
