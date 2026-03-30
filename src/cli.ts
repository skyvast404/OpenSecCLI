/**
 * CLI command definitions for OpenSecCLI.
 * Mirrors OpenCLI's cli.ts — Commander.js with dynamic adapter registration.
 */

import { Command } from 'commander'
import chalk from 'chalk'
import { getRegistry } from './registry.js'
import { executeCommand } from './execution.js'
import { listAuth, saveAuth, removeAuth, loadAuth } from './auth/index.js'
import { render } from './output.js'
import { CliError, ERROR_ICONS } from './errors.js'
import { EXIT_CODES, CONFIG_DIR_NAME } from './constants.js'
import { createAdapter } from './commands/create.js'
import { runAutopilot } from './commands/autopilot.js'
import { SECURITY_DOMAINS } from './constants/domains.js'
import { checkToolInstalled, getToolVersion } from './adapters/_utils/tool-runner.js'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import type { CliCommand, Arg } from './types.js'

export function createCli(version: string): Command {
  const program = new Command()
    .name('opensec')
    .description('The open-source security CLI hub — query, enrich, automate.')
    .version(version)
    .option('-f, --format <type>', 'output format: table, json, csv, yaml, markdown', 'table')
    .option('-o, --output <file>', 'write output to file')
    .option('-v, --verbose', 'verbose output')
    .option('--debug', 'debug mode')
    .option('-q, --quiet', 'suppress status messages')
    .option('--no-color', 'disable colors')
    .option('--json', 'shorthand for --format json')
    .option('--silent', 'alias for --quiet')
    .option('--timeout <seconds>', 'command timeout in seconds')

  // Built-in: list
  program
    .command('list')
    .description('List all available commands')
    .option('--domain <domain>', 'filter by domain (e.g., recon, threat-intel, vuln-scan)')
    .action((opts: { domain?: string }) => {
      const registry = getRegistry()
      const domainFilter = opts.domain?.toLowerCase()

      const commands = [...registry.values()]
        .filter(cmd => !domainFilter || cmd.domain === domainFilter)
        .map(cmd => ({
          command: `opensec ${cmd.provider} ${cmd.name}`,
          domain: cmd.domain ?? '-',
          description: cmd.description,
          strategy: cmd.strategy,
          auth: cmd.auth ?? (cmd.strategy === 'FREE' ? '-' : cmd.provider),
        }))
        .sort((a, b) => a.command.localeCompare(b.command))

      const format = program.opts().json ? 'json' : (program.opts().format ?? 'table')
      render(commands, {
        format: format as any,
        columns: ['command', 'domain', 'description', 'strategy', 'auth'],
      })
    })

  // Built-in: auth
  const authCmd = program
    .command('auth')
    .description('Manage API credentials')

  authCmd
    .command('add <provider>')
    .description('Add API key for a provider')
    .option('--api-key', 'set API key (will prompt)')
    .action(async (provider: string) => {
      const readline = await import('readline')
      const rl = readline.createInterface({ input: process.stdin, output: process.stderr })

      const apiKey = await new Promise<string>((resolve) => {
        rl.question(`Enter API key for ${provider}: `, (answer) => {
          rl.close()
          resolve(answer.trim())
        })
      })

      if (!apiKey) {
        process.stderr.write(chalk.red('No API key provided.\n'))
        process.exit(EXIT_CODES.BAD_ARGUMENT)
      }

      saveAuth(provider, { api_key: apiKey })
      process.stderr.write(chalk.green(`✓ API key saved for ${provider}\n`))
    })

  authCmd
    .command('list')
    .description('List configured providers')
    .action(() => {
      const providers = listAuth()
      if (providers.length === 0) {
        process.stderr.write('No credentials configured. Run: opensec auth add <provider> --api-key\n')
        return
      }
      for (const p of providers) {
        process.stdout.write(p + '\n')
      }
    })

  authCmd
    .command('remove <provider>')
    .description('Remove credentials for a provider')
    .action((provider: string) => {
      const removed = removeAuth(provider)
      if (removed) {
        process.stderr.write(chalk.green(`✓ Credentials removed for ${provider}\n`))
      } else {
        process.stderr.write(chalk.yellow(`No credentials found for ${provider}\n`))
      }
    })

  authCmd
    .command('test <provider>')
    .description('Test API key connectivity for a provider')
    .action(async (provider: string) => {
      const creds = loadAuth(provider)
      if (!creds?.api_key) {
        process.stderr.write(chalk.red(`No API key configured for ${provider}\n`))
        process.stderr.write(chalk.gray(`Run: opensec auth add ${provider} --api-key\n`))
        process.exit(EXIT_CODES.AUTH_FAILED)
      }

      process.stderr.write(`Testing ${provider}...`)
      const { testAuth } = await import('./auth/test.js')
      const result = await testAuth(provider, creds.api_key)

      if (result.ok) {
        process.stderr.write(chalk.green(` ✓ ${result.message}\n`))
      } else {
        process.stderr.write(chalk.red(` ✗ ${result.message}\n`))
        process.exit(EXIT_CODES.AUTH_FAILED)
      }
    })

  // Built-in: create
  const createCmd = program
    .command('create')
    .description('Scaffold new adapters and plugins')

  createCmd
    .command('adapter <name>')
    .description('Create a new adapter scaffold (e.g., opensec create adapter urlscan/submit)')
    .option('-t, --type <type>', 'adapter type: yaml or typescript', 'yaml')
    .option('-p, --provider <name>', 'provider name (default: inferred from name)')
    .option('-s, --strategy <strategy>', 'auth strategy: free or api_key', 'free')
    .option('-d, --domain <domain>', `security domain: ${Object.keys(SECURITY_DOMAINS).join(', ')}`, 'recon')
    .option('-o, --output <dir>', 'output directory', '.')
    .action((name: string, opts: Record<string, string>) => {
      try {
        const filePath = createAdapter(name, {
          type: opts.type as 'yaml' | 'typescript',
          provider: opts.provider,
          strategy: opts.strategy as 'free' | 'api_key',
          domain: opts.domain,
          output: opts.output,
        })
        console.log(`Created adapter: ${filePath}`)
        console.log(`\nNext steps:`)
        console.log(`  1. Edit the file and fill in TODO sections`)
        console.log(`  2. Move to ~/.openseccli/plugins/<name>/adapters/ for auto-loading`)
        console.log(`  3. Or submit a PR to add it to the built-in adapters`)
      } catch (err) {
        console.error(`Error: ${(err as Error).message}`)
        process.exit(1)
      }
    })

  // Built-in: doctor
  program
    .command('doctor')
    .description('Check environment and configuration')
    .action(async () => {
      const registry = getRegistry()
      const authProviders = listAuth()
      const globalOpts = program.opts()
      const format = globalOpts.json ? 'json' : (globalOpts.format ?? 'table')

      process.stderr.write(`\n  ${chalk.bold('OpenSecCLI Doctor')}\n\n`)

      // --- Node.js version check ---
      const nodeVersionRaw = process.version.replace(/^v/, '')
      const nodeMajor = parseInt(nodeVersionRaw.split('.')[0], 10)
      const nodeOk = nodeMajor >= 20
      process.stderr.write(
        nodeOk
          ? chalk.green(`  ✓ Node.js ${process.version} (>=20.0.0)\n`)
          : chalk.red(`  ✗ Node.js ${process.version} — requires >=20.0.0\n`),
      )

      process.stderr.write(`  ✓ opensec version ${version}\n`)
      process.stderr.write(`  ✓ ${registry.size} adapters loaded\n`)

      // --- Plugin directory status ---
      const pluginsDir = join(homedir(), CONFIG_DIR_NAME, 'plugins')
      const pluginsDirExists = existsSync(pluginsDir)
      process.stderr.write(
        pluginsDirExists
          ? chalk.green(`  ✓ Plugin directory exists: ${pluginsDir}\n`)
          : chalk.yellow(`  - Plugin directory not found: ${pluginsDir}\n`),
      )

      // --- External security tools ---
      const toolGroups: Record<string, string[]> = {
        recon: ['subfinder', 'amass', 'httpx', 'whatweb', 'nmap', 'masscan', 'ffuf', 'dirsearch', 'feroxbuster'],
        vuln: ['nuclei', 'nikto', 'testssl.sh', 'testssl'],
        secrets: ['trufflehog', 'gitleaks'],
        scan: ['semgrep'],
        'supply-chain': ['trivy', 'syft', 'cyclonedx-cli'],
        cloud: ['checkov', 'terrascan', 'kube-bench', 'kube-hunter'],
        forensics: ['exiftool', 'binwalk', 'checksec', 'tshark', 'aapt2'],
      }

      process.stderr.write('\n  Checking external tools...\n')

      const toolRows: Array<{ category: string; tool: string; status: string; version: string }> = []

      const checkPromises: Array<Promise<void>> = []
      for (const [category, tools] of Object.entries(toolGroups)) {
        for (const tool of tools) {
          checkPromises.push(
            (async () => {
              const installed = await checkToolInstalled(tool)
              let ver = ''
              if (installed) {
                const v = await getToolVersion(tool)
                ver = v ?? ''
              }
              toolRows.push({
                category,
                tool,
                status: installed ? 'installed' : 'missing',
                version: ver,
              })
            })(),
          )
        }
      }
      await Promise.all(checkPromises)

      // Sort tool rows by category then tool name for stable output
      const categoryOrder = Object.keys(toolGroups)
      toolRows.sort((a, b) => {
        const catDiff = categoryOrder.indexOf(a.category) - categoryOrder.indexOf(b.category)
        if (catDiff !== 0) return catDiff
        return a.tool.localeCompare(b.tool)
      })

      const installedCount = toolRows.filter(r => r.status === 'installed').length
      const totalCount = toolRows.length
      process.stderr.write(`  ${installedCount}/${totalCount} tools installed\n\n`)

      // --- API keys ---
      const apiKeyProviders = ['virustotal', 'abuseipdb', 'greynoise', 'ipinfo', 'shodan']
      const keyRows: Array<{ category: string; tool: string; status: string; version: string }> = []

      for (const provider of apiKeyProviders) {
        const creds = loadAuth(provider)
        const configured = creds?.api_key ? true : false
        keyRows.push({
          category: 'api-keys',
          tool: provider,
          status: configured ? 'configured' : 'missing',
          version: configured ? '***' : '',
        })
      }

      const configuredKeyCount = keyRows.filter(r => r.status === 'configured').length
      process.stderr.write(`  ${configuredKeyCount}/${apiKeyProviders.length} API keys configured`)
      if (authProviders.length > 0) {
        process.stderr.write(` (${authProviders.join(', ')})`)
      }
      process.stderr.write('\n\n')

      // --- Render table ---
      const allRows = [...toolRows, ...keyRows]
      render(allRows, {
        format: format as 'table' | 'json' | 'csv' | 'yaml' | 'markdown',
        columns: ['category', 'tool', 'status', 'version'],
      })
    })

  // Built-in: autopilot
  program
    .command('autopilot <target>')
    .description('Run full security assessment (one command does everything)')
    .option('-d, --depth <depth>', 'Scan depth: quick, standard, deep', 'standard')
    .option('-o, --output <dir>', 'Output directory for report', './opensec-report')
    .action(async (target: string, opts) => {
      await runAutopilot(target, opts)
    })

  return program
}

export function registerAdapterCommands(program: Command): void {
  const registry = getRegistry()

  // Group commands by provider
  const byProvider = new Map<string, CliCommand[]>()
  for (const cmd of registry.values()) {
    const existing = byProvider.get(cmd.provider) ?? []
    existing.push(cmd)
    byProvider.set(cmd.provider, existing)
  }

  for (const [provider, commands] of byProvider) {
    const providerCmd = program
      .command(provider)
      .description(`${provider} commands`)

    for (const cmd of commands) {
      const sub = providerCmd
        .command(cmd.name)
        .description(cmd.description)

      // Register all args as options (--flag style) for consistency.
      // Required args are also accepted as positional for convenience.
      const requiredArgNames: string[] = []
      for (const [argName, argDef] of Object.entries(cmd.args)) {
        registerOption(sub, argName, argDef)
        if (argDef.required) {
          requiredArgNames.push(argName)
        }
      }
      // Allow first required arg as optional positional too
      if (requiredArgNames.length > 0) {
        sub.argument(`[${requiredArgNames[0]}]`, `(positional) ${cmd.args[requiredArgNames[0]].help ?? ''}`)
      }

      // Action
      sub.action(async (...actionArgs: unknown[]) => {
        try {
          const opts = resolveArgs(cmd, sub, actionArgs)
          const globalOpts = program.opts()
          const format = globalOpts.json ? 'json' : globalOpts.format

          if (globalOpts.timeout) {
            process.env['OPENSECCLI_TIMEOUT'] = globalOpts.timeout
          }

          // Stdin pipe: if not TTY and first required arg missing, read lines from stdin
          if (!process.stdin.isTTY && requiredArgNames.length > 0 && !(requiredArgNames[0] in opts)) {
            const lines = await readStdinLines()
            for (const line of lines) {
              const lineOpts = { ...opts, [requiredArgNames[0]]: line }
              await executeCommand(`${provider}/${cmd.name}`, lineOpts, { format })
            }
            return
          }

          await executeCommand(`${provider}/${cmd.name}`, opts, { format })
        } catch (error) {
          handleError(error)
        }
      })
    }
  }
}

function registerOption(command: Command, name: string, def: Arg): void {
  const flag = name.length === 1 ? `-${name}` : `--${name}`
  let desc = def.help ?? ''
  if (def.choices) desc += ` (${def.choices.join('|')})`
  if (def.default !== undefined) desc += ` (default: ${def.default})`

  switch (def.type) {
    case 'boolean':
      command.option(flag, desc)
      break
    case 'number':
      command.option(`${flag} <n>`, desc)
      break
    default:
      command.option(`${flag} <value>`, desc)
  }
}

function resolveArgs(
  cmd: CliCommand,
  sub: Command,
  actionArgs: unknown[],
): Record<string, unknown> {
  const result: Record<string, unknown> = {}
  const opts = sub.opts()
  const requiredArgNames = Object.entries(cmd.args)
    .filter(([, d]) => d.required)
    .map(([name]) => name)

  // Named args from options (--flag style)
  for (const [name] of Object.entries(cmd.args)) {
    if (name in opts) {
      result[name] = opts[name]
    }
  }

  // Positional arg: first non-object, non-Command arg maps to first required arg
  if (requiredArgNames.length > 0) {
    const positional = actionArgs.find(a => typeof a === 'string')
    if (positional && !(requiredArgNames[0] in result)) {
      result[requiredArgNames[0]] = positional
    }
  }

  return result
}

async function readStdinLines(): Promise<string[]> {
  const chunks: Buffer[] = []
  for await (const chunk of process.stdin) {
    chunks.push(chunk)
  }
  return Buffer.concat(chunks)
    .toString('utf-8')
    .split('\n')
    .map(l => l.trim())
    .filter(l => l.length > 0)
}

function handleError(error: unknown): never {
  const isJson = process.argv.includes('--json') ||
    process.argv.includes('--format') && process.argv[process.argv.indexOf('--format') + 1] === 'json'

  if (error instanceof CliError) {
    if (isJson) {
      // Agent-friendly: structured JSON error on stdout
      process.stdout.write(JSON.stringify({
        error: true,
        code: error.code,
        message: error.message,
        hint: error.hint ?? null,
      }) + '\n')
    } else {
      const icon = ERROR_ICONS[error.code] ?? '✖'
      process.stderr.write(`\n${icon} Error: ${error.message}\n`)
      if (error.hint) {
        process.stderr.write(chalk.gray(`  ${error.hint}\n`))
      }
    }
    process.exit(EXIT_CODES.RUNTIME_ERROR)
  }

  if (isJson) {
    process.stdout.write(JSON.stringify({
      error: true,
      code: 'UNEXPECTED_ERROR',
      message: (error as Error).message,
    }) + '\n')
  } else {
    process.stderr.write(`\n✖ Unexpected error: ${(error as Error).message}\n`)
    if (process.argv.includes('--debug')) {
      process.stderr.write((error as Error).stack + '\n')
    }
  }
  process.exit(EXIT_CODES.RUNTIME_ERROR)
}
