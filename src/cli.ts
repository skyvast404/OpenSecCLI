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
import { EXIT_CODES } from './constants.js'
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
    .action(() => {
      const registry = getRegistry()
      const commands = [...registry.values()]
        .map(cmd => ({
          command: `opensec ${cmd.provider} ${cmd.name}`,
          description: cmd.description,
          strategy: cmd.strategy,
          auth: cmd.auth ?? (cmd.strategy === 'FREE' ? '-' : cmd.provider),
        }))
        .sort((a, b) => a.command.localeCompare(b.command))

      const format = program.opts().json ? 'json' : (program.opts().format ?? 'table')
      render(commands, {
        format: format as any,
        columns: ['command', 'description', 'strategy', 'auth'],
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

  // Built-in: doctor
  program
    .command('doctor')
    .description('Check environment and configuration')
    .action(async () => {
      const registry = getRegistry()
      const authProviders = listAuth()

      process.stderr.write(`\n  ${chalk.bold('OpenSecCLI Doctor')}\n\n`)
      process.stderr.write(`  ✓ opensec version ${version}\n`)
      process.stderr.write(`  ✓ Node.js ${process.version}\n`)
      process.stderr.write(`  ✓ ${registry.size} adapters loaded\n`)
      process.stderr.write(`  ✓ ${authProviders.length} auth providers configured`)
      if (authProviders.length > 0) {
        process.stderr.write(` (${authProviders.join(', ')})`)
      }
      process.stderr.write('\n\n')
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
  if (error instanceof CliError) {
    const icon = ERROR_ICONS[error.code] ?? '✖'
    process.stderr.write(`\n${icon} Error: ${error.message}\n`)
    if (error.hint) {
      process.stderr.write(chalk.gray(`  ${error.hint}\n`))
    }
    process.exit(EXIT_CODES.RUNTIME_ERROR)
  }

  process.stderr.write(`\n✖ Unexpected error: ${(error as Error).message}\n`)
  if (process.argv.includes('--debug')) {
    process.stderr.write((error as Error).stack + '\n')
  }
  process.exit(EXIT_CODES.RUNTIME_ERROR)
}
