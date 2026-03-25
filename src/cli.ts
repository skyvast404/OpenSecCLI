/**
 * CLI command definitions for OpenSecCLI.
 * Mirrors OpenCLI's cli.ts — Commander.js with dynamic adapter registration.
 */

import { Command } from 'commander'
import chalk from 'chalk'
import { getRegistry } from './registry.js'
import { executeCommand } from './execution.js'
import { listAuth, saveAuth, removeAuth } from './auth/index.js'
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

      // Register arguments
      for (const [argName, argDef] of Object.entries(cmd.args)) {
        if (argDef.required) {
          sub.argument(`<${argName}>`, argDef.help ?? '')
        } else {
          registerOption(sub, argName, argDef)
        }
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
  const requiredArgs = Object.entries(cmd.args).filter(([, d]) => d.required)
  const opts = sub.opts()

  // Positional required args
  for (let i = 0; i < requiredArgs.length; i++) {
    const [name] = requiredArgs[i]
    if (i < actionArgs.length - 1) {  // last arg is Command options
      result[name] = actionArgs[i]
    }
  }

  // Named optional args from options
  for (const [name] of Object.entries(cmd.args)) {
    if (name in opts) {
      result[name] = opts[name]
    }
  }

  return result
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
