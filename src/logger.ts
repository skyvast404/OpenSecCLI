/**
 * Unified logging for OpenSecCLI.
 * Mirrors OpenCLI's logger.ts — all output to stderr, chalk styling.
 */

import chalk from 'chalk'
import type { Logger } from './types.js'

const isVerbose = () =>
  process.env['OPENSECCLI_VERBOSE'] === '1' || process.argv.includes('-v') || process.argv.includes('--verbose')

const isDebug = () =>
  (process.env['DEBUG'] ?? '').includes('opensec')

function write(msg: string): void {
  process.stderr.write(msg + '\n')
}

export const log: Logger = {
  info(msg: string) {
    write(chalk.blue('ℹ') + ' ' + msg)
  },

  warn(msg: string) {
    write(chalk.yellow('⚠') + ' ' + chalk.yellow(msg))
  },

  error(msg: string) {
    write(chalk.red('✖') + ' ' + chalk.red(msg))
  },

  verbose(msg: string) {
    if (isVerbose()) {
      write(chalk.gray('  ' + msg))
    }
  },

  debug(msg: string) {
    if (isDebug()) {
      write(chalk.gray(`[DEBUG] ${msg}`))
    }
  },

  step(index: number, total: number, name: string) {
    if (isVerbose()) {
      write(chalk.cyan(`  [${index}/${total}]`) + ` ${name}`)
    }
  },
}
