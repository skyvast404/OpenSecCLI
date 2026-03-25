#!/usr/bin/env node

/**
 * Main entry point for OpenSecCLI.
 * Mirrors OpenCLI's main.ts — discovery → CLI setup → execute.
 */

import { createCli, registerAdapterCommands } from './cli.js'
import { discoverAdapters } from './discovery.js'
import { fireHook } from './hooks.js'

const VERSION = '0.1.0'

async function main(): Promise<void> {
  // 1. Discover all adapters (manifest fast path or filesystem scan)
  await discoverAdapters()

  // 2. Fire startup hook
  await fireHook('onStartup', { command: '', args: {} })

  // 3. Create CLI and register adapter commands
  const program = createCli(VERSION)
  registerAdapterCommands(program)

  // 4. Parse and execute
  await program.parseAsync(process.argv)
}

main().catch((error) => {
  process.stderr.write(`Fatal: ${error.message}\n`)
  process.exit(1)
})
