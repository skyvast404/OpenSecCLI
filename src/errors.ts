/**
 * Error type hierarchy for OpenSecCLI.
 * Mirrors OpenCLI's errors.ts — CliError base + semantic subclasses.
 */

export class CliError extends Error {
  constructor(
    public code: string,
    message: string,
    public hint?: string,
  ) {
    super(message)
    this.name = 'CliError'
  }
}

export class AuthRequiredError extends CliError {
  constructor(provider: string) {
    super(
      'AUTH_REQUIRED',
      `${provider} requires an API key`,
      `Run: opensec auth add ${provider} --api-key`,
    )
  }
}

export class AuthExpiredError extends CliError {
  constructor(provider: string) {
    super(
      'AUTH_EXPIRED',
      `${provider} API key is invalid or expired`,
      `Run: opensec auth test ${provider} to check, or opensec auth add ${provider} --api-key to reconfigure`,
    )
  }
}

export class RateLimitError extends CliError {
  constructor(provider: string, retryAfter?: number) {
    super(
      'RATE_LIMITED',
      `${provider} API rate limit exceeded${retryAfter ? ` (retry after ${retryAfter}s)` : ''}`,
      `Use --delay to slow down requests, or upgrade your API plan`,
    )
  }
}

export class ToolNotFoundError extends CliError {
  constructor(tool: string, installHint: string) {
    super(
      'TOOL_NOT_FOUND',
      `Command not found: ${tool}`,
      `Install: ${installHint}`,
    )
  }
}

export class CommandNotFoundError extends CliError {
  constructor(commandId: string) {
    super(
      'COMMAND_NOT_FOUND',
      `Unknown command: ${commandId}`,
      `Run: opensec list to see all available commands`,
    )
  }
}

export class TimeoutError extends CliError {
  constructor(seconds: number) {
    super(
      'TIMEOUT',
      `Operation timed out (${seconds}s)`,
      `Set OPENSECCLI_TIMEOUT to increase the timeout`,
    )
  }
}

export class EmptyResultError extends CliError {
  constructor(message: string) {
    super('NO_DATA', message)
  }
}

export class ArgumentError extends CliError {
  constructor(message: string) {
    super('INVALID_ARGUMENT', message)
  }
}

export class PipelineError extends CliError {
  constructor(step: string, message: string) {
    super(
      'PIPELINE_ERROR',
      `Pipeline step "${step}" failed: ${message}`,
    )
  }
}

export const ERROR_ICONS: Record<string, string> = {
  AUTH_REQUIRED: '🔒',
  AUTH_EXPIRED: '🔑',
  RATE_LIMITED: '⏳',
  TOOL_NOT_FOUND: '🔧',
  COMMAND_NOT_FOUND: '❓',
  TIMEOUT: '⏱️',
  NO_DATA: '📭',
  INVALID_ARGUMENT: '❌',
  PIPELINE_ERROR: '💥',
}
