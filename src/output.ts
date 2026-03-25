/**
 * Output formatting for OpenSecCLI.
 * Mirrors OpenCLI's output.ts — table/json/csv/yaml/markdown, RenderOptions.
 */

import Table from 'cli-table3'
import chalk from 'chalk'
import YAML from 'js-yaml'
import type { RenderOptions } from './types.js'

export function render(data: unknown, options: RenderOptions = {}): void {
  const format = options.format ?? (process.stdout.isTTY ? 'table' : 'json')
  const rows = normalizeData(data)
  const output = formatters[format](rows, options)
  process.stdout.write(output + '\n')
}

function normalizeData(data: unknown): Record<string, unknown>[] {
  if (Array.isArray(data)) return data.map(normalizeRow)
  if (data && typeof data === 'object') return [normalizeRow(data)]
  return []
}

function normalizeRow(row: unknown): Record<string, unknown> {
  if (!row || typeof row !== 'object') return {}
  const result: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(row as Record<string, unknown>)) {
    result[key] = value ?? ''
  }
  return result
}

function extractColumns(rows: Record<string, unknown>[], options: RenderOptions): string[] {
  if (options.columns?.length) return options.columns
  if (rows.length === 0) return []
  const keys = new Set<string>()
  for (const row of rows) {
    for (const key of Object.keys(row)) {
      keys.add(key)
    }
  }
  return [...keys]
}

function renderTable(rows: Record<string, unknown>[], options: RenderOptions): string {
  const columns = extractColumns(rows, options)
  if (columns.length === 0) return 'No data.'

  const table = new Table({
    head: columns.map(c => chalk.bold(c)),
    wordWrap: true,
    style: { head: [], border: [] },
  })

  for (const row of rows) {
    table.push(columns.map(col => String(row[col] ?? '')))
  }

  const parts = [table.toString()]

  // Footer with metadata
  const footerParts: string[] = []
  footerParts.push(`${rows.length} ${rows.length === 1 ? 'item' : 'items'}`)
  if (options.elapsed !== undefined) {
    footerParts.push(`${(options.elapsed / 1000).toFixed(1)}s`)
  }
  if (options.source) {
    footerParts.push(`from ${options.source}`)
  }
  if (options.footerExtra) {
    footerParts.push(options.footerExtra)
  }
  parts.push(chalk.gray(footerParts.join(' · ')))

  return parts.join('\n')
}

function renderJson(rows: Record<string, unknown>[]): string {
  return JSON.stringify(rows, null, 2)
}

function renderCsv(rows: Record<string, unknown>[], options: RenderOptions): string {
  const columns = extractColumns(rows, options)
  if (columns.length === 0) return ''

  const lines = [columns.join(',')]
  for (const row of rows) {
    const values = columns.map(col => {
      const val = String(row[col] ?? '')
      if (val.includes(',') || val.includes('"') || val.includes('\n')) {
        return `"${val.replace(/"/g, '""')}"`
      }
      return val
    })
    lines.push(values.join(','))
  }
  return lines.join('\n')
}

function renderYaml(rows: Record<string, unknown>[]): string {
  return YAML.dump(rows, { lineWidth: 120 }).trimEnd()
}

function renderMarkdown(rows: Record<string, unknown>[], options: RenderOptions): string {
  const columns = extractColumns(rows, options)
  if (columns.length === 0) return ''

  const lines = [
    '| ' + columns.join(' | ') + ' |',
    '| ' + columns.map(() => '---').join(' | ') + ' |',
  ]
  for (const row of rows) {
    const values = columns.map(col => String(row[col] ?? ''))
    lines.push('| ' + values.join(' | ') + ' |')
  }
  return lines.join('\n')
}

const formatters: Record<string, (rows: Record<string, unknown>[], options: RenderOptions) => string> = {
  table: renderTable,
  json: renderJson,
  csv: renderCsv,
  yaml: renderYaml,
  markdown: renderMarkdown,
}
