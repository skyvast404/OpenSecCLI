import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  interpolate,
  parseWorkflowYaml,
  resolveVariables,
} from '../../src/commands/workflow.js'

describe('interpolate', () => {
  it('replaces a single variable', () => {
    expect(interpolate('hello {{ name }}', { name: 'world' })).toBe('hello world')
  })

  it('replaces multiple variables', () => {
    const result = interpolate('https://{{ domain }}/{{ path }}', {
      domain: 'example.com',
      path: 'api',
    })
    expect(result).toBe('https://example.com/api')
  })

  it('handles variables without spaces around braces', () => {
    expect(interpolate('{{target}}', { target: 'foo' })).toBe('foo')
  })

  it('returns empty string for missing variables', () => {
    expect(interpolate('{{ missing }}', {})).toBe('')
  })

  it('leaves non-variable text untouched', () => {
    expect(interpolate('no templates here', { x: 'y' })).toBe('no templates here')
  })

  it('replaces the same variable used multiple times', () => {
    const result = interpolate('{{ a }}-{{ a }}', { a: 'x' })
    expect(result).toBe('x-x')
  })
})

describe('parseWorkflowYaml', () => {
  it('parses a valid workflow YAML string', () => {
    const yaml = `
name: test-workflow
description: A test
steps:
  - name: Step One
    command: vuln/header-audit
    args:
      url: "https://example.com"
`
    const def = parseWorkflowYaml(yaml)
    expect(def.name).toBe('test-workflow')
    expect(def.description).toBe('A test')
    expect(def.steps).toHaveLength(1)
    expect(def.steps[0].command).toBe('vuln/header-audit')
  })

  it('throws on missing name', () => {
    const yaml = `
steps:
  - name: Step One
    command: foo/bar
    args: {}
`
    expect(() => parseWorkflowYaml(yaml)).toThrow('missing "name" field')
  })

  it('throws on empty steps', () => {
    const yaml = `
name: bad
steps: []
`
    expect(() => parseWorkflowYaml(yaml)).toThrow('"steps" must be a non-empty array')
  })

  it('throws on non-object YAML', () => {
    expect(() => parseWorkflowYaml('just a string')).toThrow('expected an object')
  })

  it('parses variables section', () => {
    const yaml = `
name: vars-test
variables:
  domain: "{{ target }}"
  url: "https://{{ target }}"
steps:
  - name: Check
    command: vuln/cors-check
    args:
      url: "{{ url }}"
`
    const def = parseWorkflowYaml(yaml)
    expect(def.variables).toBeDefined()
    expect(def.variables!['domain']).toBe('{{ target }}')
    expect(def.variables!['url']).toBe('https://{{ target }}')
  })

  it('parses the example web-audit.yaml file', () => {
    const filePath = join(__dirname, '../../workflows/web-audit.yaml')
    const content = readFileSync(filePath, 'utf-8')
    const def = parseWorkflowYaml(content)
    expect(def.name).toBe('web-audit')
    expect(def.steps.length).toBeGreaterThanOrEqual(3)
  })
})

describe('resolveVariables', () => {
  it('interpolates workflow variables with user variables', () => {
    const result = resolveVariables(
      { domain: '{{ target }}', url: 'https://{{ target }}' },
      { target: 'example.com' },
    )
    expect(result.domain).toBe('example.com')
    expect(result.url).toBe('https://example.com')
    expect(result.target).toBe('example.com')
  })

  it('lets user variables override workflow variables', () => {
    const result = resolveVariables(
      { domain: 'from-workflow' },
      { domain: 'from-user' },
    )
    expect(result.domain).toBe('from-user')
  })

  it('handles undefined workflow variables', () => {
    const result = resolveVariables(undefined, { target: 'x' })
    expect(result).toEqual({ target: 'x' })
  })

  it('handles empty user variables', () => {
    const result = resolveVariables({ foo: 'bar' }, {})
    expect(result.foo).toBe('bar')
  })
})
