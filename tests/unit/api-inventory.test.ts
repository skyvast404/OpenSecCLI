import { describe, it, expect } from 'vitest'
import { parseOpenApiSpec, extractApiUrlsFromJs } from '../../src/adapters/vuln/api-inventory.js'

describe('api-inventory', () => {
  describe('parseOpenApiSpec', () => {
    it('extracts endpoints from a valid OpenAPI 3 spec', () => {
      const spec = JSON.stringify({
        openapi: '3.0.0',
        info: { title: 'Test API', version: '1.0.0' },
        paths: {
          '/api/users': {
            get: {
              summary: 'List users',
              parameters: [
                { name: 'limit', in: 'query', required: false },
                { name: 'offset', in: 'query', required: false },
              ],
            },
            post: {
              summary: 'Create user',
              security: [{ bearerAuth: [] }],
              parameters: [
                { name: 'body', in: 'body', required: true },
              ],
            },
          },
          '/api/users/{id}': {
            get: {
              summary: 'Get user by ID',
              security: [{ bearerAuth: [] }],
              parameters: [
                { name: 'id', in: 'path', required: true },
              ],
            },
            delete: {
              summary: 'Delete user',
              security: [{ bearerAuth: [] }],
              parameters: [
                { name: 'id', in: 'path', required: true },
              ],
            },
          },
        },
      })

      const endpoints = parseOpenApiSpec(spec)
      expect(endpoints).toHaveLength(4)

      const getUsers = endpoints.find(e => e.method === 'GET' && e.path === '/api/users')
      expect(getUsers).toBeDefined()
      expect(getUsers!.description).toBe('List users')
      expect(getUsers!.auth_required).toBe(false)
      expect(getUsers!.parameters).toContain('limit')

      const postUsers = endpoints.find(e => e.method === 'POST' && e.path === '/api/users')
      expect(postUsers).toBeDefined()
      expect(postUsers!.auth_required).toBe(true)

      const deleteUser = endpoints.find(e => e.method === 'DELETE')
      expect(deleteUser).toBeDefined()
      expect(deleteUser!.path).toBe('/api/users/{id}')
    })

    it('handles Swagger 2.0 spec', () => {
      const spec = JSON.stringify({
        swagger: '2.0',
        info: { title: 'Legacy API', version: '1.0' },
        paths: {
          '/api/items': {
            get: {
              summary: 'List items',
            },
          },
        },
      })

      const endpoints = parseOpenApiSpec(spec)
      expect(endpoints).toHaveLength(1)
      expect(endpoints[0].method).toBe('GET')
      expect(endpoints[0].path).toBe('/api/items')
    })

    it('returns empty for spec without paths', () => {
      const spec = JSON.stringify({
        openapi: '3.0.0',
        info: { title: 'Empty', version: '1.0' },
      })

      const endpoints = parseOpenApiSpec(spec)
      expect(endpoints).toHaveLength(0)
    })

    it('throws for invalid JSON', () => {
      expect(() => parseOpenApiSpec('not json at all')).toThrow()
    })

    it('skips non-HTTP-method keys in path items', () => {
      const spec = JSON.stringify({
        openapi: '3.0.0',
        paths: {
          '/api/test': {
            get: { summary: 'Test' },
            parameters: [{ name: 'shared', in: 'query' }], // shared params, not a method
            summary: 'Path-level summary', // not a method
          },
        },
      })

      const endpoints = parseOpenApiSpec(spec)
      expect(endpoints).toHaveLength(1)
      expect(endpoints[0].method).toBe('GET')
    })

    it('marks endpoints with empty security array as not requiring auth', () => {
      const spec = JSON.stringify({
        openapi: '3.0.0',
        paths: {
          '/api/public': {
            get: {
              summary: 'Public endpoint',
              security: [],
            },
          },
        },
      })

      const endpoints = parseOpenApiSpec(spec)
      expect(endpoints[0].auth_required).toBe(false)
    })
  })

  describe('extractApiUrlsFromJs', () => {
    it('extracts API paths from fetch calls', () => {
      const js = `
        const response = await fetch("/api/v1/users")
        const data = await fetch("/api/v2/products")
      `
      const endpoints = extractApiUrlsFromJs(js)
      expect(endpoints.length).toBeGreaterThanOrEqual(2)
      const paths = endpoints.map(e => e.path)
      expect(paths).toContain('/api/v1/users')
      expect(paths).toContain('/api/v2/products')
    })

    it('extracts API paths from string literals', () => {
      const js = `
        const baseUrl = "/api/v1"
        const endpoint = "/api/v1/orders/{orderId}"
      `
      const endpoints = extractApiUrlsFromJs(js)
      expect(endpoints.length).toBeGreaterThanOrEqual(1)
    })

    it('extracts path parameters', () => {
      const js = `fetch("/api/v1/users/{userId}/posts/{postId}")`
      const endpoints = extractApiUrlsFromJs(js)
      const match = endpoints.find(e => e.path.includes('users'))
      expect(match).toBeDefined()
      expect(match!.parameters).toContain('userId')
      expect(match!.parameters).toContain('postId')
    })

    it('does not extract non-API paths', () => {
      const js = `
        import "./styles.css"
        const img = "/images/logo.png"
        const font = "/fonts/main.woff2"
      `
      const endpoints = extractApiUrlsFromJs(js)
      expect(endpoints).toHaveLength(0)
    })

    it('deduplicates endpoints by method and path', () => {
      const js = `
        fetch("/api/v1/data")
        fetch("/api/v1/data")
        fetch("/api/v1/data")
      `
      const endpoints = extractApiUrlsFromJs(js)
      const dataPaths = endpoints.filter(e => e.path === '/api/v1/data')
      expect(dataPaths).toHaveLength(1)
    })

    it('infers POST method for creation paths', () => {
      const js = `fetch("/api/v1/users/create")`
      const endpoints = extractApiUrlsFromJs(js)
      const createEndpoint = endpoints.find(e => e.path.includes('create'))
      expect(createEndpoint).toBeDefined()
      expect(createEndpoint!.method).toBe('POST')
    })

    it('extracts from axios patterns', () => {
      const js = `axios.get("/api/v1/items")`
      const endpoints = extractApiUrlsFromJs(js)
      expect(endpoints.length).toBeGreaterThanOrEqual(1)
      expect(endpoints[0].path).toBe('/api/v1/items')
    })
  })
})
