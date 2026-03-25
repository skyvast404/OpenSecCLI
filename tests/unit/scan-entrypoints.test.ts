import { describe, it, expect } from 'vitest'
import { findEntryPoints, ROUTE_PATTERNS } from '../../src/adapters/scan/entrypoints.js'

describe('findEntryPoints', () => {
  it('detects Flask routes', () => {
    const code = `
from flask import Flask
app = Flask(__name__)

@app.route('/api/users', methods=['POST'])
def create_user():
    pass
`
    const eps = findEntryPoints('app.py', code, ['python'])
    expect(eps).toHaveLength(1)
    expect(eps[0]).toMatchObject({
      file: 'app.py',
      kind: 'http_route',
      pattern: '/api/users',
      framework: 'flask',
    })
    expect(eps[0].line).toBeGreaterThan(0)
  })

  it('detects FastAPI routes', () => {
    const code = `
from fastapi import FastAPI
app = FastAPI()

@app.get('/items/{item_id}')
async def read_item(item_id: int):
    return {"item_id": item_id}
`
    const eps = findEntryPoints('main.py', code, ['python'])
    expect(eps).toHaveLength(1)
    expect(eps[0]).toMatchObject({ kind: 'http_route', framework: 'fastapi' })
  })

  it('detects Express routes', () => {
    const code = `
const express = require('express')
const app = express()

app.get('/api/users', (req, res) => {
  res.json([])
})

router.post('/api/items', async (req, res) => {
  res.json({})
})
`
    const eps = findEntryPoints('server.js', code, ['javascript'])
    expect(eps).toHaveLength(2)
    expect(eps[0]).toMatchObject({ kind: 'http_route', framework: 'express' })
  })

  it('detects Django URL patterns', () => {
    const code = `
from django.urls import path
from . import views

urlpatterns = [
    path('api/users/', views.UserListView.as_view()),
    path('api/items/<int:pk>/', views.ItemDetailView.as_view()),
]
`
    const eps = findEntryPoints('urls.py', code, ['python'])
    expect(eps).toHaveLength(2)
    expect(eps[0]).toMatchObject({ kind: 'http_route', framework: 'django' })
  })

  it('detects Spring controllers', () => {
    const code = `
@RestController
@RequestMapping("/api")
public class UserController {

    @GetMapping("/users")
    public List<User> getUsers() {
        return userService.findAll();
    }

    @PostMapping("/users")
    public User createUser(@RequestBody UserDto dto) {
        return userService.create(dto);
    }
}
`
    const eps = findEntryPoints('UserController.java', code, ['java'])
    expect(eps).toHaveLength(2)
    expect(eps[0]).toMatchObject({ kind: 'http_route', framework: 'spring' })
  })

  it('returns empty for test files', () => {
    const code = `@app.route('/test')\ndef test_view(): pass`
    const eps = findEntryPoints('test_app.py', code, ['python'])
    expect(eps).toHaveLength(0)
  })

  it('returns empty for no matches', () => {
    const eps = findEntryPoints('utils.py', 'def add(a, b): return a + b', ['python'])
    expect(eps).toHaveLength(0)
  })
})
