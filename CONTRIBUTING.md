# Contributing to OpenSecCLI

Thank you for your interest in contributing! The most impactful way to contribute is **adding a new security API adapter** — and it only takes one YAML file.

## Adding a YAML Adapter (10 minutes)

### Step 1: Create the file

```bash
mkdir -p src/adapters/<provider>
touch src/adapters/<provider>/<action>.yaml
```

Naming conventions:
- `provider` = API provider name, lowercase (e.g., `virustotal`, `abuseipdb`, `abuse.ch`)
- `action` = what the command does, lowercase with hyphens (e.g., `ip-check`, `hash-lookup`)

### Step 2: Write the YAML

```yaml
provider: <provider>
name: <action>
description: One-line description of what this does
strategy: FREE | API_KEY          # FREE = no auth needed
auth: <provider>                  # omit if strategy is FREE

args:
  <arg_name>:
    type: string | number | boolean
    required: true | false
    default: <value>              # optional
    choices: [a, b, c]            # optional
    help: Description for --help

pipeline:
  # 1. Make the API request
  - request:
      url: https://api.example.com/endpoint
      method: GET | POST
      headers:
        Authorization: "Bearer {{ auth.api_key }}"    # if API_KEY strategy
      params:                      # URL query parameters (GET)
        key: "{{ args.arg_name }}"
      body:                        # request body (POST)
        key: "{{ args.arg_name }}"

  # 2. Extract data from response
  - select:
      path: data.results           # dot-notation path to the array/object

  # 3. Map fields to output columns
  - map:
      template:
        column_a: "{{ item.field_a }}"
        column_b: "{{ item.field_b }}"
        column_c: "{{ item.nested.field }}"

  # Optional: filter, sort, limit
  - filter:
      condition: "{{ item.score > 0 }}"
  - sort:
      key: score
      reverse: true
  - limit:
      count: "{{ args.limit }}"

columns: [column_a, column_b, column_c]
```

### Step 3: Test locally

```bash
# Run in development mode
npm run dev -- <provider> <action> [args]

# Run tests
npm test
```

### Step 4: Add a test

Create `tests/adapter/<provider>.test.ts`:

```typescript
import { describe, it, expect } from 'vitest'

describe('<provider>/<action>', () => {
  it('should return expected fields', async () => {
    // Mock the API response
    const mockResponse = { /* paste a real API response sample here */ }

    // Verify the adapter transforms it correctly
    const result = await executeAdapter('<provider>/<action>', {
      /* args */
    }, { mockResponse })

    expect(result).toHaveLength(/* expected */)
    expect(result[0]).toHaveProperty('column_a')
  })
})
```

### Step 5: Submit PR

```bash
git checkout -b add-<provider>-<action>
git add src/adapters/<provider>/<action>.yaml tests/adapter/<provider>.test.ts
git commit -m "feat: add <provider> <action> adapter"
git push origin add-<provider>-<action>
```

## Template Expression Reference

Use `{{ }}` in YAML to reference dynamic values:

```
{{ args.ip }}                            # CLI argument
{{ auth.api_key }}                       # Stored credential
{{ item.field }}                         # Current item in array
{{ item.score > 80 ? 'HIGH' : 'LOW' }}  # Ternary expression
{{ item.tags | join(', ') }}             # Array to string
{{ item.name | upper }}                  # Uppercase
{{ item.url | urlencode }}               # URL encode
{{ value || 'N/A' }}                     # Default fallback
{{ index + 1 }}                          # 1-based index
```

## Writing a TypeScript Adapter

For complex logic (pagination, subprocess calls, multi-step workflows), use TypeScript:

```typescript
// src/adapters/example/complex-action.ts
import { cli, Strategy } from 'openseccli/registry'

cli({
  provider: 'example',
  name: 'complex-action',
  description: 'Does something complex',
  strategy: Strategy.API_KEY,
  auth: 'example',
  args: {
    target: { type: 'string', required: true, help: 'Target to analyze' },
    limit: { type: 'number', default: 20, help: 'Max results' },
  },
  columns: ['id', 'finding', 'severity', 'detail'],

  async func(ctx, args) {
    // ctx.auth has the resolved credentials
    // ctx.log has the logger

    const results = []
    let page = 1

    // Pagination loop
    while (results.length < args.limit) {
      const response = await fetch(
        `https://api.example.com/scan?target=${args.target}&page=${page}`,
        { headers: { 'Authorization': `Bearer ${ctx.auth.api_key}` } }
      )
      const data = await response.json()
      if (!data.results?.length) break

      results.push(...data.results.map(item => ({
        id: item.id,
        finding: item.title,
        severity: item.severity,
        detail: item.description,
      })))
      page++
    }

    return results.slice(0, args.limit)
  },
})
```

## Project Structure

```
src/
├── adapters/          ← YOU CONTRIBUTE HERE
│   ├── abuse.ch/      # Free threat intelligence
│   ├── nvd/           # CVE database
│   ├── abuseipdb/     # IP reputation
│   ├── virustotal/    # File/URL/IP analysis
│   └── ...
├── pipeline/          # Execution engine (steps)
├── auth/              # Credential management
├── cli.ts             # Command definitions
├── registry.ts        # Command registry
├── execution.ts       # Execution lifecycle
├── output.ts          # Output formatting
└── errors.ts          # Error types
```

## API Sources to Consider

Looking for an adapter to build? Here are free APIs that don't have adapters yet:

- [ ] urlscan.io — URL scanning and analysis
- [ ] Censys — Internet-wide scan data
- [ ] SecurityTrails — DNS and domain intel
- [ ] Pulsedive — Threat intel enrichment
- [ ] PhishTank — Phishing URL database
- [ ] Hybrid Analysis — Malware sandbox
- [ ] AlienVault OTX — Threat intelligence
- [ ] EmailRep.io — Email reputation
- [ ] IBM X-Force Exchange — Threat intel
- [ ] Hunter.io — Email finder
- [ ] CIRCL hashlookup — Hash database
- [ ] MaxMind GeoLite2 — IP geolocation
- [ ] Tor Exit Node List — Tor detection

Check [Issues](../../issues) for adapter requests from users.

## Code Style

- TypeScript strict mode
- ES modules (`import`/`export`)
- Immutable patterns (no mutation)
- Functions < 50 lines, files < 800 lines
- No `console.log` — use the `log` object

## Commit Messages

```
feat: add <provider> <action> adapter
fix: handle empty response in <provider>
refactor: extract shared validation logic
docs: add <provider> adapter documentation
test: add tests for <provider>
```
