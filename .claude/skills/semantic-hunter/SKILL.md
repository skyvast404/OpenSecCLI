---
name: semantic-hunter
description: >
  Trigger when user asks to "find vulnerabilities by tracing data flow",
  "semantic security analysis", "source to sink analysis",
  "cross-file vulnerability hunting", "deep code security scan",
  "find injection paths". Use for LLM-powered cross-file source-to-sink
  vulnerability reasoning that goes beyond static analysis tools.
---

# Semantic Hunter

Cross-file source-to-sink vulnerability analysis using LLM reasoning over
OpenSecCLI-gathered context. Finds taint chains that static tools miss.

## Inputs

| Parameter | Required | Description |
|-----------|----------|-------------|
| `path`    | Yes      | Path to the project root |
| `scope`   | No       | Subdirectory or file glob to narrow the scan |
| `severity_floor` | No | Minimum severity to report (default: `medium`) |

If `path` is not provided, ask for it.

---

## Workflow

### Phase 1 -- Entry Point Discovery

Run in parallel:

```bash
opensec scan entrypoints --path <path> --format json
opensec scan discover --path <path> --format json
```

From the output, collect:
- Every entry point (HTTP route, RPC handler, WebSocket, CLI command, job handler)
- Languages, frameworks, and project structure
- If `scope` is set, filter entry points to matching files only

Sort entry points by risk surface: public HTTP > authenticated HTTP > internal RPC > CLI.

### Phase 2 -- Context Building (per entry point)

For each entry point (or top 20 if many), build a context window:

```bash
opensec scan context-builder --path <path> --target <FILE>:<LINE> --mode entry_point --format json
```

The context-builder returns:
- The handler function body
- Functions called by the handler (1-2 levels deep)
- Relevant middleware, decorators, and configuration
- Database queries, external calls, and file I/O in the call chain

### Phase 3 -- Semantic Analysis (LLM Reasoning)

For each entry point context from Phase 2, perform source-to-sink taint analysis.

**You are the analysis engine.** For each context window:

1. **Identify sources** -- user-controlled data entering the system
   (request params, body, headers, file uploads, env vars, DB reads from user input)
2. **Identify sinks** -- dangerous operations
   (SQL queries, shell commands, file writes, HTML rendering, deserialization,
   LDAP queries, HTTP redirects, crypto key generation)
3. **Trace taint paths** -- follow data from each source through transformations,
   assignments, function calls, and returns to each sink
4. **Check sanitization** -- at each step, determine if the data is sanitized,
   escaped, validated, or parameterized before reaching the sink
5. **Classify finding** -- if taint reaches a sink without adequate sanitization,
   emit a RawFinding

For each finding, produce:

```json
{
  "rule_id": "semantic-sqli-001",
  "severity": "critical",
  "message": "User input from req.query.id flows to SQL string concatenation without parameterization",
  "file_path": "src/routes/users.ts",
  "start_line": 42,
  "cwe": "CWE-89",
  "tools_used": ["semantic-hunter"],
  "evidence_paths": [{
    "source": { "file": "src/routes/users.ts", "line": 38, "label": "req.query.id" },
    "through": [
      { "file": "src/routes/users.ts", "line": 39, "label": "assigned to userId" },
      { "file": "src/services/user.ts", "line": 15, "label": "passed to findUser(userId)" }
    ],
    "sink": { "file": "src/services/user.ts", "line": 22, "label": "template literal in db.query()" }
  }],
  "metadata": {
    "reasoning_steps": [
      "req.query.id is user-controlled (source)",
      "Assigned to local variable userId without validation",
      "Passed to findUser() which builds SQL via template literal",
      "No parameterization or escaping before db.query()",
      "Exploitable SQL injection"
    ],
    "confidence": 92,
    "sanitization_present": false,
    "entry_point": "GET /api/users/:id"
  }
}
```

**Common vulnerability classes to check:**
- SQL Injection (CWE-89)
- OS Command Injection (CWE-78)
- Path Traversal (CWE-22)
- XSS (CWE-79)
- Deserialization (CWE-502)
- SSRF (CWE-918)
- LDAP Injection (CWE-90)
- Open Redirect (CWE-601)
- XML External Entity (CWE-611)

### Phase 4 -- Deduplication & Scoring

After analyzing all entry points:

1. **Deduplicate** -- merge findings that share the same sink location
   (same `file_path:start_line` in the sink). Keep the finding with the
   shortest/most direct taint chain as primary, others as variants.
2. **Score** each finding on three axes (0-100):
   - **Taint completeness** -- is every step in the chain concrete? (not inferred)
   - **Sanitization bypass likelihood** -- is there partial sanitization that could be bypassed?
   - **Impact severity** -- RCE > data breach > info disclosure > DoS
3. **Final confidence** = weighted average: completeness(0.4) + bypass(0.3) + impact(0.3)
4. **Sort** by final confidence descending, then by severity tier.

---

## Output

### Semantic Vulnerability Report

```markdown
# Semantic Vulnerability Report

**Target:** <path>
**Date:** <current date>
**Entry points analyzed:** N
**Findings:** N (Critical: n, High: n, Medium: n)

## Finding 1: [rule_id] -- SEVERITY

**CWE:** CWE-XXX
**Confidence:** NN%
**Entry Point:** METHOD /path

### Evidence Path

Source --> req.query.id (src/routes/users.ts:38)
  Through --> userId variable (src/routes/users.ts:39)
  Through --> findUser(userId) (src/services/user.ts:15)
Sink --> db.query() template literal (src/services/user.ts:22)

### Reasoning
1. ...
2. ...

### Remediation
Specific fix with code example.

---
(repeat per finding)

## Data Gaps
(note any entry points skipped or context-builder failures)
```

---

## Error Handling

- If `opensec scan entrypoints` or `discover` fails, log the error and note the
  gap in the report. Attempt to proceed with whatever data is available.
- If `context-builder` fails for a specific entry point, skip it and note it
  under **Data Gaps**.
- If the project path is invalid, stop and ask for a valid path.
- If no entry points are found, report that and suggest running
  `opensec scan analyze` for basic static analysis instead.

## Execution Notes

- Always use `--format json` for all opensec commands.
- Phase 1 commands run in parallel.
- Phase 2 commands can run in parallel (up to 5 concurrent).
- Phase 3 is sequential per context but can batch small contexts.
- Cap at 20 entry points per run to stay within context limits.
  If more exist, prioritize public-facing and unauthenticated endpoints.
