---
name: missed-patch-hunter
description: >
  Trigger when user asks to "find unpatched variants", "check if similar bugs
  exist", "missed patch analysis", "variant analysis from git history",
  "find code that should have been fixed too". Use to find code paths that have
  the same vulnerability pattern as a previously fixed security bug.
---

# Missed Patch Hunter

Find code paths that share the same vulnerability pattern as a previously fixed
security bug but were missed during the original patch.

## Inputs

| Parameter | Required | Description |
|-----------|----------|-------------|
| `path`    | Yes      | Path to the project root |
| `commit`  | No       | Specific fix commit to analyze (skips Phase 1 ranking) |
| `max_signals` | No  | Max git signals to analyze (default: 10) |

If `path` is not provided, ask for it.

---

## Workflow

### Phase 1 -- Git Signal Extraction

```bash
opensec scan git-signals --path <path> --format json
```

From the output, for each signal compute a priority score:

```
score = diff_length * security_keyword_count
```

Where `security_keyword_count` = number of keywords in the commit message matching:
`fix`, `vuln`, `CVE`, `security`, `patch`, `sanitize`, `inject`, `bypass`,
`auth`, `xss`, `sqli`, `rce`, `ssrf`, `traversal`, `overflow`, `escape`

**Filter and rank:**
1. Discard signals where `diff_length < 20` characters (too small to contain a meaningful fix)
2. Sort remaining by score descending
3. Select top N signals (N = `max_signals`, default 10)

If `commit` is provided, filter signals to that commit only and skip ranking.

### Phase 2 -- Context Building (per signal)

For each selected signal:

```bash
opensec scan context-builder --path <path> --target <FIXED_FILE>:<LINE> --mode finding --format json
```

Also read the original fix diff. From git-signals output, extract:
- `diff_summary` -- what changed in the fix
- `files` -- which files were touched
- The before/after code from the diff

### Phase 3 -- Invariant Extraction (LLM Reasoning)

**You are a security analyst.** For each fix diff, extract the security
invariant that the patch enforces.

An invariant is a rule that must hold to prevent the vulnerability. Examples:

| Invariant Type | Example |
|---------------|---------|
| Parameterization | "User input must use parameterized queries, not string concatenation" |
| Escaping | "HTML output must be escaped via framework auto-escaping or manual encoding" |
| Validation | "File paths must be validated against an allowlist before fs.readFile()" |
| Authentication | "Admin endpoints must check req.user.role === 'admin' before processing" |
| Rate limiting | "Login endpoint must enforce rate limiting to prevent brute force" |
| Authorization | "Resource access must verify ownership via user_id comparison" |
| Cryptography | "Password storage must use bcrypt/argon2, not MD5/SHA1" |
| Input bounds | "Array index must be bounds-checked before access" |

For each signal, produce:
- `invariant`: one-sentence description of the security rule
- `invariant_type`: category from the table above (or a new one if needed)
- `vulnerable_pattern`: regex or code pattern that violates the invariant
- `fixed_pattern`: what the correct code looks like
- `cwe`: applicable CWE ID

### Phase 4 -- Variant Search (LLM Reasoning)

For each extracted invariant, search the codebase for code that violates it.

**Strategy:**
1. Use the `vulnerable_pattern` to identify candidate locations.
   Search broadly -- check all files in the same language as the original fix.
2. For each candidate, read the surrounding context (function body, imports,
   middleware chain) to confirm whether the invariant is violated.
3. Exclude the original fixed location (it is already patched).
4. For confirmed variants, produce a finding:

```json
{
  "rule_id": "missed-patch-variant-sqli-001",
  "severity": "high",
  "message": "Same parameterization invariant violated as fixed in commit abc1234",
  "file_path": "src/services/search.ts",
  "start_line": 67,
  "cwe": "CWE-89",
  "tools_used": ["missed-patch-hunter"],
  "evidence_paths": [{
    "source": { "file": "src/routes/search.ts", "line": 12, "label": "req.query.q" },
    "sink": { "file": "src/services/search.ts", "line": 67, "label": "string concat in db.query()" }
  }],
  "metadata": {
    "original_fix_commit": "abc1234",
    "invariant": "User input must use parameterized queries",
    "invariant_type": "parameterization",
    "confidence": 85
  }
}
```

Use Read and Grep tools to search the codebase. Check:
- Same file, different functions
- Other files using the same database/API/template pattern
- Test files that may reveal other call sites
- Copied or forked code in other modules

### Phase 5 -- Dedup & Package

1. **Deduplicate** by `file_path:start_line` -- if multiple invariants flag the
   same location, merge into one finding keeping all invariant references.
2. **Sort** by severity descending, then confidence descending.
3. **Generate** the final report.

---

## Output

### Missed Patch Report

```markdown
# Missed Patch Report

**Target:** <path>
**Date:** <current date>
**Git signals analyzed:** N
**Invariants extracted:** N
**Variant findings:** N (Critical: n, High: n, Medium: n)

## Signal: commit abc1234 -- "fix: parameterize user search query"

### Invariant
User input must use parameterized queries, not string concatenation.
- **Type:** parameterization
- **CWE:** CWE-89
- **Original fix:** src/services/user.ts:45

### Variants Found

#### Variant 1: src/services/search.ts:67
- **Severity:** High
- **Confidence:** 85%
- **Evidence:** req.query.q flows to string concatenation in db.query()
- **Remediation:** Replace template literal with parameterized query

#### Variant 2: src/services/report.ts:112
- **Severity:** Medium
- **Confidence:** 72%
- **Evidence:** Internal function uses string concat for dynamic table name
- **Remediation:** Validate table name against allowlist

---
(repeat per signal)

## No Variants Found
(list signals where the invariant is consistently enforced elsewhere)

## Data Gaps
(note any context-builder failures or unreadable files)
```

---

## Error Handling

- If `opensec scan git-signals` fails, stop and report the error. This skill
  depends on git history.
- If `context-builder` fails for a specific signal, skip it and note the gap.
- If no security-relevant signals are found in git history, report that and
  suggest running `opensec scan analyze` for general static analysis instead.
- If the project path is invalid or not a git repository, stop and ask for
  a valid path.

## Execution Notes

- Always use `--format json` for all opensec commands.
- Phase 1 is a single command.
- Phase 2 context-builder calls can run in parallel (up to 5 concurrent).
- Phase 3 is sequential per signal (each invariant depends on its context).
- Phase 4 involves reading and searching files -- use Grep and Read tools.
- Cap variant search at 50 candidate locations per invariant to stay bounded.
