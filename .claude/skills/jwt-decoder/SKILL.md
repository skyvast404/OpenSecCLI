---
name: jwt-decoder
description: >
  Trigger when user pastes a JWT token or asks to "decode JWT", "analyze this token",
  "check JWT security". Instant JWT security analysis.
---

# JWT Decoder

Analyze a JWT token for security issues using built-in OpenSecCLI commands.

## Workflow

### Step 1: JWT Security Test

```bash
opensec pentest jwt-test --token "$TOKEN" --format json
```

Parse JSON output. Extract:
- Algorithm used (alg header)
- Whether "none" algorithm attack is possible
- Whether algorithm confusion is possible
- Key strength assessment
- Token claims (sub, iss, exp, iat, etc.)

### Step 2: Signature Algorithm Identification

If a signature is present (third segment is non-empty), run:

```bash
opensec crypto hash-id --hash "$SIGNATURE" --format json
```

Extract: identified hash type, hashcat/john mode suggestions.

### Step 3: Present Findings

```markdown
# JWT Security Analysis

**Token:** `<first 20 chars>...`
**Algorithm:** <alg value>

## Decoded Header
<pretty-printed JSON header>

## Decoded Payload
<pretty-printed JSON payload>

## Security Findings
| Check | Result | Severity |
|-------|--------|----------|
| None algorithm | Vulnerable/Safe | Critical/Info |
| Algorithm confusion | Vulnerable/Safe | High/Info |
| Expiration | Expired/Valid/Missing | Warn/Info/Warn |
| Signature | Present/Missing | Info/Critical |

## Plain Language Summary
<1-3 sentences explaining each finding in non-technical terms>
```

## Error Handling

- If jwt-test fails, attempt manual base64 decode of header and payload segments.
- If hash-id fails (e.g., signature too short), note as "Could not identify signature type."
