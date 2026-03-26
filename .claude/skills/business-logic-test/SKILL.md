---
name: business-logic-test
description: >
  Trigger when user asks to "test business logic", "find logic flaws",
  "workflow bypass", "payment manipulation", "IDOR testing", "race condition
  in checkout", "coupon abuse", "price tampering", "state machine testing",
  "WSTG-BUSL". Use for business logic vulnerability testing that can't be
  found by automated scanning.
---

# Business Logic Vulnerability Assessment

Orchestrate a manual-guided business logic security assessment using
OpenSecCLI adapters for automation where possible. Produces a structured
findings report mapped to OWASP WSTG-BUSL-01 through BUSL-10.

> **AUTHORIZATION WARNING**: Before proceeding, confirm with the user that
> they have explicit written authorization to test the target. Business logic
> testing modifies application state (orders, payments, accounts). If the
> user cannot confirm authorization, do NOT proceed. State the legal
> requirement and stop.

## Required Input

| Parameter | Required | Description |
|-----------|----------|-------------|
| `URL`     | Yes      | Full target URL (e.g., `https://app.example.com`) |
| `PATH`    | No       | Local source code path for static analysis |

Extract `DOMAIN` from the URL by stripping the scheme, port, and path.

---

## Workflow

### Phase 1 --- Application Understanding (run in parallel)

Launch simultaneously:

```bash
opensec scan discover --path $PATH --format json
```

```bash
opensec scan entrypoints --path $PATH --format json
```

```bash
opensec vuln header-audit --url $URL --format json
```

From the results, extract:
- **Tech stack**: Frameworks, languages, payment providers, auth mechanisms.
- **Endpoints**: All routes, especially multi-step flows (checkout, signup,
  approval, password reset, file upload).
- **Security headers**: Session config, CSRF protections, rate-limit headers.

If `PATH` is not provided, skip the `scan discover` and `scan entrypoints`
commands. Ask the user to describe application workflows manually.

### Phase 2 --- Workflow Mapping

Using Phase 1 data and user input, document:

1. **Multi-step flows**: List each flow as an ordered sequence of endpoints
   (e.g., `POST /cart/add` -> `POST /checkout/init` -> `POST /payment`
   -> `GET /order/confirm`).
2. **State transitions**: For each flow, note which state is expected at
   each step and how the server enforces it (session, token, DB flag).
3. **Business constraints**: Price floors, quantity limits, coupon rules,
   referral caps, role-based approvals, file type restrictions.
4. **Trust boundaries**: Which validations happen client-side vs server-side.

Present the workflow map to the user for confirmation before testing.

### Phase 3 --- Business Logic Tests

Execute tests per WSTG-BUSL category. For each test, craft requests with:

```bash
opensec pentest http-request --url $URL --method POST --body '...' --format json
```

**BUSL-01: Data Validation** -- Submit boundary values, type mismatches,
overlong strings, Unicode edge cases to every input field.

**BUSL-02: Forged Requests** -- Replay requests with modified hidden fields,
tampered IDs, altered amounts. Test IDOR by substituting resource IDs.

**BUSL-03: Integrity Checks** -- Modify prices, quantities, or totals
between steps. Submit negative quantities, zero prices, fractional values.

**BUSL-04: Process Timing** -- Test time-of-check/time-of-use gaps. Submit
expired tokens, replay old OTPs, use stale session data.

**BUSL-05: Function Use Limits** -- Reuse single-use coupons, repeat
referral bonuses, vote/rate multiple times, exceed withdrawal limits.

```bash
opensec pentest race-test --url $URL --count 10 --format json
```

Use race-test for concurrent coupon redemption, double-spend, and
simultaneous account operations.

**BUSL-06: Workflow Circumvention** -- Skip steps by calling final endpoint
directly. Reorder steps. Replay intermediate tokens at wrong stages.

**BUSL-07: Application Misuse** -- Test for denial-of-service via expensive
operations (large file uploads, complex searches, bulk exports).

**BUSL-08: Unexpected File Types** -- Upload polyglots (e.g., GIF header +
PHP), SVG with embedded JS, .html renamed to .jpg, oversized files.

**BUSL-09: Malicious File Upload** -- Path traversal in filenames
(`../../etc/passwd`), null byte injection, double extensions, MIME mismatch.

**BUSL-10: Payment Manipulation** -- Tamper with price at every stage:
cart, checkout, payment callback. Test discount stacking, currency
confusion, rounding errors, refund-then-use flows.

### Phase 4 --- Verification

For each potential finding, verify by:

1. Crafting a proof-of-concept request:

```bash
opensec pentest http-request --url $URL --method POST --body '{"item_id":"123","qty":-1,"price":0}' --format json
```

2. Documenting the full request and response as evidence.
3. Testing if the server state actually changed (order created, balance
   modified, privilege escalated).
4. Ruling out false positives where the server rejected the request.

---

## Error Handling

- If any `opensec` command fails, log the error, mark that check as
  `Skipped` in the report, and continue with remaining tests.
- If `PATH` is not provided, skip static analysis and note it in Data Gaps.
- Parse JSON output safely. If output is not valid JSON, include raw stderr
  in the **Data Gaps** section.
- Never let a single failed step abort the entire assessment.

---

## Output --- Business Logic Assessment Report

### 1. Executive Summary

```
Target:           $URL
Date:             <current date>
Source analysis:   Included / Not included
Authorization:    Confirmed by user

Total findings:   <N>
  Critical: <n>   High: <n>   Medium: <n>   Low: <n>   Info: <n>
```

One-paragraph summary of business logic posture and highest-impact risks.

### 2. Workflow Diagrams

For each tested flow, a text-based diagram:

```
[Add to Cart] --(item_id, qty, price)--> [Checkout Init] --(cart_token)-->
[Payment Submit] --(payment_token, amount)--> [Order Confirm]
    ^^ BUSL-03: price modified here without server re-validation
```

### 3. Findings by Severity

For each finding:

| Field | Value |
|-------|-------|
| **Title** | Descriptive name |
| **Severity** | Critical / High / Medium / Low / Info |
| **WSTG Category** | e.g., WSTG-BUSL-03 |
| **Location** | Endpoint and parameter |
| **Request** | Full HTTP request used |
| **Response** | Relevant response excerpt |
| **Impact** | Business impact (financial loss, data breach, etc.) |
| **Remediation** | Specific server-side fix |

### 4. WSTG-BUSL Coverage Matrix

| WSTG ID | Category | Tested | Findings | Severity |
|---------|----------|--------|----------|----------|
| BUSL-01 | Data Validation | Yes/No | <n> | -- |
| BUSL-02 | Forged Requests | Yes/No | <n> | -- |
| BUSL-03 | Integrity Checks | Yes/No | <n> | -- |
| BUSL-04 | Process Timing | Yes/No | <n> | -- |
| BUSL-05 | Function Use Limits | Yes/No | <n> | -- |
| BUSL-06 | Workflow Circumvention | Yes/No | <n> | -- |
| BUSL-07 | Application Misuse | Yes/No | <n> | -- |
| BUSL-08 | Unexpected File Types | Yes/No | <n> | -- |
| BUSL-09 | Malicious File Upload | Yes/No | <n> | -- |
| BUSL-10 | Payment Manipulation | Yes/No | <n> | -- |

Include all 10 categories. Use `--` for categories with no findings.

### 5. Remediation Roadmap

| Priority | Finding | WSTG ID | Effort | Recommendation |
|----------|---------|---------|--------|----------------|
| 1 | Price tamper in checkout | BUSL-10 | Medium | Server-side price recalculation |
| 2 | Coupon reuse | BUSL-05 | Low | DB unique constraint on redemption |

### 6. Data Gaps

List skipped checks and reasons. Suggest how to enable them.

---

## Follow-up Suggestions

After presenting the report, offer:

- "Want me to deep-dive on any specific workflow with more payloads?"
- "I can test race conditions with higher concurrency on a specific endpoint."
- "Should I check for IDOR across all resource types?"
- "I can run a full web pentest for broader vulnerability coverage."
