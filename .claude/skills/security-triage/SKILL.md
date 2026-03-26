---
name: security-triage
description: >
  Trigger when user asks to "triage these findings", "verify if this is a real
  vulnerability", "false positive check", "validate security findings",
  "attacker vs defender analysis", "is this exploitable". Use for adversarial
  verification of security scan results using attacker/defender/evaluator reasoning.
---

# Security Triage

Adversarial attacker/defender/evaluator verification of security findings.
Reduces false positives by reasoning about real-world exploitability.

## Inputs

| Parameter | Required | Description |
|-----------|----------|-------------|
| `path`    | Yes      | Path to the project root |
| `findings`| Yes      | Findings from `opensec scan analyze`, semantic-hunter, or manual input |
| `confidence_floor` | No | Minimum confidence to report as real (default: 60) |

Accept findings as:
- JSON output from a previous `opensec scan analyze --format json`
- Output from the semantic-hunter skill
- Manual finding description (you will structure it into a RawFinding)

If `path` is not provided, ask for it.

---

## Workflow

### Phase 1 -- Finding Intake

For each finding in the input set:

1. Compute a fingerprint: `sha256(rule_id + file_path + start_line + sink_signature)`
2. Check triage memory:

```bash
opensec scan triage-memory --action query --fingerprint <FP> --format json
```

3. If the memory returns a record with `fp_streak >= 3`, **skip** the finding and
   log: `"Skipped [rule_id] at [file:line] -- FP streak >= 3"`
4. Otherwise, proceed to Phase 2.

### Phase 2 -- Context Building

For each finding that passed intake:

```bash
opensec scan context-builder --path <path> --target <FILE>:<LINE> --mode finding --format json
```

The context includes:
- The vulnerable code and surrounding function
- Call chain leading to the vulnerable line
- Relevant middleware, guards, and configuration
- Framework-level protections in effect

### Phase 3 -- Attacker Pass (LLM Reasoning)

**Role: You are a skilled attacker.** Your goal is to prove the finding is
exploitable. Analyze each finding on six points:

| # | Analysis Point | Question |
|---|---------------|----------|
| 1 | **Source identification** | Where does attacker-controlled input enter? |
| 2 | **Sink identification** | What dangerous operation receives the input? |
| 3 | **Path validation** | Is there a concrete code path from source to sink? |
| 4 | **Control bypass** | Can existing sanitization/validation be bypassed? |
| 5 | **Exploitability** | Write a concrete proof-of-concept payload |
| 6 | **Impact assessment** | What damage results from successful exploitation? |

Produce:
- `attacker_verdict`: `"vulnerable"` or `"not_vulnerable"`
- `attacker_confidence`: 0-100
- `attacker_reasoning`: array of strings (one per analysis point)
- `attacker_payload`: concrete PoC if exploitable, `null` otherwise

### Phase 4 -- Defender Pass (LLM Reasoning)

**Role: You are a security-conscious defender.** Your goal is to prove the
finding is mitigated. Analyze each finding on six points:

| # | Mitigation Check | Question |
|---|-----------------|----------|
| 1 | **Framework protections** | Does the framework auto-escape/parameterize? |
| 2 | **Middleware guards** | Is there WAF, CSRF, rate-limit, or auth middleware? |
| 3 | **Input validation** | Is input validated/sanitized before reaching sink? |
| 4 | **Output encoding** | Is output encoded before rendering/execution? |
| 5 | **Architecture barriers** | Network segmentation, least privilege, sandboxing? |
| 6 | **Dead code check** | Is the vulnerable path actually reachable in production? |

Produce:
- `defender_verdict`: `"mitigated"` or `"not_mitigated"`
- `defender_confidence`: 0-100
- `defender_reasoning`: array of strings (one per mitigation check)
- `mitigations_found`: array of specific protections identified

### Phase 5 -- Evaluator (Conditional)

Invoke the evaluator ONLY when attacker and defender disagree AND their
confidence values differ by less than 20 points:

```
|attacker_confidence - defender_confidence| < 20
AND attacker_verdict != defender_verdict (treating "vulnerable" != "mitigated")
```

**Role: You are a neutral senior security evaluator.** Weigh both arguments:
- Review attacker's PoC payload -- is it realistic?
- Review defender's mitigations -- are they actually in the code path?
- Check for edge cases both sides missed
- Produce: `evaluator_verdict`, `evaluator_confidence`, `evaluator_reasoning`

### Phase 6 -- Fusion & Memory Update

#### Fusion Rules

| Attacker | Defender | Evaluator | Final Verdict | Confidence |
|----------|----------|-----------|---------------|------------|
| vulnerable | not_mitigated | N/A | **TRUE POSITIVE** | max(atk, def) |
| not_vulnerable | mitigated | N/A | **FALSE POSITIVE** | max(atk, def) |
| vulnerable | mitigated | vulnerable | **TRUE POSITIVE** | evaluator_confidence |
| vulnerable | mitigated | mitigated | **FALSE POSITIVE** | evaluator_confidence |
| not_vulnerable | not_mitigated | N/A | **NEEDS REVIEW** | min(atk, def) |
| vulnerable | mitigated | N/A (no eval) | **NEEDS REVIEW** | avg(atk, def) |

Apply the matching rule to determine final verdict and confidence.

If final confidence < `confidence_floor`, downgrade to **NEEDS REVIEW**.

#### Memory Update

For each triaged finding:

```bash
opensec scan triage-memory --action update \
  --fingerprint <FP> \
  --verdict <true_positive|false_positive|needs_review> \
  --confidence <N> \
  --format json
```

This updates the triage memory so future runs can skip known false positives.

---

## Output

### Triage Report

```markdown
# Security Triage Report

**Target:** <path>
**Date:** <current date>
**Findings triaged:** N
**True Positives:** N | **False Positives:** N | **Needs Review:** N
**Skipped (FP memory):** N

## Finding: [rule_id] at [file:line]

**Final Verdict:** TRUE POSITIVE | FALSE POSITIVE | NEEDS REVIEW
**Confidence:** NN%
**Severity:** critical | high | medium | low

### Attacker Analysis
- Verdict: vulnerable (confidence: NN%)
- Payload: `<concrete PoC>`
- Reasoning:
  1. ...

### Defender Analysis
- Verdict: not_mitigated (confidence: NN%)
- Mitigations found: none
- Reasoning:
  1. ...

### Evaluator (if invoked)
- Verdict: ... (confidence: NN%)
- Reasoning: ...

### Fusion
Applied rule: "Both agree vulnerable -> TRUE POSITIVE at max confidence"

---
(repeat per finding)

## Triage Memory Updates
| Fingerprint | Verdict | Confidence | FP Streak |
|------------|---------|------------|-----------|
| abc123...  | true_positive | 88 | 0 |
| def456...  | false_positive | 91 | 2 |
```

---

## Error Handling

- If `opensec scan triage-memory` is unavailable, skip memory checks and note
  "Triage memory unavailable -- all findings processed without history" in the report.
- If `context-builder` fails for a finding, attempt triage with the raw finding
  data only. Note reduced confidence in the output.
- If the findings input is empty or unparseable, stop and ask for valid findings.
- If the project path is invalid, stop and ask for a valid path.

## Execution Notes

- Always use `--format json` for all opensec commands.
- Phase 1 memory queries can run in parallel.
- Phase 2 context-builder calls can run in parallel (up to 5 concurrent).
- Phases 3 and 4 run sequentially per finding but are independent across findings.
- Phase 5 only fires for disagreements within 20 confidence points.
- Phase 6 memory updates can run in parallel.
- Process findings in severity order: critical first, then high, medium, low.
