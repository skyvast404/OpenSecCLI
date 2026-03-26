---
name: agent-attack-research
description: >
  Trigger when user asks to "research agent attacks", "find new attack
  patterns", "collect attack sources", "build attack corpus",
  "agent threat intelligence". Use for collecting, normalizing, and
  cataloging AI agent attack patterns for security research.
---

# Agent Attack Research

Collect, normalize, and catalog AI agent attack patterns from diverse sources.
Produces a structured research summary with new cases, knowledge base updates,
and coverage gap analysis mapped to MITRE ATLAS tactics.

## Inputs

| Parameter    | Required | Description |
|--------------|----------|-------------|
| `SRC_DIR`    | No       | Directory of raw attack source files to process |
| `OUT_DIR`    | No       | Output directory for normalized cases (default: `./normalized`) |
| `KB_DIR`     | No       | Knowledge base directory to update (default: `./kb`) |
| `CORPUS_DIR` | No       | Existing test corpus dir for coverage analysis |
| `TOPIC`      | No       | Specific research focus (e.g., "tool abuse", "MCP attacks") |

If no directories are provided, operates in guided mode to build a corpus.

---

## Workflow

### Phase 1 -- Source Collection

Guide the user through identifying and registering attack research sources.

**Source categories** (collect at least 2 categories for meaningful coverage):

| Category | Examples | Priority |
|----------|----------|----------|
| Academic papers | arXiv, USENIX, IEEE S&P, NeurIPS adversarial ML | High |
| CTF writeups | AI Village, LLM CTF, GPT challenge solutions | High |
| Blog posts | Security researcher blogs, vendor disclosures | Medium |
| CVE reports | NVD entries for LLM/agent vulnerabilities | High |
| Red team findings | Internal/external red team engagement reports | Critical |
| Tool documentation | Attack tool repos, framework docs | Medium |

For each source, record:
- URL or file path
- Publication date
- Author/organization
- Source category
- Brief description of attack techniques covered

If `TOPIC` is specified, focus collection on that area. If `SRC_DIR` is
provided, inventory existing files and categorize them.

### Phase 2 -- Case Normalization

Convert raw source material into structured attack cases:

```bash
opensec agent-security normalize-cases --sources_dir $SRC_DIR --output_dir $OUT_DIR --format json
```

If the command is unavailable, perform normalization manually. For each
attack pattern extracted from sources, produce:

```json
{
  "case_id": "ATK-YYYY-NNN",
  "title": "Descriptive attack name",
  "category": "prompt-injection | tool-abuse | data-exfil | privilege-escalation | persistence | evasion",
  "attack_surface": "direct-prompt | indirect-prompt | tool-schema | mcp-server | rag-pipeline | multi-turn",
  "expected_risk": "critical | high | medium | low",
  "atlas_tactic": "initial-access | execution | persistence | collection | exfiltration | impact",
  "description": "What the attack does and why it works",
  "payload_template": "Example attack payload with $VARIABLES",
  "detection_signals": ["signal1", "signal2"],
  "defense_strategies": ["strategy1", "strategy2"],
  "source_ref": "URL or citation",
  "date_added": "YYYY-MM-DD"
}
```

Assign category, attack_surface, and expected_risk based on the source
material. Flag uncertain assignments with `"confidence": "low"`.

### Phase 3 -- Knowledge Base Update

Validate and integrate normalized cases into the knowledge base:

```bash
opensec agent-security manage-kb --action validate --kb_dir $KB_DIR --format json
```

**ATLAS tactic mapping** -- ensure every case maps to at least one tactic:

| Tactic | Description | Example Attack |
|--------|-------------|----------------|
| Initial Access | Gaining first interaction with agent | Prompt injection via shared doc |
| Execution | Causing agent to perform attacker actions | Tool call with injected args |
| Persistence | Maintaining access across sessions | Memory poisoning, context injection |
| Collection | Gathering information from agent | System prompt extraction |
| Exfiltration | Extracting data outside boundaries | Markdown image exfil, tool-based leak |
| Impact | Disrupting agent operation | Safety bypass, harmful content generation |

**Bidirectional mapping** -- for each attack case, verify:
- Attack --> Detection: At least one detection signal is defined
- Detection --> Defense: At least one defense strategy addresses each signal
- Defense --> Validation: A test case can verify the defense works

If any link in the chain is missing, flag it as an incomplete mapping.

### Phase 4 -- Coverage Gap Analysis

Compare the updated knowledge base against the existing test corpus:

```bash
opensec agent-security analyze-coverage --corpus_dir $CORPUS_DIR --format json
```

Identify gaps along three axes:

1. **Category gaps**: Attack categories with zero or few test cases
2. **Surface gaps**: Attack surfaces not represented in the corpus
3. **Tactic gaps**: ATLAS tactics without corresponding test coverage

Prioritize by gap severity combined with real-world prevalence.

---

## Error Handling

- If `normalize-cases` fails, fall back to manual normalization using the
  JSON template above. Note the gap in output.
- If `manage-kb` fails, output normalized cases as standalone JSON.
- If `CORPUS_DIR` is not provided, skip Phase 4 and note it.
- If no sources are found, guide user to public attack research repositories.

---

## Output -- Research Summary

```markdown
# Agent Attack Research Summary

**Date:**          <current date>
**Topic:**         $TOPIC or "General"
**Sources processed:** N
**New cases:**     N
**KB updates:**    N additions, N modifications

## 1. New Attack Cases

| ID | Title | Category | Surface | Risk | ATLAS Tactic |
|----|-------|----------|---------|------|--------------|
| ATK-2026-001 | ... | ... | ... | ... | ... |

## 2. Source Inventory

| Source | Category | Cases Extracted | Quality |
|--------|----------|----------------|---------|
| arxiv.org/abs/... | Academic | 3 | High |
| blog.example.com/... | Blog | 1 | Medium |

## 3. Knowledge Base Delta

| Metric | Before | After | Delta |
|--------|--------|-------|-------|
| Total cases | N | N | +N |
| Categories covered | N/6 | N/6 | +N |
| ATLAS tactics covered | N/6 | N/6 | +N |
| Incomplete mappings | N | N | -N |

## 4. Coverage Gap Analysis

| Gap Type | Area | Current Coverage | Priority | Suggested Action |
|----------|------|-----------------|----------|------------------|
| Category | tool-abuse | 2 cases | High | Research MCP tool injection |
| Surface | mcp-server | 0 cases | Critical | Collect MCP attack writeups |
| Tactic | persistence | 1 case | Medium | Study memory poisoning |

## 5. Research Priorities

Ranked list of areas needing further research with suggested sources.

## 6. Data Gaps

List normalization failures, uncertain classifications, or incomplete mappings.
```

---

## Execution Notes

- Always use `--format json` for all opensec commands.
- Phase 1 is interactive; engage the user to identify sources.
- Phase 2 can process sources in parallel if multiple files exist.
- Phase 3 validation is sequential to avoid KB conflicts.
- Guided mode (no dirs): produce a research plan instead of processed cases.
