# Plugin System MVP + Domain Taxonomy Fix

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix missing domain values on 17 YAML adapters, formalize the security domain taxonomy, build a minimal plugin system (local directory scan), add `opensec create adapter` scaffold, and create CONTRIBUTING.md.

**Architecture:** Fix domain propagation in `discovery.ts` and `loadFromManifest`. Define a canonical `SecurityDomain` enum. Add `~/.openseccli/plugins/` scanning to discovery. Add scaffold command. Zero new dependencies.

**Tech Stack:** TypeScript, Commander.js, node:fs

---

## Task 1: Fix domain propagation + formalize SecurityDomain

17 YAML adapters have no domain because:
1. `loadFromManifest()` doesn't pass `entry.domain` to `CliCommand`
2. `registerYamlAdapter()` doesn't extract `domain` from YAML def

Also formalize the domain taxonomy as a const map.

**Files:**
- Create: `src/constants/domains.ts`
- Modify: `src/discovery.ts:35-46` (add `domain: entry.domain`)
- Modify: `src/discovery.ts:107-118` (add `domain: def.domain`)
- Test: verify with `opensec list --format json`

---

## Task 2: Local plugin discovery

Enable `~/.openseccli/plugins/<name>/adapters/` scanning.

**Files:**
- Create: `src/plugins/local-discovery.ts`
- Modify: `src/discovery.ts` — call `discoverLocalPlugins()` after built-in loading
- Test: `tests/unit/plugin-discovery.test.ts`

---

## Task 3: `opensec create adapter` scaffold

**Files:**
- Create: `src/commands/create.ts`
- Modify: `src/cli.ts` — register `create adapter` command
- Test: manual smoke test

---

## Task 4: CONTRIBUTING.md

**Files:**
- Create: `CONTRIBUTING.md`

---

## Task 5: Final verification + push
