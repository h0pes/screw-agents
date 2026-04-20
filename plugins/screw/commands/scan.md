---
name: screw:scan
description: "Run a security scan with screw-agents. Usage: /screw:scan <agent|domain|full> [target] [--thoroughness standard|deep] [--format json|sarif|markdown] [--adaptive]"
---

# /screw:scan — Security Scan Command

Parse the arguments and dispatch to the appropriate screw-agents subagent.

## Syntax

```
/screw:scan <scope> [target] [--thoroughness standard|deep] [--format json|sarif|markdown] [--adaptive]
```

## Arguments

**scope** (required): What to scan with.
- Agent name: `sqli`, `cmdi`, `ssti`, `xss`
- Domain name: `injection`
- `full` for comprehensive review

**target** (optional, defaults to codebase root):
- Bare path: `src/api/auth.rs` (file) or `src/api/**` (glob — auto-detected by presence of `*`)
- `git_diff:BASE` → `{ "type": "git_diff", "base": "BASE", "head": "HEAD" }`
- `function:NAME@FILE` → `{ "type": "function", "file": "FILE", "name": "NAME" }`
- `class:NAME@FILE` → `{ "type": "class", "file": "FILE", "name": "NAME" }`
- `commits:RANGE` → `{ "type": "git_commits", "range": "RANGE" }`

**--thoroughness** (optional, default `standard`): `standard` or `deep`. Passed to the scan tool.

**--format** (optional, default `markdown`): `json`, `sarif`, or `markdown`. Passed to format_output.

**--adaptive** (optional flag, default disabled): Enable adaptive analysis mode. When set, the invoked subagent will:

1. Record `context_required` heuristic matches it couldn't resolve (D1 signal via `record_context_required_match`).
2. Detect coverage gaps via `detect_coverage_gaps` (D1 + D2).
3. For each gap (up to 3 per scan session, per the Layer 0f quota): generate a targeted Python analysis script, lint it (Layer 1), send through Layer 0d semantic review, present a 5-section review to the user for **approve/reject**, sign on approve, execute in sandbox (Layer 5), and merge findings with the YAML findings.

**Requirements for `--adaptive`:**

- `.screw/config.yaml` must exist with `script_reviewers` populated via `screw-agents init-trust`.
- The invocation must be **interactive** — the user types `approve <name>` or `reject <name>` in response to the review prompt. The `--adaptive` flag IS the user consent; there is no additional session-type probe.
- CI pipelines, piped-stdin contexts, and other non-interactive invocations MUST NOT pass `--adaptive`. Subagents refuse with "Adaptive mode requires interactive approval — cannot proceed" if they cannot receive input.

**Example:**

```
/screw:scan sqli src/api/ --adaptive
```

See `docs/specs/2026-04-13-phase-3-adaptive-analysis-learning-design.md` §5 for the full 15-layer defense-in-depth model.

## Dispatch

After parsing, delegate to the appropriate subagent via the Agent tool:

| Scope | Subagent |
|---|---|
| `sqli` | `screw-sqli` |
| `cmdi` | `screw-cmdi` |
| `ssti` | `screw-ssti` |
| `xss` | `screw-xss` |
| `injection` | `screw-injection` |
| `full` | `screw-full-review` |

Pass the parsed target, thoroughness, format, and `--adaptive` flag to the subagent so it can use them.

## Examples

```
/screw:scan sqli src/api/auth.rs
/screw:scan injection --target git_diff:main
/screw:scan full --thoroughness deep
/screw:scan xss src/components/**
/screw:scan sqli function:get_user@src/api/users.py
/screw:scan sqli src/api/ --adaptive
```
