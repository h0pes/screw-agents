---
name: screw:scan
description: "Run a security scan with screw-agents. Usage: /scan <agent|domain|full> [target] [--thoroughness standard|deep] [--format json|sarif|markdown]"
---

# /screw:scan — Security Scan Command

Parse the arguments and dispatch to the appropriate screw-agents subagent.

## Syntax

```
/scan <scope> [target] [--thoroughness standard|deep] [--format json|sarif|markdown]
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

Pass the parsed target, thoroughness, and format to the subagent so it can use them.

## Examples

```
/scan sqli src/api/auth.rs
/scan injection --target git_diff:main
/scan full --thoroughness deep
/scan xss src/components/**
/scan sqli function:get_user@src/api/users.py
```
