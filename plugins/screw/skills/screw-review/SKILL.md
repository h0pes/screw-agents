---
name: screw-review
description: >
  Use when the user asks to check, scan, review, or audit code for security vulnerabilities,
  or mentions any specific vulnerability type: SQL injection, SQLi, XSS, cross-site scripting,
  command injection, CmdI, template injection, SSTI, injection, security issues, security scan,
  vulnerability scan, security audit, security review, secure code review. Delegates to screw-agents subagents.
---

# Security Review Skill

You recognize security review requests and delegate to the appropriate screw-agents subagent.

## When This Skill Activates

- User asks for security review: "review for vulnerabilities", "security audit", "check for security issues"
- User mentions specific vulnerability types: "check for SQL injection", "is this vulnerable to XSS?", "look for command injection"
- User asks to scan code: "scan src/api/", "review my PR for security", "audit this file"

## What to Do

### 1. Determine Scope

Based on the user's request, decide which subagent to dispatch:

| User intent | Subagent |
|---|---|
| Specific vulnerability: "SQL injection", "SQLi" | `screw-scan` (with `agents:[sqli]`) |
| Specific vulnerability: "command injection", "CmdI" | `screw-scan` (with `agents:[cmdi]`) |
| Specific vulnerability: "template injection", "SSTI" | `screw-scan` (with `agents:[ssti]`) |
| Specific vulnerability: "XSS", "cross-site scripting" | `screw-scan` (with `agents:[xss]`) |
| Domain: "injection vulnerabilities", "input validation" | `screw-scan` (with `agents:[sqli, cmdi, ssti, xss]`) |
| Broad: "security review", "security audit", "full scan" | See §3 redirect |

### 2. Check for Existing Findings

Before dispatching, check if `.screw/findings/` contains recent reports for the same target and agent. If a report exists from the current day, mention it: "There's already a scan from today — want me to re-scan or would you like to review the existing report?"

### 3. Delegate (or redirect)

For specific-vulnerability and domain rows: dispatch `screw-scan` via the Agent tool. The dispatch prompt MUST include:

- `target: <user's target description>` (file path, codebase root, glob, line range, etc.)
- `agents: <list-from-mapping-table-above>` — pass the literal agent-names list from the matched row in the mapping table (§1). For domain-level scans, pass all agents in the domain (e.g., `agents: [sqli, cmdi, ssti, xss]` for the injection-input-handling domain).
- `--adaptive` flag if the user explicitly requested adaptive mode (otherwise omit; the screw-scan subagent does NOT probe for interactivity itself — main session enforces consent before dispatch).

Example dispatch prompt (for "scan src/ for SQLi"):

> Run `screw-scan` with `agents: [sqli]`, `target: src/`. Loop `scan_agents` pages until `next_cursor` is null, accumulate findings, return the structured payload to the main session.

For the broad/full row: do NOT dispatch. Respond to the user with this message verbatim:

> Full scans require `/screw:scan full` (skills dispatch a single subagent with one fixed scope; full-scope coverage is owned by the slash command's resolver). Either run `/screw:scan full` directly, or specify a domain (e.g., `injection-input-handling`) or agent (`sqli`, `cmdi`, `ssti`, `xss`) for a targeted scan.

Rationale (do not include in user output): the screw-agents plugin enforces a chain-subagents pattern (sub-agents.md:683-689) where multi-agent fan-out lives in the main-session slash command (`scan.md` Step 1b), not in a skill. The skill's role is narrow intent routing; broad intents require the slash command.

Wait for the user's follow-up after printing the message.

### 4. Summarize

After the subagent completes, briefly summarize what was found and where the reports were written.

## Unavailable Agents

If the user asks about a vulnerability type without a dedicated agent, respond with what's available:

"No dedicated agent for [requested type] yet. Available agents: **sqli** (SQL injection), **cmdi** (command injection), **ssti** (template injection), **xss** (cross-site scripting). All four belong to the **injection-input-handling** domain. Want me to run one of these?"

## What NOT to Do

- Do NOT auto-trigger on code changes — only activate when the user explicitly requests security review
- Do NOT analyze code yourself — always delegate to subagents
- Do NOT attempt ad-hoc security review without the MCP tools
