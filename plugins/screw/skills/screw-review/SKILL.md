---
name: screw-review
description: >
  Use when the user asks for security review, vulnerability scanning, or security audit.
  Recognizes security review intent and delegates to the appropriate screw-agents subagent.
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
| Specific vulnerability: "SQL injection", "SQLi" | `screw-sqli` |
| Specific vulnerability: "command injection", "CmdI" | `screw-cmdi` |
| Specific vulnerability: "template injection", "SSTI" | `screw-ssti` |
| Specific vulnerability: "XSS", "cross-site scripting" | `screw-xss` |
| Domain: "injection vulnerabilities", "input validation" | `screw-injection` |
| Broad: "security review", "security audit", "full scan" | `screw-full-review` |

### 2. Check for Existing Findings

Before dispatching, check if `.screw/findings/` contains recent reports for the same target and agent. If a report exists from the current day, mention it: "There's already a scan from today — want me to re-scan or would you like to review the existing report?"

### 3. Delegate

Dispatch the chosen subagent via the Agent tool. Pass along the user's target description so the subagent can interpret it.

### 4. Summarize

After the subagent completes, briefly summarize what was found and where the reports were written.

## Unavailable Agents

If the user asks about a vulnerability type without a dedicated agent, respond with what's available:

"No dedicated agent for [requested type] yet. Available agents: **sqli** (SQL injection), **cmdi** (command injection), **ssti** (template injection), **xss** (cross-site scripting). The **injection** domain orchestrator runs all four. Want me to run one of these?"

## What NOT to Do

- Do NOT auto-trigger on code changes — only activate when the user explicitly requests security review
- Do NOT analyze code yourself — always delegate to subagents
- Do NOT attempt ad-hoc security review without the MCP tools
