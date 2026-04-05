# SCREW Agents — Draft Product Requirements Document

> **Status:** Draft v0.4.3
> **Date:** 2026-03-31
> **Author:** h0pes + Claude (architecture session)
> **Changelog:** v0.4.3 — Repository structure and distribution strategy | v0.4.2 — SpecterOps code review methodology, Anthropic security review Action refs | v0.4.1 — codex-plugin-cc reference for challenger implementation | v0.4 — Autoresearch self-improvement loop, multi-LLM challenger system, OWASP Code Review Guide, SAST benchmarks | v0.3 — Adaptive analysis scripts, persistent learning from false positives | v0.2 — CWE-1400 taxonomy backbone, OWASP Top 10:2025, git diff/PR targets

---

## 1. Vision & Problem Statement

### Problem

Security code review is a manual, expertise-intensive process. Existing SAST tools produce high false-positive rates and shallow pattern matching. LLMs have the potential to perform deeper, context-aware vulnerability analysis — but only when given highly specialized, well-structured security knowledge rather than generic "review this code" prompts.

### Vision

Build a modular system of **dedicated, vulnerability-specific AI agents** for secure code review, powered by Claude. Each agent is a specialist (e.g., one for SQL injection, one for SSTI, one for broken access control) carrying distilled knowledge from authoritative security sources (OWASP, CWE, CAPEC, SANS, real-world CVEs, community research).

The system must be **pluggable** — usable as a first-class experience inside Claude Code, integratable with the [screw.nvim](https://github.com/h0pes/screw.nvim) Neovim plugin, and extensible to future clients (CI/CD pipelines, VS Code, other editors).

### Core Value Proposition

The real value lies not in the architecture but in the **quality of agent knowledge**. A mediocre prompt produces mediocre results. An agent carrying precisely distilled knowledge from CWE subtypes, OWASP testing procedures, Semgrep rule patterns, real-world bypass techniques, and framework-specific pitfalls produces dramatically better, more actionable results.

---

## 2. Goals & Non-Goals

### Goals

- **G1:** Dedicated agents for individual vulnerability types (SQLi, SSTI, XPath injection, command injection, etc.) organized into security domains based on the **CWE-1400 (Comprehensive Categorization)** taxonomy — the only established, mutually exclusive, complete classification system for software weaknesses
- **G2:** User control over target scope — scan a single file, multiple files, entire codebase, specific methods/classes/functions, line ranges, **git diffs, or pull requests**
- **G3:** First-class standalone experience in Claude Code (no external dependencies required)
- **G4:** Pluggable integration with screw.nvim for editor-native security review workflow
- **G5:** Agent knowledge built from thorough research of authoritative security sources, optimized for LLM consumption
- **G6:** Community-extensible agent definitions (new vulnerability types via YAML, no code changes)
- **G7:** Structured, actionable output — findings with CWE classification, severity, remediation guidance, and false-positive reasoning
- **G8:** Adaptive analysis capability — when standard agents encounter unfamiliar code patterns (custom ORMs, proprietary frameworks), the system writes, executes, and persists targeted analysis scripts for reuse
- **G9:** Persistent learning from triage — false positive decisions are captured, stored per-project, and used to suppress known-safe patterns in future scans, reducing noise over time
- **G10:** Autonomous self-improvement — agents iteratively refine their own detection heuristics by running against SAST benchmark suites, measuring detection/FP rates, and proposing improvements (autoresearch pattern)
- **G11:** Multi-LLM adversarial validation — findings can be challenged by a second LLM (OpenAI Codex or others) to reduce false positives and improve confidence calibration, with results feeding back into the autoresearch loop

### Non-Goals (for v1)

- Real-time collaborative multi-user scanning (screw.nvim collaboration features remain separate)
- Replacing SAST tools entirely — this complements them, not replaces
- Fully autonomous remediation (agents suggest fixes, humans approve)
- Supporting non-Claude LLMs as the analysis backend

---

## 3. Architecture Overview

### Core Principle: MCP Server as the Pluggable Backbone

The central architectural decision is to build an **MCP (Model Context Protocol) server** that encapsulates all security review intelligence. Claude Code agents, screw.nvim, and future clients are thin orchestration layers calling into this shared backend.

```
┌─────────────────────────────────────────────────────────────────┐
│                     CONSUMERS / CLIENTS                         │
│                                                                 │
│  ┌───────────────┐  ┌───────────────┐  ┌─────────────────────┐ │
│  │  Claude Code  │  │  screw.nvim   │  │  CI/CD / CLI        │ │
│  │  (Agents +    │  │  (Lua client  │  │  (Direct MCP call   │ │
│  │   Skills)     │  │   + UI)       │  │   or CLI wrapper)   │ │
│  └──────┬────────┘  └──────┬────────┘  └──────┬──────────────┘ │
│         │                  │                   │                │
│         └──────────────────┼───────────────────┘                │
│                            │                                    │
│                     MCP Protocol                                │
│                    (stdio or HTTP)                               │
│                            │                                    │
│  ┌─────────────────────────▼─────────────────────────────────┐  │
│  │              screw-agents-mcp (MCP Server)                │  │
│  │                                                           │  │
│  │  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐  │  │
│  │  │   Agent     │  │   Target     │  │   Output        │  │  │
│  │  │   Registry  │  │   Resolver   │  │   Formatter     │  │  │
│  │  │  (YAML →    │  │  (tree-sitter│  │  (findings →    │  │  │
│  │  │   tools)    │  │   + glob)    │  │   JSON/SARIF/   │  │  │
│  │  │             │  │              │  │   Markdown)     │  │  │
│  │  └──────┬──────┘  └──────┬───────┘  └─────────────────┘  │  │
│  │         │                │                                │  │
│  │  ┌──────▼────────────────▼──────────────────────────────┐ │  │
│  │  │           Agent Definitions (YAML files)             │ │  │
│  │  │                                                      │ │  │
│  │  │  domains/                                            │ │  │
│  │  │    injection-input-handling/    # CWE-1406/1407/1409  │ │  │
│  │  │      sqli.yaml  xpath.yaml  ssti.yaml  cmdi.yaml    │ │  │
│  │  │    access-control/             # CWE-1396            │ │  │
│  │  │      broken_access.yaml  ssrf.yaml  idor.yaml       │ │  │
│  │  │    cryptography/               # CWE-1402 + CWE-1414│ │  │
│  │  │      weak_algo.yaml  hardcoded_secrets.yaml          │ │  │
│  │  │    ...                   (18 domains from CWE-1400)  │ │  │
│  │  └──────────────────────────────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │          Project-Level Persistent State (.screw/)         │  │
│  │                                                           │  │
│  │  .screw/                                                  │  │
│  │    findings/          # Scan results (JSON + Markdown)    │  │
│  │    learning/                                              │  │
│  │      exclusions.yaml  # False positive patterns (§11.2)  │  │
│  │    custom-scripts/    # Adaptive analysis scripts (§11.1) │  │
│  │    config.yaml        # Project scan configuration        │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Why This Architecture

| Decision | Rationale |
|---|---|
| **MCP server, not embedded prompts** | Portability: one source of truth for detection logic. Improve an agent once, every client benefits. |
| **Individual agents per vulnerability** | Context window efficiency and accuracy. Focused agents carry only relevant patterns, CWEs, and examples. Claude Code subagents run in isolated context windows enabling natural parallelism. |
| **CWE-1400 taxonomy backbone** | Only established classification with completeness + mutual exclusivity + practical granularity. Every finding carries a CWE ID that maps to OWASP Top 10:2025, CAPEC, ASVS, and every major SAST tool. |
| **YAML agent definitions** | Community extensibility. Security researchers contribute new agents without touching server code. Versionable, shareable, composable. |
| **Tree-sitter target resolution in MCP server** | Clients don't reimplement function extraction. screw.nvim (Lua), Claude Code, and future clients all get the same quality. |
| **Adaptive scripts + persistent learning** | Curated YAML handles the 90% case. Adaptive scripts handle novel codebases. False positive learning ensures the system improves with use rather than producing the same noise every scan. Both are project-scoped and persist across sessions. |

---

## 4. Agent Definition Format

Each vulnerability agent is defined in a YAML file with layered knowledge:

```yaml
# domains/injections/sqli.yaml
meta:
  name: sqli
  display_name: "SQL Injection Reviewer"
  domain: injections
  version: "1.0.0"
  last_updated: "2026-03-12"
  
  # Taxonomy
  cwes:
    primary: CWE-89
    related:
      - CWE-564  # Hibernate injection
      - CWE-566  # Auth bypass via SQLi
      - CWE-943  # Improper neutralization in data query logic
  capec:
    - CAPEC-66   # SQL injection
    - CAPEC-108  # Command line execution through SQL injection
  owasp:
    top10: "A05:2025 - Injection"
    asvs: ["V5.3.4", "V5.3.5"]
    testing_guide: "WSTG-INPV-05"
    
  # Knowledge source references (for maintenance/refresh)
  sources:
    - url: "https://cwe.mitre.org/data/definitions/89.html"
      last_checked: "2026-03-01"
    - url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
      last_checked: "2026-03-01"
    # ... additional sources

core_prompt: |
  You are a SQL injection specialist performing security code review.
  
  ## What You're Looking For
  [Distilled detection heuristics — the 2,000-4,000 most important
   tokens for this vulnerability type, synthesized from all sources]

  ## Detection Patterns
  [Language-aware code patterns that indicate vulnerability]
  
  ## True Positive vs False Positive Criteria
  [Precise distinguishing factors]

  ## Severity Assessment
  [Criteria for rating severity based on exploitability and impact]

detection_heuristics:
  # Precise patterns, not vague descriptions
  high_confidence:
    - "String concatenation or f-strings containing variable references within SQL query strings"
    - "Use of ORM raw()/extra() methods with user-controlled parameters"
    - "Dynamic table or column names derived from user input"
    - "Parameterized queries where the query structure itself is dynamic"
  medium_confidence:
    - "ORM filter() with dynamically constructed field lookups"
    - "Stored procedure calls with string-interpolated parameters"
  context_required:
    - "String variables passed to query methods (need to trace data flow)"

bypass_techniques:
  # Knowledge that elevates the agent above basic pattern matching
  - name: "Second-order injection"
    description: "Data stored safely, then used unsafely in a later query"
    detection_hint: "Look for values read from DB and re-used in subsequent queries"
  - name: "ORM-specific bypasses"
    description: "Framework ORMs with unsafe methods that look safe"
    examples:
      django: "extra(), raw(), RawSQL()"
      sqlalchemy: "text(), from_statement()"
      hibernate: "createQuery() with HQL string concatenation"

remediation:
  preferred: |
    Use parameterized queries / prepared statements exclusively.
    [Specific patterns per framework]
  common_mistakes:
    - mistake: "Escaping/quoting user input instead of parameterizing"
      why_insufficient: "Bypass techniques exist for most escaping approaches"
    - mistake: "Allowlisting characters instead of parameterizing"
      why_insufficient: "Doesn't protect against second-order injection"

few_shot_examples:
  vulnerable:
    - language: python
      code: |
        # Example vulnerable pattern
        query = f"SELECT * FROM users WHERE id = {user_id}"
      explanation: "Direct f-string interpolation of user input into SQL"
  safe:
    - language: python
      code: |
        # Correct parameterized query
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
      explanation: "Parameterized query — database driver handles escaping"

target_strategy:
  # What code context this agent needs
  scope: "function"  # or "file", "class", "call_chain"
  include_imports: true
  include_type_defs: true
  file_patterns:
    - "**/*.py"
    - "**/*.java"
    - "**/*.js"
    - "**/*.ts"
    - "**/*.go"
    - "**/*.rb"
    - "**/*.php"
  relevance_signals:
    # Help target resolver find relevant code
    - "SQL"
    - "query"
    - "execute"
    - "cursor"
    - "SELECT"
    - "INSERT"
    - "UPDATE"
    - "DELETE"
    - "orm"
    - "raw"
```

---

## 5. Target Specification

All clients use a unified target spec format:

```json
// Single file
{ "type": "file", "path": "src/api/users.py" }

// Multiple files via glob
{ "type": "glob", "pattern": "src/**/*.py", "exclude": ["**/test_*"] }

// Specific function/method
{ "type": "function", "file": "src/api/users.py", "name": "get_user_by_id", "include_callees": true }

// Specific class
{ "type": "class", "file": "src/models/user.py", "name": "UserRepository" }

// Line range
{ "type": "lines", "file": "src/api/users.py", "range": [42, 87] }

// Entire codebase
{ "type": "codebase", "root": ".", "exclude": ["node_modules", ".venv", "vendor"] }

// Git diff (uncommitted changes)
{ "type": "git_diff", "staged_only": false }

// Git diff against a branch (e.g., review what changed in a feature branch)
{ "type": "git_diff", "base": "main", "head": "HEAD" }

// Pull request (requires PR number or branch name)
{ "type": "pull_request", "base": "main", "head": "feature/user-auth" }

// Specific commit or commit range
{ "type": "git_commits", "range": "abc1234..def5678" }
```

**Git-aware targeting** is arguably the most common real-world use case: "review what changed in this PR" or "scan my uncommitted changes before I push." The target resolver extracts the affected files and changed lines from `git diff`, then feeds only the relevant code (plus surrounding context for comprehension) to the agents. This dramatically reduces scan scope and cost compared to full-codebase scans while focusing on exactly the code that needs review.

The MCP server's target resolver handles:
- Reading file contents
- AST parsing via tree-sitter for function/class extraction
- Glob expansion with exclusion patterns
- Import/dependency resolution for context enrichment
- Relevance filtering using agent-defined signals
- **Git diff parsing** to extract changed files, hunks, and line ranges
- **Context expansion** around changed lines to include enough surrounding code for meaningful analysis

---

## 6. MCP Server Tools

The MCP server dynamically registers tools from agent definitions:

| Tool | Description |
|---|---|
| `list_domains` | List available security domains (18 domains derived from CWE-1400) |
| `list_agents` | List agents within a domain, or all agents |
| `scan_{agent_name}` | Run a specific agent (e.g., `scan_sqli`, `scan_ssti`) against a target |
| `scan_domain` | Run all agents in a domain against a target |
| `scan_full` | Run all agents across all domains |

Each scan tool accepts:
- `target`: Target specification (see above)
- `thoroughness`: `quick` | `standard` | `deep` (controls how much extended context is loaded)
- `output_format`: `json` | `sarif` | `markdown` | `screw_notes`

Each scan tool returns structured findings (see Section 8).

---

## 7. Claude Code Integration

### 7.1 Standalone Claude Code Experience (No screw.nvim)

When used directly in Claude Code without screw.nvim, the system provides a complete workflow:

#### Subagents (`.claude/agents/`)

```
.claude/agents/
  screw-sqli.md           # SQL injection specialist
  screw-xpath.md          # XPath injection specialist
  screw-ssti.md           # Server-side template injection
  screw-cmdi.md           # Command injection
  screw-xss.md            # Cross-site scripting
  screw-injection.md      # Domain orchestrator: all injection & input handling agents
  screw-access-control.md # Broken access control, IDOR, SSRF
  screw-crypto.md         # Cryptographic issues
  screw-full-review.md    # Runs all domains
```

Each subagent:
- Has a focused system prompt referencing the MCP tools
- Uses `Read`, `Glob`, `Grep` to discover relevant code when no specific target is given
- Calls the corresponding MCP scan tool
- Produces both conversational output AND persistent file output

#### Skills (`.claude/skills/screw-review/`)

The skill teaches Claude Code's main agent when and how to invoke security review agents automatically. It covers:
- Recognizing security review requests in natural language
- Selecting appropriate agents based on the request
- Understanding the target specification format
- Managing the review workflow across sessions

#### Output: Persistent Findings + Detailed Markdown Report

Findings are always written to the project filesystem for persistence:

```
.screw/
  findings/
    sqli-2026-03-12T14-30-00.json      # Structured findings
    sqli-2026-03-12T14-30-00.md        # Human-readable report
    injection-full-2026-03-12.md       # Domain-level report
  config.yaml                           # Project-level scan configuration
```

**The markdown report** is a detailed, standalone document containing:
- Executive summary (what was scanned, when, by which agents)
- Findings organized by severity, then by file
- For each finding: location, CWE, severity, description, vulnerable code snippet, remediation with corrected code, confidence level, false positive reasoning
- Appendix: what was scanned, what was excluded, agent versions used

This report serves as the primary deliverable in standalone Claude Code mode. The user can review it, share it with the team, or use it as input for remediation work.

#### Workflow in Claude Code

1. User: "Review src/api/ for injection vulnerabilities"
2. Main agent delegates to `screw-injection` subagent
3. Subagent uses Glob/Grep to discover relevant files in `src/api/`
4. Subagent calls `mcp__screw-agents__scan_domain` with domain=injection-input-handling
5. MCP server runs SQLi, XPath, SSTI, command injection, XSS agents in sequence
6. Findings returned to subagent
7. Subagent writes `.screw/findings/injection-2026-03-12.md` (detailed report) and `.screw/findings/injection-2026-03-12.json` (structured data)
8. Subagent presents summary conversationally, offers to apply suggested fixes
9. User reviews, asks follow-up questions, approves/rejects fixes

#### CLAUDE.md Integration

Projects using screw agents include a section in `CLAUDE.md`:

```markdown
## Security Review

This project uses screw security agents. Findings are stored in `.screw/findings/`.
When performing security review:
- Check existing findings before re-scanning to avoid duplicates
- Write new findings to `.screw/findings/` in both .json and .md format
- Use the screw MCP tools for analysis, don't attempt ad-hoc security review
```

### 7.2 screw.nvim Integration

When screw.nvim is available, the workflow adds editor-native features:

#### Review-Before-Import Workflow

This is a key UX improvement over direct import:

1. **Agent runs scan** → produces findings as structured JSON + markdown report
2. **User reviews markdown report** → reads the detailed analysis in their preferred viewer
3. **User triages findings** → marks each as `confirmed` (true positive), `false_positive`, or `needs_investigation` — either via:
   - Editing the markdown report directly (agent parses annotations)
   - A dedicated triage interface (future screw.nvim feature)
   - Interactive Claude Code conversation ("finding #3 is a false positive because...")
4. **Confirmed findings are imported** → into screw.nvim's note database via SARIF import or direct API call
5. **False positives are recorded** → stored in `.screw/exclusions.yaml` so future scans don't re-flag them

This workflow ensures that the screw.nvim database only contains validated findings, maintaining the high signal-to-noise ratio that makes the plugin useful for ongoing security review work.

#### Integration Flow

```
screw.nvim                    MCP Server                    Claude Code
    │                              │                              │
    │  :Screw scan sqli %          │                              │
    │─────────────────────────────►│                              │
    │                              │  (resolve target,            │
    │                              │   construct prompt,          │
    │                              │   call Claude API)           │
    │                              │                              │
    │  findings (JSON)             │                              │
    │◄─────────────────────────────│                              │
    │                              │                              │
    │  Generate temp report (.md)  │                              │
    │  Open in split/float         │                              │
    │  User triages findings       │                              │
    │                              │                              │
    │  :Screw import confirmed     │                              │
    │  (import to note DB)         │                              │
    │                              │                              │
    │  Signs appear in signcolumn  │                              │
    │  Notes available for review  │                              │
```

---

## 8. Output Schema

### Structured Finding

```json
{
  "id": "sqli-001-abc123",
  "agent": "sqli",
  "domain": "injections",
  "timestamp": "2026-03-12T14:30:00Z",
  
  "location": {
    "file": "src/api/users.py",
    "line_start": 42,
    "line_end": 42,
    "function": "get_user_by_id",
    "class": "UserAPI",
    "code_snippet": "query = f\"SELECT * FROM users WHERE id = {user_id}\""
  },
  
  "classification": {
    "cwe": "CWE-89",
    "cwe_name": "SQL Injection",
    "capec": "CAPEC-66",
    "owasp_top10": "A05:2025",
    "severity": "high",
    "confidence": "high"
  },
  
  "analysis": {
    "description": "User-controlled parameter `user_id` is directly interpolated into SQL query string via f-string. No parameterization or input validation is applied.",
    "impact": "An attacker can execute arbitrary SQL commands, potentially reading, modifying, or deleting database contents. Combined with UNION-based techniques, data exfiltration is likely.",
    "exploitability": "Trivially exploitable if `user_id` is derived from HTTP request parameters.",
    "false_positive_reasoning": null
  },
  
  "remediation": {
    "recommendation": "Use parameterized queries with cursor.execute().",
    "fix_code": "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
    "references": [
      "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
    ]
  },
  
  "triage": {
    "status": "pending",
    "triaged_by": null,
    "triaged_at": null,
    "notes": null
  }
}
```

### SARIF Compatibility

Findings can be exported to SARIF v2.1.0 for:
- GitHub Security tab integration
- screw.nvim SARIF import
- CI/CD pipeline integration
- Interoperability with other security tools

### Markdown Report

Each scan produces a human-readable markdown report (see Section 7.1 for details).

---

## 9. Taxonomy & Domain Architecture

### Taxonomy Decision: CWE-1400 as the Backbone

After evaluating all major vulnerability classification systems (CWE Views, OWASP Top 10, OWASP ASVS, CAPEC, SANS Top 25, NIST frameworks, STRIDE, Seven Pernicious Kingdoms, Bugcrowd VRT), the domain structure is grounded in **CWE-1400 (Comprehensive Categorization)** for three reasons:

1. **Completeness** — Every one of CWE's ~944 weaknesses is assigned to exactly one category
2. **Mutual exclusivity** — No overlap between categories, so there is no ambiguity about which agent "owns" a finding
3. **Practical granularity** — 21 categories is the right level: each is substantive enough for agent specialization, none is so broad that an agent cannot develop deep expertise

No other taxonomy achieves all three. OWASP Top 10:2025 has only 10 categories (too coarse — "Broken Access Control" alone covers 40+ CWEs). OWASP ASVS v5.0 is excellent but web-only. CAPEC classifies attacks, not code weaknesses. CWE-699 (Software Development view) has ~40 categories but they overlap. CWE-1000 (Research Concepts) has only 10 pillars, each far too abstract.

### Multi-Layer Architecture

The system uses CWE-1400 as its structural backbone, with additional taxonomies as overlays:

| Layer | Taxonomy | Purpose |
|---|---|---|
| **Structure** | CWE-1400 (21 categories) | Agent domain organization — which agent handles what |
| **Risk communication** | OWASP Top 10:2025 | Stakeholder reporting — mapping findings to the categories executives and auditors recognize |
| **Verification depth** | OWASP ASVS v5.0 (17 chapters) | Determining thoroughness levels — what to check at each assurance level |
| **Prioritization** | CWE/SANS Top 25 (2024) | Build order — which agents to invest in first |
| **Attack context** | CAPEC | Enrichment — how each weakness is exploited in practice |
| **Universal join key** | CWE IDs | Every finding carries its CWE ID, enabling mapping to all other taxonomies |

### Domain-to-Agent Mapping (from CWE-1400)

| # | Agent Domain | CWE-1400 ID | Key CWEs Covered | OWASP Top 10:2025 Alignment |
|---|---|:-:|---|---|
| 1 | **Access Control** | CWE-1396 | CWE-284, CWE-862, CWE-863, CWE-269, CWE-918 | A01 Broken Access Control |
| 2 | **Comparison** | CWE-1397 | CWE-697, CWE-185, CWE-1254 | (Cross-cutting) |
| 3 | **Component Interaction** | CWE-1398 | CWE-435, CWE-436 | A08 Software/Data Integrity |
| 4 | **Memory Safety** | CWE-1399 | CWE-787, CWE-125, CWE-416, CWE-119 | (Not in Top 10) |
| 5 | **Concurrency** | CWE-1401 | CWE-362, CWE-367, CWE-421 | (Not in Top 10) |
| 6 | **Cryptography** *(merged: Encryption + Randomness)* | CWE-1402, CWE-1414 | CWE-327, CWE-326, CWE-311, CWE-330, CWE-338 | A04 Cryptographic Failures |
| 7 | **Exposed Resource** | CWE-1403 | CWE-610, CWE-668 | A01 (partial, SSRF now under Broken Access Control) |
| 8 | **File Handling** | CWE-1404 | CWE-434, CWE-22, CWE-73 | A01 (partial) |
| 9 | **Exceptional Conditions** | CWE-1405 | CWE-754, CWE-755, CWE-252, CWE-476 | A10 Mishandling of Exceptional Conditions |
| 10 | **Injection & Input Handling** *(merged: Input Validation + Neutralization + Injection)* | CWE-1406, CWE-1407, CWE-1409 | CWE-79, CWE-89, CWE-78, CWE-77, CWE-94, CWE-20, CWE-502 | A05 Injection |
| 11 | **Incorrect Calculation** | CWE-1408 | CWE-682, CWE-190, CWE-369 | (Not in Top 10) |
| 12 | **Control Flow Management** | CWE-1410 | CWE-691, CWE-835, CWE-674 | (Not in Top 10) |
| 13 | **Data Authenticity Verification** | CWE-1411 | CWE-345, CWE-346, CWE-347 | A08 Software/Data Integrity |
| 14 | **Coding Practices & Design** | CWE-1412 | CWE-710, CWE-477, CWE-1164 | A06 Insecure Design |
| 15 | **Protection Mechanism Failure** | CWE-1413 | CWE-693, CWE-307, CWE-522, CWE-287 | A07 Authentication Failures |
| 16 | **Resource Control** | CWE-1415 | CWE-400, CWE-770, CWE-920 | A02 Security Misconfiguration (partial) |
| 17 | **Resource Lifecycle Management** | CWE-1416 | CWE-404, CWE-401, CWE-772 | (Not in Top 10) |
| 18 | **Sensitive Information Exposure** | CWE-1417 | CWE-200, CWE-209, CWE-532, CWE-798 | A04 (partial), A09 Logging Failures (partial) |

> **Note on merges:** Three practical merges reduce the 21 CWE-1400 categories to **18 agent domains**: (a) Encryption + Randomness → Cryptography (insecure randomness is almost always a crypto concern); (b) Input Validation + Improper Neutralization + Injection → Injection & Input Handling (these three are tightly coupled — neutralization failures and injection attacks are consequences of input validation failures); (c) The original CWE-1400 category names are preserved in the CWE-1400 ID column for traceability.

### OWASP Top 10:2025 Reference

For stakeholder communication, every finding maps to the current OWASP Top 10:2025:

| # | OWASP Top 10:2025 Category | Key Changes from 2021 |
|---|---|---|
| A01 | Broken Access Control | SSRF (was A10:2021) consolidated here; 40 mapped CWEs |
| A02 | Security Misconfiguration | Moved from #5 to #2; affects ~3% of tested apps |
| A03 | **Software Supply Chain Failures** | **NEW** — expands 2021's "Vulnerable Components" to full supply chain |
| A04 | Cryptographic Failures | Was A02:2021; shifted down but same scope |
| A05 | Injection | Was A03:2021; shifted down but remains critical |
| A06 | Insecure Design | Was A04:2021; emphasis on root-cause design flaws |
| A07 | Authentication Failures | Renamed from "Identification and Authentication Failures" |
| A08 | Software or Data Integrity Failures | Same as 2021 |
| A09 | Security Logging & Alerting Failures | Renamed to emphasize alerting, not just logging |
| A10 | **Mishandling of Exceptional Conditions** | **NEW** — error handling, fail-open, logical errors (24 CWEs) |

### Agent Registry: Phased Build Order

Build order is driven by CWE/SANS Top 25 prevalence data and OWASP Top 10:2025 risk ranking.

#### Phase 1 — MVP (4 agents, highest-impact injection types)

| Agent Domain | Specific Agent | Primary CWEs | Top 25 Rank | OWASP:2025 |
|---|---|---|:-:|---|
| Injection & Input Handling | SQL Injection | CWE-89 | #3 | A05 |
| Injection & Input Handling | Command Injection | CWE-78 | #7 | A05 |
| Injection & Input Handling | Server-Side Template Injection | CWE-1336 | — | A05 |
| Injection & Input Handling | XSS (Reflected/Stored/DOM) | CWE-79 | #1 | A05 |

#### Phase 2 — Core expansion (8 agents across multiple domains)

| Agent Domain | Specific Agent | Primary CWEs | Top 25 Rank | OWASP:2025 |
|---|---|---|:-:|---|
| Injection & Input Handling | XPath Injection | CWE-643 | — | A05 |
| Injection & Input Handling | Insecure Deserialization | CWE-502 | #15 | A05/A08 |
| Access Control | Broken Access Control (IDOR, privilege escalation) | CWE-862, CWE-863, CWE-284 | #11, #16 | A01 |
| Access Control | SSRF | CWE-918 | #19 | A01 |
| Cryptography | Weak Algorithms + Hardcoded Secrets | CWE-327, CWE-798 | — , #18 | A04 |
| Protection Mechanism Failure | Authentication Failures | CWE-287, CWE-307, CWE-522 | #13 | A07 |
| File Handling | Path Traversal | CWE-22 | #5 | A01 |
| Sensitive Information Exposure | Sensitive Data Exposure / Verbose Errors | CWE-200, CWE-209 | — | A04/A09 |

#### Phase 3+ — Full coverage expansion

| Agent Domain | Specific Agent(s) | Primary CWEs | OWASP:2025 |
|---|---|---|---|
| Injection & Input Handling | LDAP, NoSQL, Header, Log injection | CWE-90, CWE-943, CWE-113, CWE-117 | A05 |
| Data Authenticity Verification | CSRF, JWT validation | CWE-352, CWE-347 | A08 |
| Exceptional Conditions | Error handling, fail-open logic | CWE-754, CWE-755, CWE-209 | A10 |
| Concurrency | Race conditions, TOCTOU | CWE-362, CWE-367 | — |
| Memory Safety | Buffer overflow, use-after-free | CWE-787, CWE-125, CWE-416 | — |
| Resource Control | DoS, resource exhaustion | CWE-400, CWE-770 | A02 |
| Coding Practices & Design | Insecure design patterns | CWE-710 | A06 |
| Component Interaction | XXE, unsafe reflection | CWE-611, CWE-470 | A08 |
| Sensitive Information Exposure | Hardcoded credentials, log leakage | CWE-798, CWE-532 | A04/A09 |
| (Mobile — OWASP MASVS overlay) | Insecure storage, insecure communication | MASVS-STORAGE, MASVS-NETWORK | — |

---

## 10. Knowledge Engineering Strategy

### The Core Challenge

The quality of each agent is directly proportional to the quality of its distilled knowledge. Generic prompts produce generic results. The competitive advantage of this system comes from thorough, expert-level knowledge synthesis optimized for LLM consumption.

### Source Hierarchy

**Tier 1 — Normative Standards (Taxonomic Backbone)**
- CWE definitions (full XML entries with relationships, not summaries)
- OWASP ASVS verification requirements (structured as testable assertions)
- CAPEC attack patterns (exploitation methodology)
- OWASP MASVS (mobile-specific requirements)

**Tier 2 — Testing Methodology (What To Look For)**
- OWASP Testing Guide v4.2+ (step-by-step procedures for probing running applications)
- [OWASP Code Review Guide v2](https://owasp.org/www-project-code-review-guide/assets/OWASP_Code_Review_Guide_v2.pdf) — despite dating from 2017, this is the most directly relevant OWASP resource for this project. Unlike the Testing Guide (which covers external probing), the Code Review Guide teaches how to *read source code* and identify vulnerabilities: tracing data flow, identifying trust boundaries, assessing authorization logic by reading controllers. Its methodology chapters translate directly into agent instructions regardless of framework vintage. The dated framework-specific patterns (Java/C# circa 2017) are less useful, but the systematic approach to code-level review is timeless.
- SANS Top 25 (prioritization context)
- OWASP Cheat Sheet Series (both detection and remediation)

**Tier 3 — Real-World Intelligence (What Separates Good from Great)**
- CVE databases filtered by vulnerability type
- Security research blogs (Trail of Bits, Project Zero, PortSwigger, Snyk, Doyensec, NCC Group)
- Conference presentations (BlackHat, DEF CON, OWASP AppSec)
- Semgrep rule registry (thousands of pattern-matched rules → code shapes to look for)
- CodeQL query suites (same idea, different formalism)

**Tier 4 — Existing LLM Security Skills (Standing on Shoulders)**
- Trail of Bits SKILL.md / prompts for code review
- Shannon framework for LLM security review
- VibeSec-Skill for Claude Code
- [SpecterOps secure code review methodology](https://specterops.io/blog/2026/03/26/leveling-up-secure-code-reviews-with-claude-code/) + [code-review-prompts](https://github.com/Sw4mpf0x/code-review-prompts) — practitioner methodology from a pentest team: use Claude Code to understand code structure, data flow, and async workers rather than asking it to "find vulns"; includes system prompts with application context, security boundary definitions, and targeted analysis patterns that reduce false positives
- [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review) — Anthropic's official security review GitHub Action with prompt templates (`prompts.py`), false positive filtering logic (`findings_filter.py`), and evaluation framework
- Various Claude Code security skills scattered across GitHub
- Semgrep/CodeQL rule descriptions (natural language → detection hints)

### Synthesis Principles

1. **Distill, don't concatenate.** Each agent needs 2,000-4,000 tokens of knowledge, not 50,000 tokens of raw source material.
2. **Prioritize precision over breadth.** A few highly specific detection patterns beat a long list of vague guidelines.
3. **Language-aware patterns.** "String concatenation in SQL" is vague. "f-string interpolation in Python cursor.execute()" is actionable.
4. **Include bypass techniques.** What defeats common mitigations is the knowledge that elevates analysis above basic pattern matching.
5. **Real-world grounding.** Reference actual CVEs and exploits to anchor abstract vulnerability descriptions in concrete examples.
6. **Maintenance metadata.** Every agent records its sources and last-updated dates for systematic refresh.

### Research & Build Process

For each vulnerability type:

1. **Collect** — Gather all relevant material from tiers 1-4
2. **Analyze** — Identify the most impactful detection signals, common patterns, bypass techniques
3. **Synthesize** — Distill into the YAML agent format (core prompt, detection heuristics, bypass techniques, remediation, few-shot examples)
4. **Validate** — Test against known-vulnerable codebases (WebGoat, DVWA, Juice Shop, damn-vulnerable-apps)
5. **Measure** — Track detection rate and false positive rate
6. **Iterate** — Refine prompt based on validation results
7. **Document** — Record which sources contributed which knowledge, for future maintenance

---

## 11. Adaptive Analysis & Persistent Learning

The curated YAML agent definitions handle the well-known vulnerability patterns — the 90% case. Two complementary systems handle the remaining 10% and ensure the system improves with use rather than stagnating.

### 11.1 Adaptive Analysis Scripts

**Problem:** Every codebase has idiosyncratic patterns — custom ORM wrappers, in-house templating engines, proprietary auth middleware, unusual framework configurations. The static YAML agents cannot anticipate these. When an agent encounters an unfamiliar framework or pattern, it either misses the vulnerability entirely or produces a generic, unhelpful finding.

**Solution:** When standard agents come up empty or produce low-confidence results, the Claude Code subagent (or the MCP server, depending on architecture) can enter an **adaptive analysis mode**: it examines the actual code structure, identifies the unfamiliar pattern, and writes a targeted analysis script to trace data flow or check security properties through that specific abstraction.

**How it works:**

1. **Detection of novelty** — The standard agent scans and finds nothing, but the code clearly handles user input (e.g., a custom `QueryBuilder` class wrapping raw SQL). The agent recognizes the gap: "I found user input flowing into `QueryBuilder.execute()`, but this isn't a pattern I have heuristics for."

2. **Exploration** — The agent reads the source of the unfamiliar abstraction (the `QueryBuilder` class itself), understands its internals, and determines whether it safely parameterizes queries or simply concatenates strings.

3. **Script generation** — If needed, the agent writes a targeted Python analysis script. For example: a script that uses tree-sitter to find all call sites of `QueryBuilder.execute()`, traces the arguments back to their sources, and flags cases where user input reaches the query without passing through the builder's parameterization API.

4. **Execution and reporting** — The script runs, producing structured findings in the same JSON format as standard agents.

5. **Persistence** — The working script is saved to `.screw/custom-scripts/` with metadata describing what it does, which codebase patterns it targets, and when it was created. Next time the agent scans this project, it loads and reuses the script rather than re-discovering the pattern.

**Storage structure:**

```
.screw/
  custom-scripts/
    querybuilder-sqli-check.py     # The analysis script
    querybuilder-sqli-check.meta.yaml  # Metadata
```

**Metadata format:**

```yaml
name: querybuilder-sqli-check
created: "2026-03-15T10:30:00Z"
created_by: screw-sqli-agent
domain: injection-input-handling
description: >
  Traces data flow through custom QueryBuilder class in this project.
  Checks whether user input reaches QueryBuilder.execute() without
  passing through .param() or .bind() methods.
target_patterns:
  - "QueryBuilder"
  - "execute()"
validated: false   # Set to true after human review
last_used: "2026-03-15T10:30:00Z"
findings_produced: 3
false_positive_rate: null  # Updated after triage
```

**Key design constraints:**

- **Sandboxed execution** — Custom scripts run in a restricted environment. They can read source files and perform static analysis, but cannot make network calls, modify files, or execute arbitrary code outside their analysis scope.
- **Human review gate** — Scripts are marked `validated: false` by default. In screw.nvim's review-before-import workflow, the user can inspect the script before trusting its output. In Claude Code, the agent presents the script and asks for confirmation before saving it for reuse.
- **Not a replacement for YAML agents** — Adaptive scripts supplement the curated knowledge, they don't replace it. The YAML agents remain the primary analysis path. Adaptive scripts fire only when the standard agents identify a gap.
- **Cross-session but project-scoped** — Scripts are saved per-project in `.screw/custom-scripts/`. They don't leak across projects because each codebase's custom patterns are unique.

**Client integration:**

| Client | Adaptive Script Support |
|---|---|
| **Claude Code** | Full support — Claude Code subagents can write, execute, and save scripts natively. The skill SKILL.md instructs the agent on when to enter adaptive mode and how to persist scripts. |
| **screw.nvim** | Trigger via `:Screw scan --adaptive` flag. The MCP server generates the script, screw.nvim displays it for review, and upon approval saves it to `.screw/custom-scripts/`. |
| **CI/CD** | Only runs pre-validated scripts (`validated: true`). Never generates new scripts in automated pipelines — script discovery happens in interactive sessions only. |

### 11.2 Persistent Learning from False Positives

**Problem:** Every SAST-like system suffers from false positive fatigue. The first scan of a codebase produces 50 findings. The user triages them and discovers 15 are false positives — safe patterns that the agent misclassified. On the next scan, the same 15 false positives appear again. Over time, the user stops trusting the system.

**Solution:** When a user triages a finding as a false positive, the system captures *why* it was a false positive and stores this knowledge in a project-level exclusion and learning database. Future scans consult this database before reporting, suppressing known false positives and refining confidence scores for similar patterns.

**How it works:**

**Step 1: Triage capture** — During the review-before-import workflow (in both Claude Code and screw.nvim), when the user marks a finding as a false positive, the system prompts for a brief reason:

```
Finding: Potential SQLi in user_service.py:42
         query = db.text_search(user_input)

Mark as: [x] False positive

Reason (optional but improves learning):
> db.text_search() uses full-text search with parameterized queries internally
```

**Step 2: Exclusion storage** — The finding, its context, and the reason are stored in `.screw/learning/exclusions.yaml`:

```yaml
exclusions:
  - id: "fp-2026-03-15-001"
    created: "2026-03-15T11:00:00Z"
    created_by: "h0pes"
    agent: "sqli"
    
    # What was flagged
    finding:
      file: "src/services/user_service.py"
      line: 42
      code_pattern: "db.text_search(*)"
      cwe: "CWE-89"
    
    # Why it's a false positive
    reason: "db.text_search() uses full-text search with parameterized queries internally"
    
    # How broadly to apply this exclusion
    scope:
      type: "pattern"  # "exact_line" | "pattern" | "function" | "file"
      pattern: "db.text_search(*)"  # Suppress this pattern project-wide
    
    # Tracking
    times_suppressed: 0
    last_suppressed: null
```

**Step 3: Pre-scan filtering** — Before reporting findings, the MCP server checks the exclusions database. Findings matching an exclusion pattern are either suppressed entirely or reported with a `suppressed: true` flag and a reference to the exclusion reason. The markdown report includes a section showing how many findings were suppressed and why.

**Step 4: Learning aggregation** — Over time, the exclusions database reveals patterns about the project's security posture:

- "This project consistently uses `db.text_search()` safely — the SQLi agent should lower confidence for this pattern"
- "All findings in `test/` directories are marked false positive — future scans should exclude test files by default"
- "The team always confirms findings in `src/api/public/` — these are high-value scan targets"

This aggregated learning can be surfaced as suggestions: "Based on your triage history, I recommend adding `test/**` to the scan exclusion list. All 12 findings in test directories were marked as false positives."

**Exclusion scope levels:**

| Scope | Effect | Example |
|---|---|---|
| `exact_line` | Suppress only this specific finding at this specific line | One-off false positive due to unusual context |
| `pattern` | Suppress all findings matching a code pattern | `db.text_search(*)` is always safe in this project |
| `function` | Suppress findings within a specific function | `sanitize_input()` is a known-safe wrapper |
| `file` | Suppress findings in a specific file | Generated/vendored code |
| `directory` | Suppress findings in a directory | `test/`, `vendor/`, `migrations/` |

**Integration with screw.nvim's existing note system:**

False positive triage integrates naturally with screw.nvim's existing `state` field. Notes with `state: not_vulnerable` already represent confirmed false positives. The learning system reads these and automatically builds exclusion patterns. When using screw.nvim in collaboration mode (HTTP/PostgreSQL backend), the exclusions database is shared across the team — one analyst's triage benefits everyone.

**Feedback loop to agent improvement:**

The exclusions database also serves as a **signal for agent YAML refinement**. If a particular pattern generates false positives across multiple projects, that's evidence the agent's detection heuristics need updating. Periodically (or on demand), the system can generate a "false positive report" showing the most common suppression patterns, which informs the next iteration of the YAML agent definitions. This closes the loop: curated knowledge → scan → triage → learning → improved curated knowledge.

### 11.3 Autoresearch: Self-Improving Agents

**Inspiration:** This capability is inspired by Karpathy's [autoresearch](https://github.com/karpathy/autoresearch) pattern — an autonomous loop where an AI agent modifies code, runs an experiment, measures results against a fitness function, keeps improvements, discards regressions, and repeats. In autoresearch, the human programs the *research strategy* (`program.md`), not the code itself. The agent programs the code.

**Applied to screw-agents:** The agent modifies its own YAML definition (detection heuristics, prompt structure, few-shot examples, confidence thresholds) → runs the modified agent against a benchmark suite of labeled vulnerable code → measures true positive rate, false positive rate, and overall accuracy → keeps the change if metrics improved, discards if they regressed → repeats.

#### The Fitness Function: SAST Benchmarks

Autoresearch requires ground-truth labeled codebases where every vulnerability is annotated with its CWE, location, and whether it's a true positive or false alarm. The agent scores itself objectively against these benchmarks.

**Benchmark selection criteria:**
- Must be based on **real-world vulnerabilities** (actual CVEs from production projects), not synthetic test cases
- Must include both **vulnerable and patched versions** so the agent tests detection AND precision
- Must cover **multiple languages** — the OWASP Benchmark (Java-only, synthetic) is explicitly excluded as insufficient
- Must provide **SARIF or equivalent ground-truth markup** for automated scoring

**Primary benchmark sources:**

| Benchmark | Description | Languages | Suitability |
|---|---|---|---|
| [flawgarden/reality-check](https://github.com/flawgarden/reality-check) | 165+ CVEs from real industry projects with SARIF ground-truth markup, vulnerable + fixed versions | Java, C#, Go, Python | Primary benchmark — real-world, multi-language |
| [flawgarden/BenchmarkJava-mutated](https://github.com/flawgarden/BenchmarkJava-mutated) | Enhanced OWASP Benchmark with selective fuzzing and Java language feature enrichment | Java | Supplementary — better than vanilla OWASP Benchmark |
| CVE-based benchmarks per the [SMU research methodology](https://ink.library.smu.edu.sg/cgi/viewcontent.cgi?article=9979&context=sis_research) | Language-agnostic approach to building CVE benchmarks | Language-agnostic | Framework for building new benchmarks in uncovered languages |
| DVWA, WebGoat, Juice Shop | Intentionally vulnerable web apps | PHP, Java, JS | Manual validation — not structured for automated scoring but useful for qualitative assessment |

**Critical gap — language coverage:** The current benchmark landscape has strong coverage for Java, Python, Go, and C#, but significant gaps exist for Rust, TypeScript/modern JS frameworks, Kotlin, Swift, and others. For uncovered languages, the system should:
1. Use the SMU research methodology to build CVE-based benchmarks from real vulnerabilities in those ecosystems (e.g., Rust advisory database: [RustSec](https://rustsec.org/))
2. Create synthetic but realistic test fixtures as a stopgap, clearly labeled as "synthetic" with lower confidence in autoresearch results
3. Leverage the multi-LLM challenger (§11.4) as a supplementary quality signal when benchmark coverage is thin

#### The Autoresearch Loop

```
┌─────────────────────────────────────────────────────────┐
│                 AUTORESEARCH LOOP                        │
│                                                         │
│  ┌──────────┐    ┌──────────┐    ┌───────────────────┐  │
│  │  MUTATE  │───►│ EVALUATE │───►│    GATE           │  │
│  │          │    │          │    │                   │  │
│  │ Propose  │    │ Run agent│    │ Score improved?   │  │
│  │ change   │    │ against  │    │ ┌─YES→ Keep      │  │
│  │ to YAML  │    │ benchmark│    │ └─NO → Discard   │  │
│  │ agent    │    │ suite    │    │                   │  │
│  └──────────┘    └──────────┘    └────────┬──────────┘  │
│       ▲                                   │             │
│       │           ┌──────────┐            │             │
│       └───────────│   LOG    │◄───────────┘             │
│                   │          │                          │
│                   │ Record   │                          │
│                   │ experiment│                          │
│                   │ & metrics │                          │
│                   └──────────┘                          │
│                                                         │
│  ADDITIONAL INPUTS:                                     │
│  ← False positive exclusion data (§11.2)               │
│  ← Multi-LLM challenger disagreements (§11.4)          │
│  ← New security research (web search for CVEs, blogs)  │
└─────────────────────────────────────────────────────────┘
```

**Step 1 — Mutate:** The agent proposes a specific modification to the YAML agent definition. Types of mutations include:
- Adding a new detection heuristic (e.g., "Django `extra()` with user input")
- Refining a prompt section for clearer instructions
- Adjusting confidence thresholds (e.g., moving a pattern from `medium_confidence` to `high_confidence`)
- Adding a new few-shot example (vulnerable or safe)
- Adding a bypass technique discovered from recent CVEs
- Removing or downweighting a heuristic that correlates with false positives

**Step 2 — Evaluate:** Run the modified agent against the full benchmark suite for that vulnerability type. Compute:
- True Positive Rate (TPR): % of real vulnerabilities correctly identified
- False Positive Rate (FPR): % of safe code incorrectly flagged
- Accuracy Score: TPR − FPR (the standard SAST benchmark metric)
- Token efficiency: total tokens consumed per finding (lower is better at equal accuracy)

**Step 3 — Gate:** Compare scores against the baseline (the current production YAML). If accuracy improved (or maintained with reduced token count), the change is a candidate for approval. If accuracy regressed, discard.

**Step 4 — Log:** Every experiment is recorded in `.screw/autoresearch/experiments.log`:

```yaml
- id: "exp-sqli-2026-04-01-007"
  agent: "sqli"
  timestamp: "2026-04-01T03:15:00Z"
  mutation:
    type: "add_heuristic"
    description: "Added detection for Django extra() with user-controlled kwargs"
    diff: |
      + - "Django ORM extra(where=[...]) or extra(select={...}) with user-derived parameters"
  baseline_score:
    tpr: 0.82
    fpr: 0.15
    accuracy: 0.67
  new_score:
    tpr: 0.85
    fpr: 0.14
    accuracy: 0.71
  result: "improvement"
  status: "pending_review"  # awaiting human approval
```

**Step 5 — Human review gate:** The autoresearch loop proposes changes but does **not** autonomously commit them to production YAML files. Proposed improvements are batched into a "research report" that a human reviews and selectively approves. This mirrors how actual security research works — you don't deploy a new detection rule without peer review. The report surfaces:
- Which experiments were run
- Which mutations improved metrics and by how much
- The specific YAML diffs for each proposed change
- Any trade-offs (e.g., "TPR +3% but FPR +1%")

**Step 6 — Repeat:** The loop continues, either on-demand or scheduled.

#### Execution Modes

| Mode | Trigger | Use Case |
|---|---|---|
| **On-demand** | User runs `/screw autoresearch sqli --iterations 20` | Initial agent development, targeted optimization after discovering a gap |
| **Scheduled** | Cron/CI job runs nightly or weekly | Ongoing maintenance — incorporates new CVEs, responds to drift |
| **Research-triggered** | New CVE published for a covered CWE → autoresearch picks it up | Keeping agents current with emerging threats |

#### Input Signals (Beyond Benchmarks)

The autoresearch loop is most powerful when it combines multiple quality signals:

1. **Benchmark scores** — The primary, objective fitness function
2. **False positive exclusion data (§11.2)** — Patterns that users consistently mark as FP indicate heuristics that need refinement. If exclusion `db.text_search(*)` is suppressed across 5 projects, the autoresearch loop should try reducing confidence for that pattern
3. **Multi-LLM challenger disagreements (§11.4)** — When Claude and Codex disagree on a benchmark case, that case becomes a high-priority target for heuristic refinement. Disagreement signals ambiguity in the current detection logic
4. **New security research** — The agent can search for recently published CVEs, security advisories, and bypass techniques (via web search), synthesize findings, and propose YAML updates. This is the "knowledge currency" function

#### Qualitative Limitations

Benchmark metrics measure *whether* the agent finds vulnerabilities and avoids false positives. They do not measure *how well* the agent explains its findings, *how correct* the remediation suggestions are, or *how useful* the analysis is to a human reviewer. These qualitative dimensions still require periodic human review — the autoresearch loop optimizes the quantitative signal, and human review ensures the qualitative output doesn't degrade.

### 11.4 Multi-LLM Adversarial Challenger

**Problem:** Any single-LLM analysis has blind spots. Claude might confidently flag something that isn't exploitable, or miss a subtle vulnerability that a different model's training data emphasized. There's no way to calibrate confidence from a single opinion.

**Solution:** A **challenger system** that sends findings to an independent LLM for adversarial peer review. When both models agree, confidence is high. When they disagree, the disagreement is surfaced for human attention and fed into the autoresearch loop.

#### Challenger Architecture

The system defines a **provider-agnostic challenger interface** — a standardized way to send a finding (code + analysis + classification + remediation) to any LLM and receive a structured assessment back. Providers are pluggable:

> **Implementation note:** OpenAI has published [codex-plugin-cc](https://github.com/openai/codex-plugin-cc), an official Claude Code plugin that invokes Codex from within Claude Code for adversarial code review (`/codex:adversarial-review`) and task delegation (`/codex:rescue`). It also features a `Stop` hook-based review gate that creates a live Claude/Codex adversarial loop. During implementation, this plugin should be cross-referenced as both a proof-of-concept validation of our challenger approach and a potential transport layer for the Codex adapter — it handles invocation, background job management, and result retrieval. Our system layers security-specific challenger prompts, structured reconciliation logic, and autoresearch feedback on top. The provider-agnostic interface remains the architectural contract to ensure adding future providers (Gemini, etc.) is a config-level change.

```yaml
# .screw/config.yaml
challenger:
  enabled: false  # opt-in per analysis
  providers:
    - name: "openai-codex"
      type: "openai"
      model: "codex"  # or specific model version
      api_key_env: "OPENAI_API_KEY"
      priority: 1
    # Future providers — adding a new LLM is just a config entry
    # - name: "google-gemini"
    #   type: "google"
    #   model: "gemini-2.5-pro"
    #   api_key_env: "GOOGLE_API_KEY"
    #   priority: 2
  
  # When to invoke the challenger
  trigger:
    mode: "on-demand"  # "on-demand" | "severity-gated" | "all-findings"
    min_severity: "high"  # for severity-gated mode
  
  # Cost disclaimer acknowledged
  cost_acknowledged: false  # must be set to true before first use
```

#### Challenge Flows

Three operational modes, selectable by the user:

**Mode 1 — Primary + Challenger (default):**
1. Claude-powered agent produces findings with full analysis
2. Each finding (code, reasoning, CWE, severity, remediation) is sent to the challenger with a peer review prompt
3. Challenger returns its independent assessment
4. System reconciles: agreement strengthens finding, disagreement is flagged

**Mode 2 — Reverse Direction:**
1. Codex runs the primary analysis (using the same agent YAML knowledge base, delivered as a system prompt)
2. Claude reviews Codex's findings as challenger
3. Same reconciliation logic

**Mode 3 — Parallel Independent + Cross-Validation:**
1. Both Claude and Codex run independent analyses simultaneously
2. Each model's findings are submitted to the other for challenge
3. System produces a consolidated finding list:
   - **Agreed True Positives** — Both models found it, high confidence
   - **Agreed False Negatives** — Neither found it (only detectable against benchmarks)
   - **Disputed Findings** — One model found it, the other disagrees — surfaced with both perspectives for human triage
   - **Unique Findings** — Found by only one model, not disputed (challenger was uncertain rather than disagreeing)

#### Challenger Prompt Design

The challenger prompt is designed to avoid anchoring bias while still being constructive:

```
You are an independent security expert performing peer review.
You have no prior relationship with the analyst who produced this finding.

A security review agent reported the following finding:

[FINDING: code, location, CWE, severity, analysis, remediation]

Your task:
1. EXPLOITABILITY: Is this vulnerability real and exploitable in context?
   Provide specific reasoning. If not exploitable, explain which defense
   prevents exploitation.
2. SEVERITY: Is the severity assessment accurate? If you disagree,
   state your assessment with justification.
3. REMEDIATION: Does the proposed fix actually resolve the issue? Does
   it introduce new problems? Is there a better approach?
4. GAPS: Did the original analysis miss anything? Additional attack
   vectors, bypass techniques, or related vulnerabilities?

Respond with a structured assessment including your confidence level
(agree/disagree/uncertain) for each dimension.
```

#### Output: Enriched Finding Report

When the challenger is active, the markdown report and structured findings include both perspectives:

```json
{
  "id": "sqli-001",
  "primary_analysis": { /* Claude's finding */ },
  "challenger_assessment": {
    "provider": "openai-codex",
    "exploitability": {
      "verdict": "agree",
      "confidence": "high",
      "reasoning": "Confirmed — user_id parameter flows directly from request.args to query without sanitization."
    },
    "severity": {
      "verdict": "disagree",
      "original": "high",
      "challenger_assessment": "medium",
      "reasoning": "The endpoint requires admin authentication (see middleware at line 15), limiting the attack surface to authenticated admin users."
    },
    "remediation": {
      "verdict": "agree",
      "notes": "Parameterized query is correct. Additionally recommend adding input type validation — user_id should be integer-only."
    },
    "gaps": "Original analysis did not note that the same pattern exists in get_user_by_email() at line 67."
  },
  "consensus": {
    "exploitable": true,
    "agreed_severity": "medium",  # downgraded based on challenger reasoning
    "confidence": "high",
    "additional_findings": ["sqli-001b"]  # new finding from gap analysis
  }
}
```

#### Integration with Autoresearch (§11.3)

Challenger disagreements are a high-value signal for the autoresearch loop:

- If Claude flags a pattern and Codex consistently disagrees (across multiple benchmark cases), the detection heuristic for that pattern likely needs refinement — it may be too aggressive
- If Codex finds vulnerabilities that Claude misses, those cases become priority targets for adding new heuristics to the YAML definition
- The autoresearch loop can run experiments specifically targeting "disagreement cases" — mutations that aim to resolve the disagreement by improving Claude's detection on cases where Codex was right and Claude was wrong

This creates a **three-way feedback loop**: benchmark metrics + challenger disagreements + false positive triage data all converge to drive agent improvement.

#### Cost and User Experience

- **Opt-in only** — The challenger is never activated by default. The user explicitly enables it per analysis
- **Cost disclaimer** — Before first use, the system displays a clear notice: "Multi-LLM analysis will send findings to [provider] via their API. This incurs additional API costs. Your code context will be shared with the challenger provider. Do you want to proceed?" The user must acknowledge (`cost_acknowledged: true` in config)
- **Configurable trigger** — Users can choose to challenge all findings, only high-severity findings, or specific findings on demand
- **Provider-agnostic design** — Adding a new LLM provider (e.g., Gemini) requires only a new config entry and a thin API adapter. The challenger interface, prompt design, and reconciliation logic are provider-agnostic

---

## 12. Implementation Plan (High-Level Phases)

### Phase 0: Knowledge Research Sprint
- Systematic discovery of existing security skills, frameworks, and prompt libraries
- Deep research on Phase 1 vulnerability types (SQLi, command injection, SSTI, XSS)
- Source collection from all four tiers
- Synthesis into draft agent YAML definitions
- Validation of CWE-1400 domain mapping against real codebases

### Phase 1: Core Infrastructure
- Build MCP server skeleton (Python, FastAPI or stdio)
- Implement agent registry (YAML loading → MCP tool registration, CWE-1400 domain structure)
- Implement target resolver (tree-sitter for function/class extraction, glob for file discovery, **git diff parsing**)
- Implement output formatter (JSON, SARIF, Markdown)
- Create 4 initial agent definitions from Phase 0 research (SQLi, command injection, SSTI, XSS)
- Test standalone with `claude --mcp-config`

### Phase 2: Claude Code Integration
- Create subagent markdown files for each agent + domain orchestrators
- Create skill SKILL.md for auto-invocation
- Implement filesystem output (`.screw/findings/` reports)
- Create `CLAUDE.md` template for projects using screw agents
- **Implement persistent learning: `.screw/learning/exclusions.yaml` storage and pre-scan filtering**
- End-to-end testing in Claude Code

### Phase 3: screw.nvim Integration
- Add `:Screw scan` commands (calls MCP server)
- Implement review-before-import workflow:
  - Temp report generation and display
  - Finding triage interface (confirm/reject/investigate)
  - **False positive reason capture during triage**
  - Import confirmed findings to screw.nvim DB
- SARIF bridge for findings import/export
- **Integrate exclusions with screw.nvim's `not_vulnerable` state — auto-populate exclusions from existing notes**

### Phase 4: Adaptive Analysis & Learning Refinement
- **Implement adaptive analysis script generation in Claude Code subagents**
- **Script sandboxing and persistence (`.screw/custom-scripts/`)**
- **Human review gate for custom scripts (validated flag)**
- **screw.nvim `:Screw scan --adaptive` flag support**
- **Learning aggregation: false positive pattern reports and scan exclusion suggestions**
- **Feedback loop: generate agent improvement recommendations from exclusion data**

### Phase 5: Autoresearch & Self-Improvement
- **Integrate SAST benchmark suites (reality-check, BenchmarkJava-mutated) as evaluation infrastructure**
- **Build benchmark runner: automated agent evaluation with TPR/FPR/accuracy scoring**
- **Implement autoresearch loop: mutate → evaluate → gate → log → repeat**
- **On-demand mode (`/screw autoresearch sqli --iterations 20`)**
- **Scheduled mode (nightly/weekly via cron/CI)**
- **Research-triggered mode (new CVE ingestion → auto-propose YAML updates)**
- **Human review gate: research reports with proposed YAML diffs and metric changes**
- **Build CVE-based benchmark fixtures for languages with gaps (Rust via RustSec, TypeScript, Kotlin)**
- **Experiment logging and history (`.screw/autoresearch/experiments.log`)**

### Phase 6: Multi-LLM Challenger System
- **Define provider-agnostic challenger interface (structured input/output contract)**
- **Implement OpenAI Codex adapter (first provider)**
- **Challenger prompt design with anti-anchoring measures**
- **Three challenge flow modes: primary+challenger, reverse, parallel independent**
- **Finding reconciliation logic (agreed/disputed/unique classification)**
- **Enriched output: dual-perspective findings in markdown reports and JSON**
- **Cost controls: opt-in configuration, disclaimers, severity-gated triggers**
- **Connect challenger disagreement signals to autoresearch loop (§11.3)**
- **Prepare extensibility for additional providers (Gemini, etc.) — config-only addition**

### Phase 7: Agent Expansion & Ecosystem
- Research and build Phase 2 agents (access control, crypto, path traversal, etc.)
- Validation against diverse vulnerable codebases
- Community contribution workflow for new agents
- Performance optimization (parallel scanning, caching)
- Knowledge refresh process for existing agents
- **CI/CD integration with validated-only script execution**

---

## 13. Success Metrics

| Metric | Target | Phase |
|---|---|---|
| Detection rate on known-vulnerable code (WebGoat, DVWA) | >80% of targeted vulnerability types | Phase 1 |
| False positive rate | <20% of reported findings | Phase 1 |
| Time to scan a single file | <30 seconds | Phase 1 |
| Time to add a new vulnerability agent | <1 day (YAML only, no code) | Phase 1 |
| Agent knowledge sources per vulnerability type | ≥5 authoritative sources | Phase 0 |
| **False positive rate after learning (repeat scans on same project)** | **<5% (down from <20% on first scan)** | **Phase 2-3** |
| **Adaptive script reuse rate** | **>70% of custom scripts successfully reused in subsequent sessions** | **Phase 4** |
| **Triage-to-exclusion conversion rate** | **>80% of false positive triages produce reusable exclusion patterns** | **Phase 3** |
| **Time from first scan to "clean" scan (no new FPs)** | **<3 scan cycles per project** | **Phase 3** |
| **Autoresearch accuracy improvement per cycle** | **≥2% accuracy gain per 20-iteration research cycle** | **Phase 5** |
| **Benchmark coverage (languages with ground-truth suites)** | **≥6 languages (Java, Python, Go, C#, Rust, TypeScript)** | **Phase 5** |
| **Challenger agreement rate on true positives** | **>85% cross-model agreement on confirmed vulnerabilities** | **Phase 6** |
| **Disputed findings that are actual vulnerabilities** | **>50% of disputed findings resolve as true positives after human triage** | **Phase 6** |
| **Time to add new challenger LLM provider** | **<1 day (config + thin adapter only)** | **Phase 6** |

---

## 14. Open Questions

1. **MCP transport for screw.nvim**: stdio (subprocess) vs HTTP? screw.nvim already has HTTP infrastructure for collaboration, so HTTP may be simpler. But stdio avoids running a persistent server.
2. **LLM call management**: Should the MCP server call the Claude API directly for analysis, or should it construct prompts and let the client's LLM handle it? Direct API calls give more control but add cost management complexity.
3. **Caching strategy**: Should scan results be cached per-file-hash to avoid re-scanning unchanged code?
4. **Agent composition**: Can agents reference each other? (e.g., "if SQLi is found, also check for auth bypass via SQLi")
5. **Multi-language support**: Should agent definitions be language-agnostic with language-specific overlays, or fully separate per language?
6. **Rate limiting / cost control**: How to handle scanning an entire large codebase without excessive API usage?
7. **Adaptive script security boundary**: How restrictive should the sandbox be? Read-only filesystem access is a clear minimum. Should scripts be able to import third-party packages (e.g., `networkx` for call graph analysis)? What about subprocess execution for running the project's own linters?
8. **Exclusion portability**: Should `.screw/learning/exclusions.yaml` be committed to version control and shared across the team? Pro: collective learning. Con: one analyst's false positive judgment may not match another's risk tolerance.
9. **Adaptive script quality assurance**: Should there be automated tests for custom scripts (e.g., "this script should find the known vulnerability in test fixture X")? This would prevent script rot and enable confidence in CI/CD reuse.
10. **Learning feedback cadence**: How often should the system generate agent improvement recommendations from exclusion data? Per-scan? Weekly? On-demand?
11. **Autoresearch mutation strategy**: Should mutations be random (explore broadly) or directed (prioritize areas where benchmarks reveal weaknesses)? Likely a hybrid: directed mutations from benchmark failures and FP data, with occasional random exploration.
12. **Benchmark construction for uncovered languages**: For Rust, TypeScript, Kotlin, Swift — should we invest in building full CVE-based benchmark suites (high effort, high value) or rely primarily on the challenger system and manual validation until community benchmarks emerge?
13. **Autoresearch compute budget**: Each iteration involves an LLM call (to run the agent) plus benchmark scoring. 20 iterations per cycle could cost $5-20 in API calls. Should there be a per-cycle budget cap? How does this scale when running across all agent types?
14. **Challenger data privacy**: Mode 3 (parallel independent) sends the same code context to both Anthropic and OpenAI. Some organizations may have policies against sharing code with multiple AI providers. Should there be a "no-code-sharing" mode that only sends the finding description (not the source code) to the challenger?
15. **Challenger prompt iteration**: The challenger prompt is itself subject to quality improvement. Should the autoresearch loop also optimize the challenger prompt against benchmark cases where challenger responses were poor quality?
16. **Cross-model capability asymmetry**: Claude and Codex have different strengths (e.g., one may be better at Rust, the other at Java). Should the system track per-language challenger accuracy and weight disagreements accordingly?

---

## Appendix A: Relationship to screw.nvim

screw.nvim is an existing Neovim plugin for security code review with:
- Security-focused annotations attached to code lines
- CWE classification, severity levels, state tracking
- SARIF import/export
- Telescope search integration
- Collaboration via HTTP/PostgreSQL backend
- Visual signcolumn indicators

The screw-agents system extends screw.nvim with AI-powered vulnerability detection. screw.nvim remains the editor UI and note management layer; screw-agents provides the detection intelligence. See Appendix C for the repository structure, distribution strategy, and screw.nvim integration boundary.

## Appendix B: Key References

**Architecture & Tooling:**
- [screw.nvim GitHub](https://github.com/h0pes/screw.nvim)
- [Claude Code Custom Subagents](https://code.claude.com/docs/en/sub-agents)
- [Claude Code Skills](https://code.claude.com/docs/en/slash-commands)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)

**Taxonomy & Classification:**
- [CWE-1400 Comprehensive Categorization](https://cwe.mitre.org/data/definitions/1400.html) — Taxonomy backbone
- [CWE/MITRE Full Database](https://cwe.mitre.org/)
- [OWASP Top 10:2025](https://owasp.org/Top10/2025/) — Risk communication overlay
- [OWASP ASVS v5.0](https://owasp.org/www-project-application-security-verification-standard/) — Verification depth
- [CWE/SANS Top 25 (2024)](https://www.sans.org/top25-software-errors/) — Prioritization
- [CAPEC](https://capec.mitre.org/) — Attack pattern context
- [OWASP MASVS](https://mas.owasp.org/MASVS/) — Mobile-specific overlay

**Knowledge Sources:**
- [OWASP Code Review Guide v2 (PDF)](https://owasp.org/www-project-code-review-guide/assets/OWASP_Code_Review_Guide_v2.pdf) — Code-level review methodology
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [SpecterOps: Leveling Up Secure Code Reviews with Claude Code](https://specterops.io/blog/2026/03/26/leveling-up-secure-code-reviews-with-claude-code/) — Practitioner methodology for LLM-assisted code review during pentests
- [Sw4mpf0x/code-review-prompts](https://github.com/Sw4mpf0x/code-review-prompts) — System prompts and methodology files for the above
- [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review) — Anthropic's official security review Action with prompt templates and FP filtering

**Benchmarks & Validation:**
- [flawgarden/reality-check](https://github.com/flawgarden/reality-check) — Real-world CVE-based SAST benchmark (Java, C#, Go, Python)
- [flawgarden/BenchmarkJava-mutated](https://github.com/flawgarden/BenchmarkJava-mutated) — Enhanced OWASP Benchmark
- [SMU SAST Benchmark Research](https://ink.library.smu.edu.sg/cgi/viewcontent.cgi?article=9979&context=sis_research) — CVE-based benchmark methodology
- [RustSec Advisory Database](https://rustsec.org/) — Source for Rust-specific benchmark construction
- [OWASP Benchmark](https://owasp.org/www-project-benchmark/) — Reference only (limitations noted in §11.3)

**Autoresearch & Self-Improvement:**
- [karpathy/autoresearch](https://github.com/karpathy/autoresearch) — Inspiration for autonomous agent self-improvement loop

**Multi-LLM Challenger:**
- [openai/codex-plugin-cc](https://github.com/openai/codex-plugin-cc) — Official Claude Code plugin for invoking Codex as adversarial reviewer; reference implementation for challenger transport layer

## Appendix C: Repository Structure & Distribution

### Repository: `screw-agents`

A single repository (`github.com/h0pes/screw-agents`) containing the MCP server, Claude Code plugin, agent knowledge base, and benchmark infrastructure.

```
screw-agents/
│
├── .claude-plugin/                  # Claude Code plugin manifest
│   └── plugin.json                  # Plugin metadata, dependencies
│
├── plugins/screw/                   # Claude Code plugin contents
│   ├── agents/                      # Subagent definitions
│   │   ├── screw-sqli.md
│   │   ├── screw-xss.md
│   │   ├── screw-cmdi.md
│   │   ├── screw-ssti.md
│   │   ├── screw-injection.md       # Domain orchestrator
│   │   ├── screw-access-control.md
│   │   ├── screw-crypto.md
│   │   └── screw-full-review.md     # All-domain orchestrator
│   │
│   ├── skills/screw-review/
│   │   └── SKILL.md                 # Auto-invocation skill
│   │
│   └── commands/                    # Slash commands
│       ├── scan.md                  # /screw:scan
│       ├── autoresearch.md          # /screw:autoresearch
│       └── challenge.md             # /screw:challenge
│
├── src/screw_agents/                # MCP server (Python package)
│   ├── __init__.py
│   ├── server.py                    # MCP server entry point
│   ├── registry.py                  # Agent YAML loading → tool registration
│   ├── resolver.py                  # Target resolution (tree-sitter, git diff)
│   ├── formatter.py                 # Output formatting (JSON, SARIF, Markdown)
│   ├── learning.py                  # Exclusions DB, FP learning
│   ├── autoresearch/
│   │   ├── loop.py                  # Mutate → evaluate → gate → log
│   │   ├── benchmark.py             # Benchmark runner + scoring
│   │   └── mutations.py             # Mutation strategies
│   └── challenger/
│       ├── interface.py             # Provider-agnostic challenger contract
│       ├── codex_adapter.py         # OpenAI Codex implementation
│       └── reconciliation.py        # Finding reconciliation logic
│
├── domains/                         # Agent YAML definitions (the knowledge base)
│   ├── injection-input-handling/    # CWE-1406/1407/1409
│   │   ├── sqli.yaml
│   │   ├── xss.yaml
│   │   ├── cmdi.yaml
│   │   ├── ssti.yaml
│   │   └── xpath.yaml
│   ├── access-control/              # CWE-1396
│   │   ├── broken_access.yaml
│   │   └── ssrf.yaml
│   ├── cryptography/                # CWE-1402 + CWE-1414
│   │   ├── weak_algorithms.yaml
│   │   └── hardcoded_secrets.yaml
│   └── ...                          # 18 domains from CWE-1400
│
├── benchmarks/                      # Autoresearch evaluation infrastructure
│   ├── README.md
│   ├── bootstrap.sh                 # Downloads reality-check + other suites
│   ├── fixtures/                    # Small self-contained test cases (committed)
│   │   ├── sqli/
│   │   │   ├── vulnerable/
│   │   │   └── safe/
│   │   └── ...
│   └── scoring/                     # TPR/FPR calculation, report generation
│
├── docs/
│   ├── PRD.md                       # This document
│   ├── ARCHITECTURE.md
│   ├── CONTRIBUTING.md              # How to contribute new agents
│   └── AGENT_AUTHORING.md           # Guide for writing YAML definitions
│
├── .mcp.json                        # MCP server config (for development)
├── pyproject.toml                   # Python package definition (uv / pip / pipx compatible)
├── CLAUDE.md                        # Project-level instructions for Claude Code
└── README.md
```

### Distribution: Two Mechanisms from One Repo

**1. MCP Server (Python package):**

```bash
# Option A: uv (recommended)
uv tool install screw-agents
# Or run without installing globally
uvx screw-agents serve

# Option B: pipx (isolated install, avoids system package conflicts)
pipx install screw-agents

# Option C: pip (if your system allows it)
pip install screw-agents

# Register with Claude Code
claude mcp add screw-agents -- screw-agents serve
```

The MCP server bundles the `domains/` YAML definitions and the `src/screw_agents/` Python code. Published to PyPI. The `uv` / `uvx` approach is recommended as it handles virtual environment isolation automatically and avoids conflicts with system Python packages (relevant on Arch Linux, NixOS, and other rolling distributions where `pip install` is restricted).

**2. Claude Code Plugin (agents, skills, commands):**

```
# In Claude Code
/plugin marketplace add h0pes/screw-agents
/plugin install screw
```

The plugin installs the subagent `.md` files, the skill, and the slash commands. These are thin orchestration wrappers that call the MCP tools.

**3. Manual installation (no plugin system):**

Users who prefer explicit control can clone the repo and copy files:

```bash
# Copy agents and skills to project
cp -r screw-agents/plugins/screw/agents/ .claude/agents/
cp -r screw-agents/plugins/screw/skills/ .claude/skills/
cp -r screw-agents/plugins/screw/commands/ .claude/commands/
```

### Design Principles

**`domains/` is at the top level** because it's the community contribution target. Security researchers adding a new agent write a YAML file and add test fixtures — no Python code required. The `AGENT_AUTHORING.md` guide walks them through the format.

**Benchmarks bootstrap externally, fixtures commit locally.** Large benchmark suites (reality-check: 165+ CVEs) are downloaded via `benchmarks/bootstrap.sh`. Small test fixtures (a handful of vulnerable/safe code snippets per vulnerability type) are committed directly, enabling the autoresearch loop to run without external dependencies for quick iterations.

**Single commit for cross-cutting changes.** Adding a new agent typically requires a YAML definition in `domains/`, a subagent `.md` in `plugins/screw/agents/`, and test fixtures in `benchmarks/fixtures/` — all in one PR.

### screw.nvim Integration Boundary

The screw.nvim repository (github.com/h0pes/screw.nvim) adds screw-agents support as an optional feature module:

```
screw.nvim/  (existing repo, unchanged structure)
│
├── lua/screw/
│   ├── ...existing modules...
│   └── agents/                    # NEW: screw-agents integration
│       ├── client.lua             # MCP client (calls screw-agents-mcp)
│       ├── scan.lua               # :Screw scan command implementation
│       ├── triage.lua             # Review-before-import workflow
│       └── learning.lua           # FP exclusion capture + display
```

**Dependency model:** screw-agents is an optional dependency of screw.nvim, following the same pattern as screw.nvim's Telescope integration — the feature unlocks when the dependency is detected, but screw.nvim works fully without it. All existing features (manual notes, SARIF import/export, collaboration, signcolumn indicators) remain unchanged.

**Setup from screw.nvim:**

```vim
" Check if screw-agents MCP server is available
:Screw agents setup

" If installed, all scan commands become available
:Screw scan sqli %              " Scan current file for SQLi
:Screw scan injection src/      " Scan directory for all injection types
:Screw scan --diff main         " Scan changes vs main branch
```

**Transport:** The MCP server communicates with screw.nvim via stdio (spawned as a subprocess) or HTTP, to be determined during Phase 3 implementation. screw.nvim already has HTTP infrastructure from its collaboration backend, but stdio is simpler for the single-user case and avoids running a persistent server.
