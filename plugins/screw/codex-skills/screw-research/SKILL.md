---
name: screw-research
description: >
  Use when researching a vulnerability type to build an agent YAML definition.
  Enforces the research → synthesize → validate cycle with mandatory research notes gate.
---

# Security Knowledge Research Skill

You are conducting deep security research to build high-quality YAML agent definitions for screw-agents. Each agent definition must contain 2,000-4,000 tokens of distilled, LLM-optimized detection knowledge — not raw concatenation of source material.

## Before You Start

1. Read `docs/KNOWLEDGE_SOURCES.md` for the full source hierarchy and research roadmap.
2. Read `docs/PRD.md` §4 for the exact YAML agent definition schema.
3. If any completed agent YAML already exists in `domains/`, read it as the quality reference — match or exceed its depth and specificity.

## Hard Rule: Research Notes Before YAML

**Do NOT write the agent YAML definition until research notes have been produced and reviewed.**

Research notes go in `docs/research/{agent}-research-notes.md` (gitignored — local only). These capture the raw collected knowledge, source analysis, and synthesis decisions before distillation into the final YAML. The cycle is strictly: **research → synthesize → validate**. No skipping steps.

## Research Process

For each vulnerability type, follow this process in order:

### 1. Collect — Gather from All Four Tiers

**Tier 1 — Normative Standards (what the vulnerability IS):**
- CWE full entry: definition, extended description, relationships (parent/child CWEs), observed examples, detection methods
- OWASP ASVS v5.0: specific verification requirements that map to testable assertions
- CAPEC: attack patterns linked to the CWE — exploitation methodology, prerequisites, consequences

**Tier 2 — Testing Methodology (how to FIND it in code):**
- OWASP Code Review Guide v2: code-level review methodology — data flow tracing, trust boundary identification, authorization logic assessment
- OWASP Testing Guide: step-by-step testing procedures (e.g., WSTG-INPV-05 for SQLi)
- OWASP Cheat Sheet Series: both detection patterns AND remediation knowledge
- SANS/CWE Top 25: danger scores for prioritization

**Tier 3 — Real-World Intelligence (what separates good from great):**
- CVE databases (NVD, MITRE): real exploitation examples filtered by CWE type
- Semgrep Rule Registry: translate pattern-matched rules into natural language detection heuristics
- CodeQL Query Suites: dataflow analysis patterns and query descriptions
- Security research blogs: PortSwigger, Trail of Bits, Project Zero, Doyensec, NCC Group
- Language-specific advisory databases (RustSec for Rust, npm advisories for JS/TS)

**Tier 4 — Existing LLM Security Skills:**
- SpecterOps/Sw4mpf0x code-review-prompts: practitioner methodology and system prompt structure
- anthropics/claude-code-security-review: prompt templates and FP filtering logic
- Trail of Bits security skills: SKILL.md format and detection approaches
- Other Claude Code / LLM security skills found on GitHub

### 2. Analyze — Identify What Matters Most

From collected material, extract:
- The most impactful detection signals (what code patterns indicate this vulnerability?)
- Common vulnerable code shapes per language/framework
- Bypass techniques that defeat common mitigations
- Framework-specific pitfalls (e.g., Django extra(), SQLAlchemy text())
- True positive vs false positive distinguishing criteria
- Severity assessment criteria based on exploitability and impact

### 3. Synthesize — Distill into YAML Agent Format

**Gate:** Only proceed here after research notes in `docs/research/{agent}-research-notes.md` have been produced and reviewed. The notes must cover all four tiers with specific findings, not just source listings.

Write the YAML agent definition following the schema in `docs/PRD.md` §4:

```yaml
meta:
  name: ...
  display_name: ...
  domain: ...
  version: "1.0.0"
  cwes: { primary: ..., related: [...] }
  capec: [...]
  owasp: { top10: ..., asvs: [...], testing_guide: ... }
  sources: [{ url: ..., last_checked: ... }, ...]

core_prompt: |
  [2,000-4,000 tokens of distilled detection knowledge]

detection_heuristics:
  high_confidence: [...]
  medium_confidence: [...]
  context_required: [...]

bypass_techniques: [...]
remediation: { preferred: ..., common_mistakes: [...] }
few_shot_examples: { vulnerable: [...], safe: [...] }
target_strategy: { scope: ..., file_patterns: [...], relevance_signals: [...] }
```

### 4. Validate & Iterate

- Test against known-vulnerable code (benchmark fixtures in `benchmarks/fixtures/`)
- Check for gaps: are there common patterns the agent would miss?
- Check for noise: are there safe patterns the agent would falsely flag?
- Refine heuristics based on results

## Quality Requirements (Non-Negotiable)

1. **Every detection heuristic must be language-specific and precise.** "String concatenation in SQL" is vague. "f-string interpolation in Python cursor.execute()" is actionable.
2. **Every bypass technique must reference a real attack vector.** Not theoretical — cite a real CVE, published research, or documented exploitation method.
3. **Every remediation must include BOTH the correct fix AND common mistakes.** Show what to do and what people get wrong trying to fix it.
4. **Distill, don't concatenate.** 2,000-4,000 tokens of knowledge, not 50,000 of raw material.
5. **Precision over breadth.** A few highly specific detection patterns beat a long list of vague guidelines.
6. **Real-world grounding.** Reference actual CVEs and exploits to anchor abstract descriptions.
7. **Maintenance metadata.** Record all sources with URLs and last-checked dates in `meta.sources`.

## Output Locations

- **Research notes:** `docs/research/{agent}-research-notes.md` (gitignored — local only, produced FIRST)
- **Agent YAML definitions:** `domains/{domain-name}/{agent}.yaml` (produced AFTER research notes are reviewed)
- **Benchmark fixtures:** `benchmarks/fixtures/{agent}/vulnerable/` and `benchmarks/fixtures/{agent}/safe/`

## Phase 1 Agents (Build Order)

1. `domains/injection-input-handling/sqli.yaml` — SQL Injection (CWE-89)
2. `domains/injection-input-handling/cmdi.yaml` — Command Injection (CWE-78)
3. `domains/injection-input-handling/ssti.yaml` — Server-Side Template Injection (CWE-1336)
4. `domains/injection-input-handling/xss.yaml` — Cross-Site Scripting (CWE-79)
