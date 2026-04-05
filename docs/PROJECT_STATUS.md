# Project Status — screw-agents

> Last updated: 2026-04-05

## Current Phase: Pre-Implementation

Architecture and product design phase is **complete**. The PRD (v0.4.3) is the definitive document.

### What's Done
- Full architecture design (MCP server backbone, Claude Code integration, screw.nvim integration boundary)
- Taxonomy decision: CWE-1400 as structural backbone with OWASP Top 10:2025 overlay
- Domain mapping: 21 CWE-1400 categories consolidated to 18 agent domains
- Agent YAML definition format specified (see PRD §4)
- Target specification format with git diff/PR support (see PRD §5)
- Output schema (structured JSON + SARIF + Markdown reports) (see PRD §8)
- Four advanced features designed: adaptive scripts, persistent FP learning, autoresearch, multi-LLM challenger
- Repository structure defined (see PRD Appendix C)
- Phased implementation plan (Phases 0-7)
- Success metrics defined
- 16 open questions documented

### What's NOT Done
- No code exists yet. Zero implementation.
- No agent YAML definitions exist yet. The knowledge research sprint hasn't started.
- No benchmarks have been set up.
- The repository structure exists only in the PRD — directories haven't been created.

## Immediate Next Step: Phase 0 — Knowledge Research Sprint

This is the highest-value, highest-effort task. The quality of agent YAML definitions determines the quality of the entire system.

### Phase 0 Deliverables
1. Researched and synthesized YAML agent definitions for 4 Phase 1 agents:
   - `domains/injection-input-handling/sqli.yaml`
   - `domains/injection-input-handling/cmdi.yaml`
   - `domains/injection-input-handling/ssti.yaml`
   - `domains/injection-input-handling/xss.yaml`
2. Small benchmark fixtures in `benchmarks/fixtures/` for each agent
3. Discovery report of existing security skills, frameworks, and prompt libraries

### Phase 0 Approach
See `docs/KNOWLEDGE_SOURCES.md` for the full research roadmap. For each agent:
- Collect from all 4 tiers of knowledge sources
- Synthesize into 2,000-4,000 tokens of distilled detection knowledge
- Validate against known-vulnerable code
- Iterate until detection quality is satisfactory

## Full Phase Plan (from PRD §12)

| Phase | Focus | Status |
|---|---|---|
| **Phase 0** | Knowledge Research Sprint | **NEXT** |
| Phase 1 | Core Infrastructure (MCP server, agent registry, target resolver) | Pending |
| Phase 2 | Claude Code Integration (subagents, skills, filesystem output, FP learning) | Pending |
| Phase 3 | screw.nvim Integration (scan commands, review-before-import, exclusions) | Pending |
| Phase 4 | Adaptive Analysis & Learning Refinement | Pending |
| Phase 5 | Autoresearch & Self-Improvement | Pending |
| Phase 6 | Multi-LLM Challenger System | Pending |
| Phase 7 | Agent Expansion & Ecosystem | Pending |

## Marco's Environment & Preferences
- **OS:** Arch Linux
- **Editor:** Neovim (screw.nvim author)
- **Package manager:** `uv` (pip install restricted on Arch)
- **Languages:** Significant Rust development; also Python, TypeScript, others
- **Rust gap:** No established SAST benchmarks for Rust. Need to build from RustSec advisories.
