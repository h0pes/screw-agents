# Knowledge Sources & Research Roadmap — screw-agents

This document maps every knowledge source identified during the architecture phase, organized by tier and by how they should be consumed during the knowledge research sprint.

## Research Sprint Objective

Each Source Tier must be researched in depth in order to find the best and most accurate and effective sources to build/design our whole features.
Spend a lot of time performing deep researches on each of the topics not only in standard web searches, but also academic research papers (arXiv and alikes), github repositories themselves, hidden blog posts by security researchers, etc.
Build high-quality YAML agent definitions for Phase 1 vulnerability types (SQLi, Command Injection, SSTI, XSS) by collecting, analyzing, and synthesizing security knowledge from all tiers below. Each agent definition should contain 2,000-4,000 tokens of distilled, LLM-optimized detection knowledge — not raw concatenation of source material.

## Source Tiers

### Tier 1 — Normative Standards (Taxonomic Backbone)

These define WHAT the vulnerabilities are. Every agent references these for CWE IDs, relationships, and formal definitions.

| Source            | URL                                                                       | How to Use                                                                                                                                                      |
| ----------------- | ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CWE Full Database | https://cwe.mitre.org/                                                    | Extract full XML entries for each agent's primary CWEs. Include relationships (parent/child CWEs, related weaknesses). Use CWE-1400 view for domain assignment. |
| OWASP ASVS v5.0   | https://owasp.org/www-project-application-security-verification-standard/ | Map each agent to specific ASVS verification requirements. These become testable assertions in the agent prompt.                                                |
| CAPEC             | https://capec.mitre.org/                                                  | Extract attack patterns linked to each CWE. These inform the "bypass techniques" and "exploitability" sections of agent definitions.                            |
| OWASP MASVS v2.1  | https://mas.owasp.org/MASVS/                                              | Mobile-specific overlay. Defer to Phase 6+ unless specifically needed.                                                                                          |

### Tier 2 — Testing Methodology (What To Look For)

These define HOW to find the vulnerabilities in code. The most directly actionable sources for agent prompts.

| Source                     | URL                                                                                   | How to Use                                                                                                                                                                                                                                                         |
| -------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| OWASP Code Review Guide v2 | https://owasp.org/www-project-code-review-guide/assets/OWASP_Code_Review_Guide_v2.pdf | **Highest priority for agent prompt authoring.** Extract code-level review methodology: data flow tracing techniques, trust boundary identification, authorization logic assessment patterns. The methodology chapters translate directly into agent instructions. |
| OWASP Testing Guide v4.2+  | https://owasp.org/www-project-web-security-testing-guide/                             | Extract step-by-step testing procedures per vulnerability type (e.g., WSTG-INPV-05 for SQLi). These inform what patterns the agent should look for.                                                                                                                |
| OWASP Cheat Sheet Series   | https://cheatsheetseries.owasp.org/                                                   | Dual use: detection patterns AND remediation knowledge. Each cheat sheet (e.g., SQL Injection Prevention) lists both what's wrong and how to fix it correctly. Extract both into agent YAML.                                                                       |
| SANS/CWE Top 25 (2024)     | https://www.sans.org/top25-software-errors/                                           | Prioritization data. Use the danger scores to rank which agents get the most investment.                                                                                                                                                                           |

### Tier 3 — Real-World Intelligence (Separates Good from Great)

These provide the knowledge that elevates agents above basic pattern matching.

| Source                | URL                                            | How to Use                                                                                                                                                                                                   |
| --------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| CVE databases         | https://nvd.nist.gov/ , https://cve.mitre.org/ | Filter by CWE type. Extract real-world exploitation examples to ground abstract vulnerability descriptions in concrete cases. Use for few-shot examples in YAML.                                             |
| Semgrep Rule Registry | https://semgrep.dev/explore                    | **Critical source.** Thousands of pattern-matched vulnerability rules. Extract the code patterns (in Semgrep's pattern syntax) and translate them into natural language detection heuristics for agent YAML. |
| CodeQL Query Suites   | https://github.com/github/codeql               | Same as Semgrep but in CodeQL's dataflow analysis formalism. Extract the query descriptions and patterns.                                                                                                    |
| PortSwigger Research  | https://portswigger.net/research               | Bypass techniques, novel exploitation methods. Essential for the `bypass_techniques` section of agent YAML.                                                                                                  |
| Trail of Bits Blog    | https://blog.trailofbits.com/                  | Deep technical security research. Particularly strong on memory safety, crypto, and smart contract vulnerabilities.                                                                                          |
| Project Zero          | https://googleprojectzero.blogspot.com/        | Advanced exploitation research. Use selectively for bypass techniques.                                                                                                                                       |
| Snyk Vulnerability DB | https://snyk.io/vuln/                          | Real-world vulnerability examples with affected versions and fix patterns.                                                                                                                                   |
| Doyensec Blog         | https://blog.doyensec.com/                     | Application security research, particularly web and mobile.                                                                                                                                                  |
| NCC Group Research    | https://research.nccgroup.com/                 | Broad security research coverage.                                                                                                                                                                            |
| RustSec Advisory DB   | https://rustsec.org/                           | Rust-specific vulnerabilities. Critical for building Rust benchmark fixtures.                                                                                                                                |

### Tier 4 — Existing LLM Security Skills (Standing on Shoulders)

These are existing prompts, skills, and frameworks for LLM-powered code review. Study their approach, extract what works, avoid their mistakes.

| Source                                    | URL                                                                                     | What to Extract                                                                                                                                                         |
| ----------------------------------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SpecterOps secure code review methodology | https://specterops.io/blog/2026/03/26/leveling-up-secure-code-reviews-with-claude-code/ | Practitioner methodology: use LLM to understand code, not just "find vulns." System prompt structure with application context. Targeted analysis patterns.              |
| Sw4mpf0x/code-review-prompts              | https://github.com/Sw4mpf0x/code-review-prompts                                         | The actual system prompt files for the SpecterOps methodology. Study the prompt structure and adapt.                                                                    |
| anthropics/claude-code-security-review    | https://github.com/anthropics/claude-code-security-review                               | Anthropic's official security review. Study `prompts.py` (prompt templates), `findings_filter.py` (FP filtering logic). Reference implementation for our output format. |
| Trail of Bits Security Skills             | Search GitHub: "trail of bits" "SKILL.md" security                                      | Professional security-focused Claude Code skills for code auditing. Study their SKILL.md format and detection approaches.                                               |
| Shannon Framework                         | Search GitHub: "shannon framework" security review LLM                                  | Framework for LLM security review. Study the prompt engineering patterns.                                                                                               |
| VibeSec-Skill                             | Search GitHub: VibeSec-Skill claude code                                                | Security skill for Claude Code. Study approach and prompts.                                                                                                             |
| Semgrep rule descriptions                 | https://semgrep.dev/explore                                                             | Natural language descriptions of detection rules. These translate into detection heuristics for agent YAML.                                                             |

## Research Process Per Agent

For each Phase 1 vulnerability type (SQLi, Command Injection, SSTI, XSS):

1. **Collect** — Gather all relevant material from tiers 1-4 for that specific CWE
2. **Analyze** — Identify the most impactful detection signals, common code patterns, bypass techniques, and framework-specific pitfalls
3. **Synthesize** — Distill into the YAML agent format (see PRD §4 for schema): core_prompt, detection_heuristics (high/medium/context_required), bypass_techniques, remediation (preferred + common_mistakes), few_shot_examples (vulnerable + safe per language)
4. **Validate** — Test against benchmark fixtures (reality-check + self-authored)
5. **Measure** — Compute TPR, FPR, accuracy
6. **Iterate** — Refine based on results
7. **Document** — Record which sources contributed which knowledge in the YAML `meta.sources` field

## Benchmark Sources

| Benchmark                        | URL                                                                                  | Coverage                         | Role                                   |
| -------------------------------- | ------------------------------------------------------------------------------------ | -------------------------------- | -------------------------------------- |
| flawgarden/reality-check         | https://github.com/flawgarden/reality-check                                          | Java, C#, Go, Python (165+ CVEs) | Primary benchmark — real-world         |
| flawgarden/BenchmarkJava-mutated | https://github.com/flawgarden/BenchmarkJava-mutated                                  | Java                             | Supplementary                          |
| SMU SAST Research                | https://ink.library.smu.edu.sg/cgi/viewcontent.cgi?article=9979&context=sis_research | Methodology (language-agnostic)  | Framework for building new benchmarks  |
| RustSec                          | https://rustsec.org/                                                                 | Rust                             | Source for Rust benchmark construction |
| WebGoat / DVWA / Juice Shop      | Various                                                                              | PHP, Java, JS                    | Manual validation only                 |

## Discovery Tasks (Skills/Frameworks to Find)

These need active research to discover — they're scattered across GitHub and security blogs:

- [ ] Search GitHub for: `SKILL.md` + security + code review + vulnerability
- [ ] Search GitHub for: Claude Code + security + agent + audit
- [ ] Search GitHub for: LLM + secure code review + prompt
- [ ] Search GitHub for: AI + SAST + prompt engineering
- [ ] Check awesome-claude-code lists for security-related entries
- [ ] Survey Semgrep community rules for vulnerability types matching Phase 1 agents
- [ ] Survey CodeQL query suites for the same
- [ ] Search for Rust-specific security review tools and skills
