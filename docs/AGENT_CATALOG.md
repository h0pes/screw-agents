# Agent Catalog — CWE-1400 Domain-to-Agent Mapping

> Complete inventory of all planned individual agents, organized by CWE-1400 domain.
> Derived from PRD §9 (Agent Registry: Phased Build Order) and §9 (Domain-to-Agent Mapping).
>
> Last updated: 2026-04-11

## Reading This Document

- **Domain** = CWE-1400 category (structural backbone). Each domain gets one orchestrator subagent.
- **Agent** = individual vulnerability specialist. Each gets its own YAML definition + subagent `.md`.
- **Phase** = when the agent's YAML is researched and built (Phase 0 = done, Phase 2/7 = future).
- **YAML** = agent definition in `domains/<domain-dir>/`. The real knowledge lives here.
- **Subagent** = Claude Code `.md` file in `plugins/screw/agents/`. Thin wrapper calling MCP tools.

## Summary

| Metric | Count |
|---|---|
| Domains (CWE-1400 categories) | 18 |
| Domain orchestrator subagents | 18 |
| Individual agents (planned) | 41 |
| Individual agent subagents | 41 |
| Full-review orchestrator | 1 |
| **Total subagent `.md` files** | **60** |

---

## Domain 1: Access Control

| CWE-1400 ID | Directory | OWASP 2025 |
|---|---|---|
| CWE-1396 | `domains/access-control/` | A01 Broken Access Control |

| # | Agent | Primary CWEs | SANS Top 25 | Phase | Status |
|---|---|---|---|---|---|
| 1 | `broken_access` — IDOR, privilege escalation, missing authz | CWE-862, CWE-863, CWE-284 | #11, #16 | 2 (expansion) | Planned |
| 2 | `ssrf` — Server-side request forgery | CWE-918 | #19 | 2 (expansion) | Planned |

**Orchestrator:** `screw-access-control.md`

---

## Domain 2: Comparison

| CWE-1400 ID | Directory | OWASP 2025 |
|---|---|---|
| CWE-1397 | `domains/comparison/` | (Cross-cutting) |

| # | Agent | Primary CWEs | SANS Top 25 | Phase | Status |
|---|---|---|---|---|---|
| 1 | `type_confusion` — Incorrect type comparison, type juggling (PHP), loose equality | CWE-697, CWE-843 | — | 7 | Planned |
| 2 | `regex_dos` — ReDoS, incorrect regex validation bypass | CWE-185, CWE-1333 | — | 7 | Planned |

**Orchestrator:** `screw-comparison.md`

> Note: CWE-1254 (incorrect comparison logic in hardware) is out of scope for software code review.

---

## Domain 3: Component Interaction

| CWE-1400 ID | Directory | OWASP 2025 |
|---|---|---|
| CWE-1398 | `domains/component-interaction/` | A08 Software/Data Integrity |

| # | Agent | Primary CWEs | SANS Top 25 | Phase | Status |
|---|---|---|---|---|---|
| 1 | `xxe` — XML External Entity injection | CWE-611 | — | 3+ | Planned |
| 2 | `unsafe_reflection` — Unsafe reflection, dynamic class loading | CWE-470 | — | 3+ | Planned |

**Orchestrator:** `screw-component-interaction.md`

---

## Domain 4: Memory Safety

| CWE-1400 ID | Directory | OWASP 2025 |
|---|---|---|
| CWE-1399 | `domains/memory-safety/` | (Not in Top 10) |

| # | Agent | Primary CWEs | SANS Top 25 | Phase | Status |
|---|---|---|---|---|---|
| 1 | `buffer_overflow` — Out-of-bounds write/read, stack/heap overflow | CWE-787, CWE-125, CWE-119 | #1 (787), #3 (125) | 3+ | Planned |
| 2 | `use_after_free` — Use-after-free, double free | CWE-416, CWE-415 | #4 (416) | 3+ | Planned |
| 3 | `null_deref` — Null pointer dereference | CWE-476 | #12 | 3+ | Planned |

**Orchestrator:** `screw-memory-safety.md`

> Primary languages: C, C++, Rust (unsafe blocks). Less relevant for managed languages.

---

## Domain 5: Concurrency

| CWE-1400 ID | Directory | OWASP 2025 |
|---|---|---|
| CWE-1401 | `domains/concurrency/` | (Not in Top 10) |

| # | Agent | Primary CWEs | SANS Top 25 | Phase | Status |
|---|---|---|---|---|---|
| 1 | `race_condition` — Race conditions, TOCTOU | CWE-362, CWE-367 | #21 (362) | 3+ | Planned |

**Orchestrator:** `screw-concurrency.md`

---

## Domain 6: Cryptography

| CWE-1400 ID | Directory | OWASP 2025 |
|---|---|---|
| CWE-1402, CWE-1414 (merged: Encryption + Randomness) | `domains/cryptography/` | A04 Cryptographic Failures |

| # | Agent | Primary CWEs | SANS Top 25 | Phase | Status |
|---|---|---|---|---|---|
| 1 | `weak_crypto` — Weak/broken algorithms, insufficient key length, ECB mode | CWE-327, CWE-326 | — | 2 (expansion) | Planned |
| 2 | `hardcoded_secrets` — Hardcoded passwords, API keys, private keys in source | CWE-798, CWE-321 | #18 (798) | 2 (expansion) | Planned |
| 3 | `insecure_random` — Predictable PRNG, insufficient entropy | CWE-330, CWE-338 | — | 7 | Planned |

**Orchestrator:** `screw-cryptography.md`

> Note: PRD Phase 2 groups `weak_crypto` + `hardcoded_secrets` as one agent initially. Splitting them into two agents is recommended because detection heuristics are fundamentally different (algorithmic analysis vs. secret pattern matching). The orchestrator runs both regardless.

---

## Domain 7: Exposed Resource

| CWE-1400 ID | Directory | OWASP 2025 |
|---|---|---|
| CWE-1403 | `domains/exposed-resource/` | A01 (partial) |

| # | Agent | Primary CWEs | SANS Top 25 | Phase | Status |
|---|---|---|---|---|---|
| 1 | `open_redirect` — Unvalidated redirect/forward | CWE-601 | — | 7 | Planned |
| 2 | `resource_exposure` — Exposure of resource to wrong sphere, information leak via URL | CWE-668, CWE-610 | — | 7 | Planned |

**Orchestrator:** `screw-exposed-resource.md`

> Note: SSRF (CWE-918) could structurally belong here (CWE-610 is a parent), but the PRD places it under Access Control (Domain 1) following OWASP 2025's consolidation of SSRF into A01.

---

## Domain 8: File Handling

| CWE-1400 ID | Directory | OWASP 2025 |
|---|---|---|
| CWE-1404 | `domains/file-handling/` | A01 (partial) |

| # | Agent | Primary CWEs | SANS Top 25 | Phase | Status |
|---|---|---|---|---|---|
| 1 | `path_traversal` — Directory traversal, file inclusion | CWE-22, CWE-73 | #5 (22) | 2 (expansion) | Planned |
| 2 | `file_upload` — Unrestricted file upload, MIME type bypass | CWE-434 | #10 (434) | 7 | Planned |

**Orchestrator:** `screw-file-handling.md`

---

## Domain 9: Exceptional Conditions

| CWE-1400 ID | Directory | OWASP 2025 |
|---|---|---|
| CWE-1405 | `domains/exceptional-conditions/` | A10 Mishandling of Exceptional Conditions |

| # | Agent | Primary CWEs | SANS Top 25 | Phase | Status |
|---|---|---|---|---|---|
| 1 | `error_handling` — Missing error checks, fail-open logic, uncaught exceptions | CWE-754, CWE-755, CWE-252 | — | 3+ | Planned |

**Orchestrator:** `screw-exceptional-conditions.md`

> Note: CWE-209 (verbose errors leaking info) overlaps with Domain 18 (Sensitive Info). The error_handling agent focuses on control-flow consequences of bad error handling; info leakage via errors is Domain 18's sensitive_data agent's responsibility.

---

## Domain 10: Injection & Input Handling

| CWE-1400 ID | Directory | OWASP 2025 |
|---|---|---|
| CWE-1406, CWE-1407, CWE-1409 (merged) | `domains/injection-input-handling/` | A05 Injection |

| # | Agent | Primary CWEs | SANS Top 25 | Phase | Status |
|---|---|---|---|---|---|
| 1 | `sqli` — SQL injection | CWE-89 | #3 | 0 (research) | **YAML complete** |
| 2 | `cmdi` — OS command injection | CWE-78 | #7 | 0 (research) | **YAML complete** |
| 3 | `ssti` — Server-side template injection | CWE-1336 | — | 0 (research) | **YAML complete** |
| 4 | `xss` — Cross-site scripting (reflected, stored, DOM) | CWE-79 | #1 | 0 (research) | **YAML complete** |
| 5 | `xpath` — XPath injection | CWE-643 | — | 2 (expansion) | Planned |
| 6 | `deserialization` — Insecure deserialization | CWE-502 | #15 | 2 (expansion) | Planned |
| 7 | `ldap_injection` — LDAP injection | CWE-90 | — | 3+ | Planned |
| 8 | `nosql_injection` — NoSQL injection (MongoDB, CouchDB, etc.) | CWE-943 | — | 3+ | Planned |
| 9 | `header_injection` — HTTP header/response splitting | CWE-113 | — | 3+ | Planned |
| 10 | `log_injection` — Log injection/forging | CWE-117 | — | 3+ | Planned |

**Orchestrator:** `screw-injection.md`

> Largest domain by agent count. The 3 merged CWE-1400 categories (Input Validation + Neutralization + Injection) reflect the tight coupling: neutralization failures and injection attacks are consequences of input validation failures.

---

## Domain 11: Incorrect Calculation

| CWE-1400 ID | Directory | OWASP 2025 |
|---|---|---|
| CWE-1408 | `domains/incorrect-calculation/` | (Not in Top 10) |

| # | Agent | Primary CWEs | SANS Top 25 | Phase | Status |
|---|---|---|---|---|---|
| 1 | `integer_overflow` — Integer overflow/underflow, truncation | CWE-190, CWE-191 | #14 (190) | 7 | Planned |

**Orchestrator:** `screw-incorrect-calculation.md`

> Note: CWE-369 (divide by zero) and CWE-682 (incorrect calculation) are typically caught by compilers/linters. The integer_overflow agent focuses on security-relevant overflow (e.g., allocation size calculations, length checks).

---

## Domain 12: Control Flow Management

| CWE-1400 ID | Directory | OWASP 2025 |
|---|---|---|
| CWE-1410 | `domains/control-flow/` | (Not in Top 10) |

| # | Agent | Primary CWEs | SANS Top 25 | Phase | Status |
|---|---|---|---|---|---|
| 1 | `control_flow` — Infinite loops, uncontrolled recursion, missing break | CWE-835, CWE-674, CWE-691 | — | 7 | Planned |

**Orchestrator:** `screw-control-flow.md`

> Lower security relevance — primarily a reliability/DoS concern. Single agent covers the domain since these are closely related control-flow failures.

---

## Domain 13: Data Authenticity Verification

| CWE-1400 ID | Directory | OWASP 2025 |
|---|---|---|
| CWE-1411 | `domains/data-authenticity/` | A08 Software/Data Integrity |

| # | Agent | Primary CWEs | SANS Top 25 | Phase | Status |
|---|---|---|---|---|---|
| 1 | `csrf` — Cross-site request forgery | CWE-352 | #9 | 3+ | Planned |
| 2 | `jwt_validation` — JWT signature bypass, algorithm confusion, missing claims validation | CWE-347 | — | 3+ | Planned |

**Orchestrator:** `screw-data-authenticity.md`

---

## Domain 14: Coding Practices & Design

| CWE-1400 ID | Directory | OWASP 2025 |
|---|---|---|
| CWE-1412 | `domains/coding-practices/` | A06 Insecure Design |

| # | Agent | Primary CWEs | SANS Top 25 | Phase | Status |
|---|---|---|---|---|---|
| 1 | `insecure_design` — Security-relevant design flaws, missing security controls | CWE-710, CWE-477 | — | 3+ | Planned |

**Orchestrator:** `screw-coding-practices.md`

> Broadest and most subjective domain. The agent focuses on concrete, detectable anti-patterns (e.g., deprecated API usage, missing security headers in framework setup) rather than abstract "bad design."

---

## Domain 15: Protection Mechanism Failure

| CWE-1400 ID | Directory | OWASP 2025 |
|---|---|---|
| CWE-1413 | `domains/protection-mechanism/` | A07 Authentication Failures |

| # | Agent | Primary CWEs | SANS Top 25 | Phase | Status |
|---|---|---|---|---|---|
| 1 | `auth_failures` — Broken authentication, weak password policy, missing MFA checks | CWE-287, CWE-307, CWE-522 | #13 (287) | 2 (expansion) | Planned |

**Orchestrator:** `screw-protection-mechanism.md`

---

## Domain 16: Resource Control

| CWE-1400 ID | Directory | OWASP 2025 |
|---|---|---|
| CWE-1415 | `domains/resource-control/` | A02 Security Misconfiguration (partial) |

| # | Agent | Primary CWEs | SANS Top 25 | Phase | Status |
|---|---|---|---|---|---|
| 1 | `resource_exhaustion` — DoS via resource exhaustion, unbounded allocation, missing rate limits | CWE-400, CWE-770 | — | 3+ | Planned |

**Orchestrator:** `screw-resource-control.md`

---

## Domain 17: Resource Lifecycle Management

| CWE-1400 ID | Directory | OWASP 2025 |
|---|---|---|
| CWE-1416 | `domains/resource-lifecycle/` | (Not in Top 10) |

| # | Agent | Primary CWEs | SANS Top 25 | Phase | Status |
|---|---|---|---|---|---|
| 1 | `resource_leak` — Unclosed handles, file descriptors, DB connections, memory leaks | CWE-404, CWE-401, CWE-772 | — | 7 | Planned |

**Orchestrator:** `screw-resource-lifecycle.md`

> Primarily a reliability concern but security-relevant when leaked resources enable DoS or information disclosure (e.g., leaked temp files with sensitive data).

---

## Domain 18: Sensitive Information Exposure

| CWE-1400 ID | Directory | OWASP 2025 |
|---|---|---|
| CWE-1417 | `domains/sensitive-info/` | A04 (partial), A09 Logging Failures (partial) |

| # | Agent | Primary CWEs | SANS Top 25 | Phase | Status |
|---|---|---|---|---|---|
| 1 | `sensitive_data` — PII/secrets in responses, verbose error messages, debug endpoints | CWE-200, CWE-209 | — | 2 (expansion) | Planned |
| 2 | `log_leakage` — Sensitive data written to logs, insufficient log sanitization | CWE-532 | — | 3+ | Planned |

**Orchestrator:** `screw-sensitive-info.md`

> Note: CWE-798 (hardcoded credentials) is covered by Domain 6's `hardcoded_secrets` agent, not here. Detection is algorithmic pattern matching (secret scanning), which aligns better with the Cryptography domain's tooling.

---

## Build Order by Phase

| Phase | Agents | Domains Touched | Status |
|---|---|---|---|
| **0** (research) | sqli, cmdi, ssti, xss | 1 (injection) | **Complete** |
| **2** (expansion) | xpath, deserialization, broken_access, ssrf, weak_crypto, hardcoded_secrets, auth_failures, path_traversal, sensitive_data | 5 (injection, access-control, cryptography, protection-mechanism, file-handling, sensitive-info) | **Agent YAML: Phase 6. Subagent .md: Phase 2 only for existing 4 agents** |
| **3+** | xxe, unsafe_reflection, error_handling, race_condition, csrf, jwt_validation, resource_exhaustion, insecure_design, ldap_injection, nosql_injection, header_injection, log_injection, log_leakage, buffer_overflow, use_after_free, null_deref | 10 | Planned |
| **6** (full coverage) | type_confusion, regex_dos, open_redirect, resource_exposure, file_upload, integer_overflow, control_flow, resource_leak, insecure_random | 7 | Planned |

> **Clarification on "Phase 2" overloading:** The PRD uses "Phase 2" in two contexts: (a) Phase 2 of the *implementation plan* = Claude Code Integration (subagents, skills, filesystem output) for the existing 4 agents; (b) "Phase 2 agents" in §9 = the next 8 agent YAMLs to be researched. The YAML research for expansion agents happens in Phase 6 (Agent Expansion). Phase 2 of the implementation plan builds Claude Code integration for whatever agents exist at the time (currently 4).

---

## Mobile Overlay (Future)

The PRD mentions OWASP MASVS-based mobile agents as a future overlay, not a CWE-1400 domain. These would be additional agents within existing domains with mobile-specific detection heuristics:

| Agent | Standards | Domains Affected |
|---|---|---|
| `insecure_storage` | MASVS-STORAGE | File Handling, Sensitive Info |
| `insecure_communication` | MASVS-NETWORK | Cryptography, Exposed Resource |

These are Phase 6+ and depend on mobile-specific benchmark availability.
