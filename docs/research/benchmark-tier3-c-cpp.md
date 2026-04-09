# Benchmark Research Tier 3 — C and C++ SAST Datasets

_Date: 2026-04-09_
_Purpose: Identify C/C++ SAST benchmarks for future agent expansion (post Phase 1). Phase 1 agents are SQLi (CWE-89), CmdI (CWE-78), XSS (CWE-79), SSTI (CWE-1336); this tier assesses C/C++ availability for the two that conceivably apply to C backends (CWE-78, CWE-89)._

---

## 1. Lipp et al. Study — "An Empirical Study on the Effectiveness of Static C Code Analyzers for Vulnerability Detection" (ISSTA 2022)

**The paper referenced as [50] in the SMU/ESEC-FSE'23 study.** Found.

### Paper metadata
- **Authors:** Stephan Lipp, Sebastian Banescu, Alexander Pretschner (Technical University of Munich)
- **Venue:** ISSTA '22 — 31st ACM SIGSOFT International Symposium on Software Testing and Analysis, July 2022
- **DOI:** https://doi.org/10.1145/3533767.3534380
- **Preprint:** https://mediatum.ub.tum.de/doc/1659728/1659728.pdf
- **Artifact (Zenodo):** https://doi.org/10.5281/zenodo.6515687 (also 6600197 for newer revision)
- **License:** CC-BY-4.0

### Benchmark composition
- **27 C projects**, ~1.15 million LoC
- **192 real-world CVE-derived vulnerabilities** (ground-truth via CVE reports)
- Named projects include: **Binutils, FFmpeg, libpng, LibTIFF, Libxml2, OpenSSL, PHP, Poppler, SQLite3** (among 27)
- CWE labeling is rolled up to MITRE **Pillar-level** (CWE-1000 top tier) for analysis:
  - **CWE-664** — Improper Control of a Resource Through its Lifetime (memory lifetime, use-after-free, etc.)
  - **CWE-682** — Incorrect Calculation
  - **CWE-691** — Insufficient Control Flow Management
  - **CWE-703** — Improper Check or Handling of Exceptional Conditions
  - **CWE-707** — Improper Neutralization (the pillar under which CWE-78, CWE-89, CWE-79 all live)
- Fine-grained CWE distribution is provided in `cwe_distr.csv` inside the Zenodo artifact. The paper headlines CWE-664 and CWE-703 as most detectable; **CWE-707 (the injection pillar) is present but not a focus** — injection bugs are a tiny minority in this corpus, which is dominated by memory-safety CVEs typical of the chosen C projects.

### SAST tools evaluated (6 total)
1. **Flawfinder** 2.0.11
2. **Cppcheck** 2.3
3. **Infer** 0.14.0
4. **CodeChecker** 6.12.0
5. **CodeQL** 2.1.3
6. **CommSCA** (anonymized commercial tool)

### Headline findings
- SAST tools miss **47%–80%** of real-world C vulnerabilities.
- Ensembling all tools together reduces false negatives to **30%–69%** but increases flagged functions by ~15 pp.
- Synthetic benchmark performance does **not** predict real-world performance — a core argument against Juliet-only validation.

### Relevance to screw-agents Phase 1
- **Low for CWE-78/CWE-89.** The 192 CVEs are overwhelmingly memory-safety and control-flow bugs (CWE-664/-691/-703 dominated). Injection CVEs in this C-project sample are rare because these projects are libraries/parsers, not CGI/backend shell wrappers.
- **High as a methodology template.** The evaluation pipeline (CVE → patch → function-level ground truth → tool CWE mapping) is the best-in-class approach for _any_ real-world SAST benchmark. screw-agents' autoresearch loop should model on this methodology, not on Juliet pattern-matching.

---

## 2. Academic Dataset Deep Dives

### 2.1 Juliet Test Suite for C/C++ (NIST SAMATE / SARD)
- **Source:** NSA Center for Assured Software; hosted at https://samate.nist.gov/SARD/test-suites/112 (v1.3)
- **Scope:** Synthetic. 118 CWEs in C/C++, tens of thousands of test cases organized as BAD/GOOD pairs.
- **CWE-78 (OS Command Injection):** **~4,800 C test cases present.** Covers `system()`, `execl()`, `execv()`, `execvp()`, `popen()`, `wspawnl()`, `CreateProcess()`, plus wchar_t / multi-source variants. Confirmed via direct SARD test case inspection (e.g., `CWE78_OS_Command_Injection__wchar_t_file_w32spawnl_54d.c`).
- **CWE-89 (SQL Injection):** **NOT present in the C suite.** Juliet explicitly documents that "SQL Injection issues are covered in the related Java test cases." No C/C++ SQLi test cases exist in Juliet.
- **CWE-79 (XSS):** Not applicable to C.
- **CWE-1336 (SSTI):** Not applicable to C.
- **Caveat:** Synthetic. Lipp et al. showed tools that ace Juliet still miss 47–80% on real CVEs.

### 2.2 SARD (NIST Software Assurance Reference Dataset)
- **URL:** https://samate.nist.gov/SARD/
- **Scope:** >170,000 programs across C, C++, Java, PHP, C#, covering >150 CWE classes. Superset of Juliet plus real CVE test cases (one test case per CVE), plus community contributions.
- **CWE-78 in C:** Yes, both synthetic (Juliet) and real-CVE-backed test cases.
- **CWE-89 in C:** Not meaningfully present. SQLi test cases in SARD are Java/PHP/C#.
- **Documentation:** NIST IR 8561 (2025) — https://nvlpubs.nist.gov/nistpubs/ir/2025/NIST.IR.8561.pdf

### 2.3 Big-Vul (Fan et al., MSR 2020)
- **Paper:** https://doi.org/10.1145/3379597.3387501
- **Repo:** https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset (file: `all_c_cpp_release2.0.csv`)
- **Scope:** 3,754 C/C++ CVEs from 348 GitHub projects, 2002–2019. **91 CWE types.** After dedup: ~8,783 functions, 88 CWE-IDs.
- **CWE distribution:** Long-tailed. Dominated by memory-safety (CWE-119, CWE-125, CWE-787, CWE-416, CWE-476). **CWE-78 present but rare** (dozens, not thousands). **CWE-89 present but extremely rare in C context** (mostly framework-adjacent C code).
- **Known issue:** High duplication and label noise — see PrimeVul for the corrective study.

### 2.4 PrimeVul (Ding et al., ICSE 2025; arXiv 2024)
- **Paper:** https://arxiv.org/abs/2403.18624
- **Repo:** https://github.com/DLVulDet/PrimeVul
- **Scope:** ~7k vulnerable + ~229k benign C/C++ functions; **140+ CWEs.** Aggressive dedup (vs Big-Vul) and chronological splits to prevent data leakage.
- **Pair-based evaluation:** Test split includes paired (vulnerable, patched) function pairs. <20% textual diff. VD-Score metric captures "miss vs noise" trade-off.
- **Headline result:** SOTA 7B model drops from **68.26% F1 on Big-Vul** to **3.09% F1 on PrimeVul** — existing benchmarks massively overstate model capability. Hugely relevant caution for screw-agents' own evaluation design.
- **CWE-78 coverage:** Inherited from Big-Vul universe, so present but sparse.

### 2.5 MegaVul (Ni et al., MSR 2024)
- **Paper:** https://arxiv.org/abs/2406.12415
- **Repo:** https://github.com/Icyrockton/MegaVul
- **Scope:** **17,380 vulnerabilities** from **992 open-source repos**, 2006–2023, **176 CWE IDs**. Includes Joern graphs for ~87% of functions, 4 code representations.
- **Top 10 CWEs:** CWE-119, CWE-125, CWE-787, CWE-476, CWE-20, CWE-416, CWE-190 (others). **Memory-safety dominates at 59.27%.**
- **CWE-78: NOT in top 10.** Present in the long tail but not a focus.
- **CWE-89 in C:** Effectively absent.
- **Continuously updated** — most current C/C++ real-CVE dataset as of 2024.

### 2.6 D2A (IBM, ICSE-SEIP 2021)
- **Paper:** https://arxiv.org/abs/2102.07995
- **Repo:** https://github.com/IBM/D2A
- **Scope:** 1.3M+ labeled examples from before/after commit differential analysis (Infer-based). Projects: **OpenSSL, FFmpeg, httpd, NGINX, libtiff, libav.**
- **CWE coverage:** Driven by Infer bug types → maps to CWE-476 (NULL deref), CWE-457 (uninit), CWE-400 (resource leak), CWE-401, CWE-416, CWE-562, CWE-690. **Narrow memory/resource focus.** No CWE-78 or CWE-89 coverage.
- **Note:** Labels are _probabilistic_ (differential analysis, not human ground truth). Known label-noise issues.

### 2.7 Devign (Zhou et al., NeurIPS 2019)
- **Sources:** FFmpeg + QEMU (original); broader variants add Linux kernel and Wireshark.
- **Scope:** ~27,318 manually labeled C functions; labels are binary (vulnerable/not) rather than CWE-typed.
- **CWE-78 coverage:** Not CWE-annotated at function level. Unusable for CWE-targeted evaluation.

### 2.8 VulDeePecker (Li et al., NDSS 2018)
- **Repo:** https://github.com/CGCL-codes/VulDeePecker
- **Scope:** Only two CWEs: **CWE-119** (buffer errors) and **CWE-399** (resource management). **No CWE-78/CWE-89.** Obsolete for our purposes.

### 2.9 SySeVR (Li et al., TDSC 2021)
- **Scope:** 15,591 C/C++ programs from NVD + SARD. Covers **126 CWEs** — broader than VulDeePecker. Includes CWE-78 in the long tail.
- **Caveat:** Heavily SARD-derived — so CWE-78 cases are largely synthetic Juliet tests, not fresh real CVEs.

### 2.10 DiverseVul (Chen et al., RAID 2023)
- **Paper:** https://surrealyz.github.io/files/pubs/raid23-diversevul.pdf
- **Repo:** https://github.com/wagner-group/diversevul
- **Scope:** 18,945 vulnerable functions + 330,492 benign, **150 CWEs**, ~800 projects.
- **Top CWEs:** CWE-787 (38.5%), CWE-125 (24.9%), CWE-119 (21.7%), CWE-20 (17.5%), CWE-703 (16.3%), CWE-416 (13.4%). **Memory-safety dominated; CWE-78 in long tail; CWE-89 effectively absent.**

### 2.11 CASTLE (2024-2025) — **most relevant small-scale CWE-78 / CWE-89 C benchmark**
- **Paper:** https://arxiv.org/html/2503.09433v2 — "CASTLE: Benchmarking Dataset for Static Code Analyzers and LLMs towards CWE Detection"
- **Repo:** https://github.com/CASTLE-Benchmark
- **Scope:** **250 compilable compact C programs**, avg 42 LoC each. **25 distinct CWEs × 10 programs (6 vulnerable + 4 clean).**
- **CWE-78 (OS Command Injection in C): YES — 6 vulnerable + 4 clean cases.** Direct confirmation.
- **CWE-89 (SQL Injection in C): YES — 6 vulnerable + 4 clean cases.** Rare — this is one of the very few C corpora with intentionally constructed CWE-89 in C (typically a C backend calling sqlite3_exec or similar with unsanitized input).
- **Best fit for our Phase 1 agents if we add C/C++ support**, precisely because it was designed to give balanced CWE-level coverage including our targets.

### 2.12 CWE-Bench-Java (adjacent reference)
- **Repo:** https://github.com/iris-sast/cwe-bench-java
- **Scope:** 120 real CVEs × 4 CWEs (path traversal, OS command injection, XSS, code injection) — **Java only**. Listed here only as methodological reference; not usable for C/C++.

---

## 3. CWE Coverage Matrix for C/C++

| Benchmark | Lang | Real CVEs? | CWE-78 (CmdI) | CWE-89 (SQLi) | Notes |
|---|---|---|---|---|---|
| **Lipp et al. / ISSTA '22** | C | Yes (192) | Rare (under CWE-707 pillar) | Effectively no | Memory-safety dominant; best real-world methodology |
| **Juliet v1.3 C/C++** | C/C++ | No (synthetic) | **YES — ~4,800** | **NO** (Java-only in Juliet) | Juliet explicitly excludes C SQLi |
| **SARD (full)** | Mixed | Partial | Yes (C/C++) | C/C++: effectively no | SQLi test cases are Java/PHP/C# |
| **Big-Vul** | C/C++ | Yes (3,754) | Sparse | Near-zero | Memory-safety heavy; Fan et al. MSR 2020 |
| **PrimeVul** | C/C++ | Yes (~7k) | Sparse | Near-zero | Dedup of Big-Vul; pair eval |
| **MegaVul** | C/C++ | Yes (17,380) | Long tail (not top 10) | Near-zero | 59% memory-safety |
| **D2A** | C/C++ | Differential labels | **NO** | **NO** | Infer-driven: null deref, leaks, uninit only |
| **Devign** | C | Yes (binary labels) | No CWE annotations | No CWE annotations | Unsuitable for CWE-targeted eval |
| **VulDeePecker** | C/C++ | Mixed | **NO** | **NO** | CWE-119 + CWE-399 only |
| **SySeVR** | C/C++ | SARD-derived mostly | Yes (mostly synthetic) | No | 126 CWEs but mostly synthetic |
| **DiverseVul** | C/C++ | Yes (18,945) | Long tail | Near-zero | RAID '23 |
| **CASTLE** | C | No (crafted real-world-style) | **YES — 6+4** | **YES — 6+4** | Best CWE-78+CWE-89 C coverage available |
| **CWE-Bench-Java** | Java | Yes (120) | YES (Java) | — | Reference methodology only |

---

## 4. Recommendations for screw-agents

### 4.1 Phase 1 relevance (SQLi, CmdI, XSS, SSTI)
- **XSS (CWE-79)** and **SSTI (CWE-1336)** have **zero relevance** to C/C++. These are web template / browser vulnerabilities. Skip C/C++ for these agents entirely.
- **SQLi (CWE-89) in C/C++** has **almost zero real-world benchmark coverage.** Only **CASTLE** provides any C SQLi test cases (6 vulnerable + 4 clean). No meaningful CVE corpus exists. If/when we add C/C++ support to the SQLi agent, it will be for niche cases (C backends using libpq/sqlite3/MySQL C API) and the agent should lean on handwritten detection patterns plus CASTLE as the sole evaluation corpus.
- **CmdI (CWE-78) in C** is where C support actually matters. Coverage options (in priority order):
  1. **Juliet C/C++** — ~4,800 synthetic cases covering the full spectrum of sinks (`system`, `popen`, `execl*`, `execv*`, `spawn*`, `CreateProcess`, wchar_t variants). Good for unit-level agent heuristic validation.
  2. **CASTLE** — 10 compact C cases for cross-validation against synthetic/Juliet overfitting.
  3. **Lipp et al. dataset (192 CVE corpus)** — use as the real-world validation set, even though CWE-78 CVEs are a small minority. Ensures we don't ship a pattern matcher that only passes Juliet.
  4. **MegaVul / PrimeVul** — filter by CWE-78 to extract the long tail of real C CVEs. Expect <100 cases each.

### 4.2 When to add C/C++ to Phase 1 agents
- **Defer until after Phase 1 is stable on Python/JS/Java/Rust.** Injection vulns in C are a small fraction of the C security landscape (where memory safety dominates). The 4 Phase 1 agents' highest ROI is web-framework languages.
- **When added, prioritize CWE-78 only.** Add tree-sitter-c + tree-sitter-cpp grammars. Target sinks: `system`, `popen`, `execl`, `execlp`, `execle`, `execv`, `execvp`, `execve`, `_wsystem`, `_spawnl*`, `_wspawnl*`, `CreateProcess*`, `ShellExecute*`, `posix_spawn`. Test corpus: Juliet CWE-78 (pattern coverage) + CASTLE CWE-78 + filtered MegaVul/PrimeVul CWE-78 slice (real-world).
- **CWE-89 in C:** Only add if a user explicitly requests it. The evaluation signal is too thin to autoresearch against.

### 4.3 General evaluation methodology lessons (apply immediately, all languages)
- **Lipp et al.'s methodology** (CVE → patch → function-level ground truth → tool CWE mapping) should become the template for screw-agents' autoresearch loop regardless of language. The Zenodo artifact CSVs (`cwe_distr.csv`, `sca_data_*.csv`, `fct_stats_*.csv`) are worth studying as a data-model reference.
- **PrimeVul's 68% → 3% F1 collapse** (Big-Vul → PrimeVul) is the single most important cautionary result in this entire literature. Our autoresearch benchmarks MUST use dedupped, chronologically split, paired evaluation — never naive train/test splits on Big-Vul-like corpora. Otherwise YAMLs will silently overfit to dataset artifacts.
- **Synthetic-only validation is forbidden.** Lipp et al. prove Juliet performance does not predict real-world performance. Any agent that ships must be validated against at least one real-CVE corpus (Lipp, MegaVul slice, or PrimeVul slice).

### 4.4 Concrete deferred action items (post-Phase 1)
1. Download Lipp et al. Zenodo artifact (6515687), extract `cwe_distr.csv`, inventory the exact CWE-78/CWE-89 counts among the 192.
2. Download MegaVul full JSON, filter `cwe_id == "CWE-78"`, count functions and extract the CVE list.
3. Clone CASTLE, use it as the first C smoke-test for a future cmdi agent C/C++ extension.
4. Juliet CWE-78 ingestion — wrap in a parser that extracts BAD/GOOD pairs as a fixture format compatible with our existing benchmarks harness.

---

## Sources

- Lipp et al. ISSTA 2022 paper: https://dl.acm.org/doi/10.1145/3533767.3534380
- Lipp et al. preprint: https://mediatum.ub.tum.de/doc/1659728/1659728.pdf
- Lipp et al. Zenodo artifact: https://zenodo.org/records/6515687 (and 6600197)
- Juliet v1.3 C/C++ (NIST SARD): https://samate.nist.gov/SARD/test-suites/112
- NIST IR 8561 SARD documentation: https://nvlpubs.nist.gov/nistpubs/ir/2025/NIST.IR.8561.pdf
- Big-Vul (Fan et al. MSR 2020): https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset
- PrimeVul (Ding et al. 2024): https://arxiv.org/abs/2403.18624 | https://github.com/DLVulDet/PrimeVul
- MegaVul (Ni et al. MSR 2024): https://arxiv.org/abs/2406.12415 | https://github.com/Icyrockton/MegaVul
- D2A (Zheng et al. ICSE-SEIP 2021): https://arxiv.org/abs/2102.07995 | https://github.com/IBM/D2A
- Devign (Zhou et al. NeurIPS 2019): https://sites.google.com/view/devign
- VulDeePecker: https://github.com/CGCL-codes/VulDeePecker
- DiverseVul (Chen et al. RAID 2023): https://github.com/wagner-group/diversevul
- CASTLE benchmark: https://arxiv.org/html/2503.09433v2 | https://github.com/CASTLE-Benchmark
- CWE-Bench-Java (methodology reference): https://github.com/iris-sast/cwe-bench-java
