# Benchmark Research Tier 2 — Academic Datasets and Tools

_Date: 2026-04-09_
_Scope: Exhaustive survey of academic and industrial SAST benchmarks covering Java, JavaScript/TypeScript, and multi-language, for screw-agents Phase 1 (CWE-89 SQLi, CWE-78 CmdI, CWE-79 XSS, CWE-1336/CWE-94 SSTI)._

---

## 0. Executive Summary

The SMU ESEC/FSE'23 paper (Li et al., "Comparison and Evaluation on Static Application Security Testing (SAST) Tools for Java") was citing the **OpenSSF CVE Benchmark** (`ossf-cve-benchmark/ossf-cve-benchmark`) as reference [75]. That benchmark exists, is real, contains 218+ JavaScript/TypeScript CVEs, and is NOT currently referenced in our project docs. This is the single most important finding of this tier.

Second finding: beyond OpenSSF, the academic benchmark landscape for our four Phase 1 CWEs is dominated by C/C++ (Big-Vul, DiverseVul, PrimeVul, MegaVul, D2A). Multi-language datasets that include Java/Python/JavaScript are much scarcer; the standouts are **CVEfixes**, **CrossVul**, **ReposVul**, **MoreFixes**, and **MegaVul's Java track**.

Third finding: `flawgarden/reality-check` (our PRD's designated primary benchmark) currently covers only Java with 165 CVEs. Its own README says it plans to extend via CVEfixes. So CVEfixes is effectively the upstream engine for reality-check's future multi-language coverage.

---

## 1. OpenSSF JavaScript/TypeScript Benchmark — Deep Dive

### Identity
- **Repo:** https://github.com/ossf-cve-benchmark/ossf-cve-benchmark
- **Org:** https://github.com/ossf-cve-benchmark (separate org, not `ossf/`)
- **Announcement:** Black Hat Europe 2020, by the OpenSSF Security Tooling WG.
- **Announcement blog:** https://openssf.org/blog/2020/12/09/introducing-the-openssf-cve-benchmark/
- **Paper citation:** Li et al., ESEC/FSE'23, ref [75].

### Size and scope
- **Total CVEs:** 218 historical CVEs (the repo's `CVEs/` directory actually contains 223 JSON files as of enumeration via the GitHub Contents API; some files are placeholders/metadata).
- **Languages:** JavaScript and TypeScript only.
- **CVE time range:** 2016–2021 (heavy concentration in 2017–2019).
- **Activity:** Last commit January 2024, 88 commits total, 162 stars, 46 forks, 13 open issues, 13 open PRs. **Moderately maintained**, not actively curated. Should be treated as a stable historical snapshot.

### Ground-truth format
Each CVE is a JSON file at `CVEs/CVE-YYYY-NNNNN.json` containing:
- `CWEs`: list of CWE IDs in the form `CWE-079`, `CWE-078`, etc. Multiple CWEs per CVE are common.
- Vulnerable file path and specific line numbers.
- Pre-patch and post-patch commit SHAs.
- Repository link and package identifier.

This is **exactly the ground-truth structure we need** for a per-line SAST detection benchmark — comparable to `flawgarden/reality-check`'s format.

### Verified CWE coverage for our four agents
Sampled five CVE JSON files to confirm CWE tagging directly:

| CVE | CWEs present | Library | Confirms |
|---|---|---|---|
| CVE-2018-16487 | CWE-078, CWE-079, CWE-094, CWE-400, CWE-915 | lodash | CmdI + XSS + CodeInj |
| CVE-2018-3721  | CWE-078, CWE-079, CWE-094, CWE-400, CWE-915 | lodash | CmdI + XSS + CodeInj |
| CVE-2019-10744 | CWE-079, CWE-094, CWE-116                    | lodash | XSS + CodeInj |
| CVE-2017-16119 | CWE-400, CWE-730                             | fresh  | ReDoS (not ours) |

**Interpretation:** The benchmark uses multi-CWE tagging (a single finding may have 3–5 CWE labels). CVEs tagged as CWE-079 (XSS), CWE-078 (OS Command Injection), and CWE-094 (Code Injection, parent of CWE-1336 SSTI) are **definitively present**. CWE-089 (SQL Injection) presence is **unverified in my sample** and is likely very sparse or absent, because the benchmark is npm-centric and npm packages rarely ship SQL directly.

### How to run SAST tools
- CLI: `bin/cli run --tool [tool-name] [CVE-ids]`
- Tool drivers live in `config.json`.
- Supported tools out of the box: **ESLint, NodeJSScan, CodeQL**. Adding a tool = writing a driver.
- The harness produces per-CVE SARIF-like reports and tool-vs-ground-truth comparison.

### Verdict for screw-agents
**HIGHLY RELEVANT for CWE-79 and CWE-78/CWE-94 in JavaScript/TypeScript.** This is the only real-CVE JS/TS benchmark in existence at this scale, and we should absolutely add it to `benchmarks/` as a secondary evaluation dataset alongside `flawgarden/reality-check`. CWE-089 coverage is likely too thin to rely on here; we'd need to pull SQLi evaluation from a different source (reality-check Java side, or CVEfixes multi-language queries).

---

## 2. Per-Benchmark Analysis

### 2.1 Big-Vul (Fan et al., MSR 2020)
- **Paper:** "A C/C++ Code Vulnerability Dataset with Code Changes and CVE Summaries", MSR '20.
- **Repo:** https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset (mirror: `rshariffdeen/Big-Vul`)
- **Size:** 3,754 vulnerabilities from 348 GitHub projects, 91 CWE types, 2002–2019.
- **Languages:** C/C++ only.
- **CWE-79/78/89/1336 coverage:** CWE-78 (OS command injection) is applicable to C/C++ `system()`/`exec*()` CVEs and is present. CWE-89 is rare in C/C++. CWE-79 and CWE-1336 are out of scope (no web rendering in C).
- **Relevance to Phase 1:** LOW. Single-language C/C++ and not our primary languages.
- **Last updated:** 2020 (stale).

### 2.2 CVEfixes (Bhandari et al., PROMISE 2021)
- **Paper:** "CVEfixes: Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software", arXiv:2107.08760.
- **Repo:** https://github.com/secureIT-project/CVEfixes
- **Zenodo (v1.0.8):** https://zenodo.org/records/13138703
- **Size:** 12,107 vulnerability-fixing commits in 4,249 projects covering **11,873 CVEs across 272 CWE types**. 51,342 files / 138,974 functions with before/after code.
- **Languages:** **Multi-language.** The pipeline uses a deep-learning language classifier recognizing 30+ languages. No hard language filter — languages are detected per-file.
- **Dataset vs tool:** **BOTH.** The repo contains the Python collection scripts and the Zenodo releases are the frozen dataset snapshots.
- **CWE-79/78/89/1336 coverage:** Because it is CWE-agnostic scraping from NVD, it covers the full 272-CWE breadth — all four of our CWEs are present, though specific counts are not published in the README; you need to query the SQLite/CSV dump.
- **Last updated:** v1.0.8 covers CVEs published through 23 July 2024. **Actively maintained.**
- **Relevance to Phase 1:** **VERY HIGH** as an upstream data source. It is also the declared upstream for `flawgarden/reality-check`'s multi-language expansion.

### 2.3 PrimeVul (Ding et al., ICSE 2025)
- **Paper:** "Vulnerability Detection with Code Language Models: How Far Are We?", arXiv:2403.18624, ICSE '25.
- **Repo:** https://github.com/DLVulDet/PrimeVul
- **Size:** ~7,000 vulnerable functions + 229,000 benign functions, 140+ CWEs.
- **Languages:** **C/C++ only.**
- **Construction:** Reconstruction and cleanup of existing datasets (Big-Vul + others) with novel labeling achieving up to 3× accuracy over automatic labeling. Chronological splits to avoid LM contamination.
- **CWE coverage for us:** Same story as Big-Vul — CWE-78 yes, CWE-79/89/1336 effectively no.
- **Last updated:** v0.1 September 2024.
- **Relevance:** LOW for Phase 1. Valuable as a benchmark quality-engineering reference (labeling methodology), not as a direct dataset.

### 2.4 MegaVul (Ni et al., MSR 2024)
- **Paper:** "MegaVul: A C/C++ Vulnerability Dataset with Comprehensive Code Representations", arXiv:2406.12415.
- **Repo:** https://github.com/Icyrockton/MegaVul
- **Size:** 17,975 vulnerable functions + 335,898 non-vulnerable, from 9,288 commits across 992 repos, 2006-01 to 2023-10. **176 CWEs for C/C++, 115 CWEs for Java.**
- **Languages:** C, C++, **and Java** (Java track added 2024).
- **Java coverage:** Joern graph extraction succeeds at 100% on Java. Java track is relatively new and growing.
- **CWE-79/78/89/1336 coverage:** With 115 Java CWEs the canonical web injections should be represented, but the README does not provide per-CWE counts. Would need to query the dataset directly.
- **Last updated:** April 2024, **continuously updated**, GPL-3.0.
- **Relevance to Phase 1:** **MEDIUM-HIGH for Java CWE-89/78/79.** Worth adding to the Tier-2 benchmark candidates alongside reality-check.

### 2.5 D2A (Zheng et al., ICSE-SEIP 2021, IBM)
- **Paper:** "D2A: A Dataset Built for AI-Based Vulnerability Detection Methods Using Differential Analysis", arXiv:2102.07995.
- **Repo:** https://github.com/IBM/D2A
- **Languages:** **C/C++ only** (based on Infer static analyzer).
- **Construction:** Differential static analysis — issues reported by Infer on a version-pair that disappear after a bug-fix commit are labeled likely-true-positives; issues that persist are labeled likely-false-positives. Novel contribution: the benchmark preserves analyzer traces, bug types, and locations.
- **CWE coverage:** Not explicitly CWE-tagged; organized by Infer bug type (buffer overflow, null deref, etc.). Not naturally indexed by CWE-78/79/89/1336.
- **Relevance to Phase 1:** LOW (wrong languages, wrong taxonomy).

### 2.6 Devign (Zhou et al., NeurIPS 2019)
- **Paper:** "Devign: Effective Vulnerability Identification by Learning Comprehensive Program Semantics via Graph Neural Networks", arXiv:1909.03496.
- **Repo:** https://github.com/epicosy/devign (community mirror; official site: https://sites.google.com/view/devign)
- **Size:** Manually labeled on 4 C projects: Linux, QEMU, FFmpeg, Wireshark.
- **Languages:** **C only.**
- **CWE coverage:** The original Devign dataset is binary (vuln/not-vuln) at function level; not CWE-tagged in a structured way.
- **Relevance:** LOW. Historical baseline. Not useful for Phase 1.

### 2.7 CrossVul (Nikitopoulos et al., ESEC/FSE 2021)
- **Paper:** "CrossVul: a cross-language vulnerability dataset with commit data", ESEC/FSE '21.
- **Zenodo:** https://zenodo.org/records/4734050
- **Size:** 27,476 files from 1,675 GitHub repos, 5,131 unique CVEs, **168 CWEs**, **40+ programming languages**, 1.4 GB.
- **Languages:** **Explicitly multi-language, 40+ languages including Java, Python, JavaScript, PHP, Ruby, Go.** One of the few that gives PHP and Ruby coverage.
- **Construction:** Scraping NVD, following links to GitHub fix commits, downloading changed files before/after.
- **CWE-79/78/89/1336 coverage:** With 168 CWEs and the breadth of languages all four are represented — but per-CWE-per-language counts are not published in abstract; you must query the dataset.
- **Last updated:** 2021 (Zenodo snapshot). Not continuously updated.
- **Relevance to Phase 1:** **HIGH for PHP and Ruby coverage, which we have zero of elsewhere.** Medium for Java/Python/JS.

### 2.8 DiverseVul (Chen et al., RAID 2023)
- **Paper:** "DiverseVul: A New Vulnerable Source Code Dataset for Deep Learning Based Vulnerability Detection", arXiv:2304.00409.
- **Repo:** https://github.com/wagner-group/diversevul
- **Size:** 18,945 vulnerable functions + 330,492 non-vulnerable, 7,514 commits, **797 projects, 150 CWEs.**
- **Languages:** C/C++ only.
- **Construction:** Crawled security issue websites, extracted fix commits and function-level code. Claims 2× the size of CVEfixes's C/C++ slice and 295 more projects than prior datasets combined.
- **Relevance to Phase 1:** LOW (C/C++ only) but frequently cited as a C/C++ gold standard.

### 2.9 ReposVul (Wang et al., ICSE 2024 Industry Track)
- **Paper:** "ReposVul: A Repository-Level High-Quality Vulnerability Dataset", arXiv:2401.13169.
- **Repo:** https://github.com/Eshe0922/ReposVul
- **Size:** 6,134 CVEs across 1,491 projects and **236 CWE types**.
- **Languages:** **C (212,790 functions), C++ (20,302), Java (2,816), Python (26,308).** Multi-language.
- **Key contribution:** Repository-level granularity (not just function-level) with inter-procedural call relationships at repo/file/function/line levels. Uses LLM-based untangling to separate vuln-fixing changes from unrelated code churn.
- **Last updated:** ICSE 2024.
- **Relevance to Phase 1:** **HIGH for Python.** The Python slice (26k functions, filtered by CVE) is among the largest Python vulnerability datasets and is explicitly CWE-tagged. Java slice is smaller but usable.

### 2.10 MoreFixes (Akhoundali et al., PROMISE 2024)
- **Paper:** "MoreFixes: A Large-Scale Dataset of CVE Fix Commits Mined through Enhanced Repository Discovery", PROMISE '24.
- **Repo:** https://github.com/JafarAkhondali/Morefixes
- **Zenodo:** https://zenodo.org/records/13983082
- **Size:** **29,203 unique CVEs, 7,238 projects, 35,276 fix commits, 39,931 patch files.** Through 2024-09-26. **Largest CVE-fix-commit dataset to date.**
- **Format:** Released as a **16 GB PostgreSQL database** dump. CVE → CWE → file → method granularity. Repo metadata included.
- **Languages:** **Language-agnostic** (indexed by files, not languages).
- **Key contribution:** Positions itself explicitly as a successor/superset of CVEfixes with enhanced repository discovery heuristics.
- **Construction:** Sources are NVD + GitHub Advisory Database (GHSA).
- **Last updated:** 2024-09-26 (dataset). Active.
- **Relevance to Phase 1:** **VERY HIGH.** This is effectively the "latest, largest" CVE-fix-commit upstream. It supersedes CVEfixes for raw coverage and freshness. Pair MoreFixes (for breadth) with `flawgarden/reality-check` (for curated ground truth) and you have strong evaluation.

### 2.11 Vul4J (Bui et al., MSR 2022)
- **Paper:** "Vul4J: a dataset of reproducible Java vulnerabilities geared towards the study of program repair techniques".
- **Repo:** https://github.com/tuhh-softsec/vul4j (mirror: `aprorg/vul4j`)
- **Size:** 79 reproducible Java vulnerabilities across 51 projects, **25 CWEs**.
- **Languages:** **Java only.**
- **Key contribution:** Each vulnerability ships with a reproducible Proof-of-Vulnerability (PoV) test case and a human patch — not just source lines but an actually runnable repro. First of its kind for Java.
- **Size caveat:** Small (79 CVEs). But quality is high because each is hand-verified.
- **Relevance to Phase 1:** **MEDIUM for Java CWE-89/78/79.** Small but high-quality. Good for precision measurements; insufficient for recall estimates.

### 2.12 Project KB (SAP, 2019–present)
- **Repo:** https://github.com/SAP/project-kb (data on `vulnerability-data` branch)
- **Paper:** Ponta et al. at MSR 2019.
- **Size:** ~1,400 Java VFCs (vulnerability-fixing commits) manually curated, extended to ~1,500 including Mitre CVE mining. Some Python coverage.
- **Languages:** **Java (primary) and Python.**
- **Format:** YAML statements per vulnerability; tools (`kaybee`, `prospector`) for mining additional VFCs from text descriptions.
- **Relevance to Phase 1:** MEDIUM. Project KB's manually curated Java VFCs are the seed corpus that several later Java benchmarks build on, including `flawgarden/reality-check`.

### 2.13 SecVulEval (2025)
- **Paper:** "SecVulEval: Benchmarking LLMs for Real-World C/C++ Vulnerability Detection", arXiv:2505.19828.
- **Size:** 25,440 function samples across 5,867 unique CVEs, 1999–2024.
- **Languages:** C/C++ only.
- **Key contribution:** Statement-level (not just function-level) vulnerability annotations with contextual information.
- **Relevance to Phase 1:** LOW (C/C++ only).

### 2.14 CVE-Bench (UIUC Kang Lab, 2025)
- **Paper:** "CVE-Bench: A Benchmark for AI Agents' Ability to Exploit Real-World Web Application Vulnerabilities", arXiv:2503.17332.
- **Repo:** https://github.com/uiuc-kang-lab/cve-bench
- **Size:** 40 CVEs with CVSS 3.1 base score ≥ 9.0 (critical-severity only).
- **Languages:** Multi-language web apps.
- **Key orientation:** **Exploitation benchmark, not SAST benchmark.** Includes sandboxed deployments for LLM-driven exploitation. Not for static analyzer evaluation.
- **Relevance to Phase 1:** LOW for SAST evaluation; HIGH if we ever build an agentic-exploitation evaluator. Worth noting.

### 2.15 SeCodePLT (Zhang et al., 2024)
- **Paper:** "SeCodePLT: A Unified Platform for Evaluating the Security of Code GenAI", arXiv:2410.11096.
- **Size:** 5,900+ samples across **44 CWE-based risk categories**.
- **Languages:** **Python, C/C++, Java.**
- **Key orientation:** Secure code GENERATION benchmark (LLM-focused), not SAST. But ships with prompts + vulnerable code + patched code + test cases + PoC proofs.
- **Relevance to Phase 1:** MEDIUM. Can be repurposed as a SAST test corpus because it carries both the vulnerable and patched code, but that was not the authors' intent.

### 2.16 JavaVFC (2024)
- **Paper:** "JavaVFC: Java Vulnerability Fixing Commits from Open-source Software", arXiv:2409.05576.
- **Relevance:** A curated Java VFC dataset in the Project KB lineage. Worth tracking but I have not enumerated size/CWEs in this research pass.

### 2.17 SARD / Juliet (NIST, ongoing)
- **URL:** https://samate.nist.gov/SARD/
- **NIST IR 8561 (2025):** documents current state.
- **Size:** 450,000+ synthetic test cases across dozens of CWEs.
- **Languages:** C/C++, Java (Juliet 1.3), PHP (42,212 cases from TELECOM Nancy), C# and Python (VTSG v3).
- **Key caveat:** **SYNTHETIC, not real CVEs.** Our PRD explicitly deprioritizes synthetic benchmarks. Listed here for completeness and because PHP coverage is uniquely large.
- **Relevance to Phase 1:** LOW as our primary benchmark but USEFUL as a synthetic supplement especially for PHP where real-CVE coverage is thin.

---

## 3. CWE Coverage Matrix

"Y" = definitively present. "~" = likely present based on CWE count and language but not directly verified. "n/a" = structurally impossible (e.g. CWE-79 in C kernel code). "?" = unverified.

| Benchmark | Lang scope | CWE-89 SQLi | CWE-78 CmdI | CWE-79 XSS | CWE-94/1336 SSTI |
|---|---|---|---|---|---|
| **OpenSSF CVE Benchmark** | JS/TS | ? (likely sparse) | **Y** (verified) | **Y** (verified) | **Y** (verified — CWE-094) |
| **flawgarden/reality-check** | Java (+ future C#/Go/Py) | ~ | ~ | ~ | ~ |
| **CVEfixes** | multi (30+) | Y | Y | Y | Y (272 CWEs scraped from NVD) |
| **MoreFixes** | multi | Y | Y | Y | Y (29k CVEs scraped from NVD+GHSA) |
| **CrossVul** | multi (40+) | ~ | ~ | ~ | ~ (168 CWEs) |
| **ReposVul** | C/C++/Java/Python | ~ Java+Py | ~ Java+Py | ~ Java+Py | ~ (236 CWEs) |
| **MegaVul** | C/C++/Java | ~ Java | ~ Java | ~ Java | ~ (115 Java CWEs) |
| **Vul4J** | Java | ~ (25 CWEs) | ~ | ~ | ~ |
| **Project KB** | Java/Python | ~ | ~ | ~ | ~ |
| **SeCodePLT** | Py/C++/Java | Y (44 CWE cats) | Y | Y | Y |
| **Big-Vul** | C/C++ | ~rare | Y | n/a | n/a |
| **DiverseVul** | C/C++ | ~rare | Y | n/a | n/a |
| **PrimeVul** | C/C++ | ~rare | Y | n/a | n/a |
| **D2A** | C/C++ | n/a | ~ | n/a | n/a |
| **Devign** | C | n/a | ~ | n/a | n/a |
| **SecVulEval** | C/C++ | n/a | ~ | n/a | n/a |
| **CVE-Bench (UIUC)** | web multi | Y (exploitable) | Y | Y | Y | (but exploitation-only, not SAST) |
| **SARD/Juliet** | synthetic multi | Y | Y | Y | Y (but synthetic) |

---

## 4. Language Coverage Matrix

| Benchmark | C/C++ | Java | Python | JS/TS | PHP | Ruby | Go | C# |
|---|---|---|---|---|---|---|---|---|
| OpenSSF CVE Benchmark | | | | **Y** | | | | |
| flawgarden/reality-check | | **Y** | planned | | | | planned | planned |
| CVEfixes | Y | Y | Y | Y | Y | Y | Y | Y |
| MoreFixes | Y | Y | Y | Y | Y | Y | Y | Y |
| CrossVul | Y | Y | Y | Y | **Y** | **Y** | Y | Y |
| ReposVul | Y | Y | **Y** | | | | | |
| MegaVul | Y | **Y** | | | | | | |
| Vul4J | | **Y** | | | | | | |
| Project KB | | **Y** | Y | | | | | |
| SeCodePLT | Y | Y | Y | | | | | |
| Big-Vul / DiverseVul / PrimeVul / D2A / Devign / SecVulEval | **Y** | | | | | | | |
| SARD (synthetic) | Y | Y | Y | | Y | | | Y |

**Gaps still unfilled even with Tier 2:** Go vulnerability datasets are extremely thin (CVEfixes/MoreFixes by NVD scraping are the only options). Ruby is similarly thin; CrossVul is the only real-code source.

---

## 5. Benchmark Construction Tools (vs. static datasets)

Tools that AUTOMATE benchmark construction from CVE databases:

| Tool | Purpose | Repo |
|---|---|---|
| **CVEfixes pipeline** | NVD → fix commits → before/after code extraction. Python scripts on GitHub. | `secureIT-project/CVEfixes` |
| **MoreFixes pipeline** | Enhanced repo discovery over CVEfixes. PostgreSQL output. | `JafarAkhondali/Morefixes` |
| **SAP Prospector (Project KB)** | Natural-language CVE description → ranked fix-commit candidates. | `SAP/project-kb` |
| **SAP kaybee** | YAML-based vulnerability statement management | `SAP/project-kb` |
| **V-SZZ** | Vulnerability-inducing commit identification (version range affected by CVE). ICSE 2022. | See https://baolingfeng.github.io/papers/ICSE2022VSZZ.pdf |
| **OpenSZZ** | General SZZ (bug-introducing commit finder). | `clowee/OpenSZZ` |
| **SZZ Unleashed** | Line-number-aware SZZ. | `wogscpar/SZZUnleashed` |
| **Neural SZZ** | ML-driven SZZ variant (ASE 2023). | See https://baolingfeng.github.io/papers/ASE2023.pdf |
| **bentoo (FlawGarden)** | Harness for running and comparing SAST tools on reality-check. | under `flawgarden/` org |

For the autoresearch loop: **CVEfixes or MoreFixes is the right upstream to seed custom benchmark construction.** Combine with V-SZZ to resolve vulnerability introduction ranges if we ever need historical regression slices.

---

## 6. GHSA / OSV as data sources

- **GitHub Advisory Database** (`github/advisory-database`): security advisories in OSV format. Used by MoreFixes as one of two primary sources.
- **OSV.dev** (`google/osv.dev`): aggregator of 24 vulnerability data sources including GHSA, PyPA, RustSec, GSD. Machine-readable OSV schema. API lookup by commit hash or package version.
- **Practical pattern:** Advisory → affected package → package version → commit hash → GitHub API → vulnerable file. No academic paper I found describes a clean end-to-end extraction tool built purely on OSV.dev, but the infrastructure is there and we could build one in Phase 2.

---

## 7. Recommendations for screw-agents Phase 1

### Primary benchmark stack (use now)
1. **flawgarden/reality-check** — already our primary. Java, 165 CVEs, curated ground truth.
2. **OpenSSF CVE Benchmark** — ADD. JS/TS, 218 CVEs. Verified coverage of CWE-79 + CWE-78 + CWE-94. Closes our JavaScript evaluation gap that reality-check currently cannot cover.

### Secondary benchmarks (for breadth and recall)
3. **MoreFixes** (or CVEfixes) — multi-language, 29k CVEs, 272+ CWEs. Use as the upstream to build custom per-CWE per-language slices when reality-check/OpenSSF leave holes. Especially for CWE-89 SQLi where the JS ecosystem is thin.
4. **ReposVul** — Python slice is one of the largest Python-vuln-with-CWE datasets. Fills the Python gap that reality-check's "planned" status doesn't yet.
5. **MegaVul (Java track)** — Java with 115 CWEs and continuous updates. Complements the small reality-check Java set.

### Synthetic fallback (only where real-CVE coverage is missing)
6. **SARD/Juliet PHP** (TELECOM Nancy 42k cases) — only real option for PHP test coverage at scale. Use with explicit "synthetic" labeling.

### Not recommended for Phase 1
- Big-Vul, DiverseVul, PrimeVul, D2A, Devign, SecVulEval (all C/C++-only, wrong language family for our Phase 1 agents).
- CVE-Bench UIUC (exploitation benchmark, not SAST).
- SeCodePLT (code-generation benchmark; repurposable but not primary).

### Construction tools to adopt
- **CVEfixes** Python pipeline as the first autoresearch crawler implementation.
- **V-SZZ** or **Neural SZZ** for vulnerability-inducing-commit resolution.

---

## Sources

- [OpenSSF CVE Benchmark repo](https://github.com/ossf-cve-benchmark/ossf-cve-benchmark)
- [OpenSSF CVE Benchmark org](https://github.com/ossf-cve-benchmark)
- [OpenSSF CVE Benchmark announcement](https://openssf.org/blog/2020/12/09/introducing-the-openssf-cve-benchmark/)
- [Li et al., ESEC/FSE'23 SAST for Java](https://dl.acm.org/doi/10.1145/3611643.3616262)
- [Big-Vul repo](https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset)
- [CVEfixes repo](https://github.com/secureIT-project/CVEfixes)
- [CVEfixes Zenodo v1.0.8](https://zenodo.org/records/13138703)
- [PrimeVul repo](https://github.com/DLVulDet/PrimeVul)
- [PrimeVul paper (arXiv 2403.18624)](https://arxiv.org/abs/2403.18624)
- [MegaVul repo](https://github.com/Icyrockton/MegaVul)
- [MegaVul paper (arXiv 2406.12415)](https://arxiv.org/abs/2406.12415)
- [D2A repo](https://github.com/IBM/D2A)
- [D2A paper (arXiv 2102.07995)](https://arxiv.org/abs/2102.07995)
- [Devign paper (arXiv 1909.03496)](https://arxiv.org/abs/1909.03496)
- [CrossVul Zenodo](https://zenodo.org/records/4734050)
- [DiverseVul repo](https://github.com/wagner-group/diversevul)
- [DiverseVul paper (arXiv 2304.00409)](https://arxiv.org/abs/2304.00409)
- [ReposVul repo](https://github.com/Eshe0922/ReposVul)
- [ReposVul paper (arXiv 2401.13169)](https://arxiv.org/abs/2401.13169)
- [MoreFixes repo](https://github.com/JafarAkhondali/Morefixes)
- [MoreFixes Zenodo](https://zenodo.org/records/13983082)
- [Vul4J repo](https://github.com/tuhh-softsec/vul4j)
- [Project KB](https://github.com/SAP/project-kb)
- [JavaVFC paper (arXiv 2409.05576)](https://arxiv.org/html/2409.05576v1)
- [SecVulEval paper (arXiv 2505.19828)](https://arxiv.org/abs/2505.19828)
- [CVE-Bench (UIUC) repo](https://github.com/uiuc-kang-lab/cve-bench)
- [SeCodePLT paper (arXiv 2410.11096)](https://arxiv.org/abs/2410.11096)
- [flawgarden/reality-check](https://github.com/flawgarden/reality-check)
- [NIST SARD](https://samate.nist.gov/SARD/)
- [NIST IR 8561 (2025)](https://nvlpubs.nist.gov/nistpubs/ir/2025/NIST.IR.8561.pdf)
- [GitHub Advisory Database repo](https://github.com/github/advisory-database)
- [OSV.dev](https://osv.dev/)
- [OpenSZZ](https://github.com/clowee/OpenSZZ)
- [SZZ Unleashed](https://github.com/wogscpar/SZZUnleashed)
- [V-SZZ paper (ICSE 2022)](https://baolingfeng.github.io/papers/ICSE2022VSZZ.pdf)
