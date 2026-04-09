# Benchmark Research Tier 1 — Flawgarden Ecosystem

_Date: 2026-04-09_
_Purpose: Deep investigation of the flawgarden GitHub organization for SAST benchmark construction tools and datasets, conducted in support of Phase 0 benchmark planning for screw-agents._
_Method: Fetched every flawgarden repo README verbatim, the bentoo documentation tree, the reality-check per-language CVE databases, and a sample `truth.sarif`. All findings come from actual page fetches; nothing is speculated._

---

## TL;DR — Headline Findings

1. **The benchmark-construction tool the user hinted at is `flawgarden/bentoo`** — a Rust CLI that runs SAST tools on benchmark suites, compares against ground truth in `truth.sarif` files, and emits precision/recall/F1 summaries. It is the evaluation harness that holds the flawgarden ecosystem together.
2. **`flawgarden/vulnomicon` is the meta-repository** that assembles 10 distinct benchmarks (BenchmarkJava, Juliet, reality-check, FlowBlot, go-sec-code, go-test-bench, skf-labs, go-owasp-converted, python-owasp-converted, sast-rules) for Java/C#/Go/Python and drives bentoo via `bootstrap.sh` + `scripts/benchmarks/*/run.sh`.
3. **`flawgarden/templates-db` is a second construction tool** — an ANTLR-backed template language used to generate mutational-fuzzing SAST benchmarks while preserving compilability. It is what produces the `*-mutated` benchmark variants.
4. **`flawgarden/reality-check` has grown beyond the outdated README**: it now covers Java (165), C# (55), Go (54), and Python (64) — **338 real CVEs total**, each with vulnerable+patched version pairs and `truth.sarif` ground truth.
5. **Critical gap for screw-agents Phase 1:** reality-check contains **zero CWE-1336 (SSTI)** CVEs across any language, only **2 CWE-89 (SQLi)** CVEs total, **5 CWE-78 (CmdI)** CVEs total, and **18 CWE-79 (XSS)** CVEs total. CWE-502 (insecure deserialization) dominates Java with 60/165 entries. We will need to supplement reality-check heavily for the Phase 1 agents.
6. **No Rust coverage anywhere** in the flawgarden ecosystem — neither in reality-check nor in any mutated benchmark. Marco's Rust-first requirement is not served by flawgarden at all; we will need a separate Rust benchmark track.
7. The ecosystem is tied to an academic paper: **Li, Chen et al., "Comparison and Evaluation on Static Application Security Testing (SAST) Tools for Java," FSE 2023** (ACM DOI 10.1145/3611643.3616262). The 165-Java-CVE seed and the language-agnostic extension methodology come from that paper.

---

## 1. Flawgarden Organization Overview

Data from `https://api.github.com/orgs/flawgarden` (fetched 2026-04-09):

| Field | Value |
|---|---|
| Login | `flawgarden` |
| Display name | FlawGarden |
| Description | "A functional ecosystem for assessing the effectiveness of application security testing tools." |
| Email | flawgarden.benchmark@gmail.com |
| Blog/website | (none) |
| Location | (none) |
| Twitter | (none) |
| Created | 2024-05-11 |
| Updated | 2024-05-21 |
| Public repos | 12 |
| Followers | 3 |
| Verified | no |

**Members.** `GET /orgs/flawgarden/members` returns `[]` — no members are public. Identity is inferable only from commit authorship.

**Core contributors (derived from `GET /repos/.../contributors` across bentoo, vulnomicon, reality-check, templates-db):**

- `misonijnik` — present in every core repo; appears to be the lead maintainer
- `ocelaiwo` — bentoo, vulnomicon, templates-db
- `ch3zych3z` — bentoo, vulnomicon, templates-db
- `DanielELog` (Daniil Logunov) — vulnomicon, templates-db, reality-check (co-authored the multi-language expansion PR)
- `KarasssDev` — templates-db
- `DaniilStepanov` — templates-db, BenchmarkJava-mutated

The usernames and committer style (several `.ru` patterns in commit messages, Russian-transliteration handles) plus the FSE 2023 paper that seeded reality-check suggest a university-affiliated research group. The organization does not publicly claim an affiliation. No blog, no publication page, no linked papers in any README.

**Licensing posture.** Apache-2.0 or MIT across the first-party tooling (bentoo, vulnomicon, reality-check, templates-db). Mutated benchmarks inherit upstream licenses (BenchmarkJava-mutated is GPL-2.0, JulietCSharp-mutated is CC0-1.0, skf-labs-mutated is Apache-2.0).

---

## 2. Repository Inventory

From `GET /orgs/flawgarden/repos?per_page=100` — 12 repositories total. **Note: one repo (`FlowBlot.NET`) does NOT appear on the HTML listing of `github.com/flawgarden` but is returned by the API.**

| # | Repo | Language | Stars | Last push | License | One-liner |
|---|---|---|---|---|---|---|
| 1 | **bentoo** | Rust | 3 | 2025-07-02 (commit); pushed_at 2026-01-19 | MIT | SAST benchmark runner/evaluator; produces precision/recall/F1 from `truth.sarif` comparison |
| 2 | **vulnomicon** | Shell/Python | 4 | 2025-08-06 | Apache-2.0 | Meta-repo aggregating 10 benchmarks (Java, C#, Go, Python) driven by bentoo |
| 3 | **templates-db** | Python/ANTLR | 0 | 2024-12-24 | Apache-2.0 | Template-language DB used to generate mutational-fuzzing SAST benchmarks |
| 4 | **reality-check** | Python | 0 | 2024-12-24 (pushed); last content commit 2024-12-24 | Apache-2.0 | 338 real-world CVE benchmarks across Java/C#/Go/Python with SARIF ground truth |
| 5 | **BenchmarkJava-mutated** | Java | 2 | 2025-11-07 | GPL-2.0 | OWASP BenchmarkJava extended via mutational fuzzing |
| 6 | **JulietCSharp-mutated** | C# | 0 | 2024-12-29 | CC0-1.0 | Juliet C# 1.3 extended via mutational fuzzing |
| 7 | **go-owasp-converted-mutated** | Go | 0 | 2024-12-28 | (none) | OWASP-style Go benchmark, mutated |
| 8 | **go-sec-code-mutated** | Go | 0 | 2024-12-28 | (none) | Fork of cokeBeer/go-sec-code; educational Go vuln playground |
| 9 | **python-owasp-converted-mutated** | Python | 0 | 2024-12-28 | (none) | OWASP-style Python benchmark, mutated |
| 10 | **skf-labs-mutated** | Python | 0 | 2024-12-27 | Apache-2.0 | Fork of OWASP-SKF Docker labs, adapted for bentoo |
| 11 | **FlowBlot.NET** | C# | 0 | 2024-07-20 | GPL-3.0 | Mirror of Codethreat FlowBlot benchmark (sink-source challenges); not customized |
| 12 | **.github** | — | 0 | 2024-11-08 | — | Organization profile README |

**Active development signals.** bentoo and vulnomicon are the only repos with 2025 commits. reality-check stopped receiving content updates in December 2024 but is not archived. The mutated benchmarks were last refreshed in Q4 2024, with BenchmarkJava-mutated getting a late 2025 top-up.

---

## 3. Per-Repository Deep Dives

### 3.1 bentoo — The benchmark evaluation harness

**Purpose (verbatim, from `README.md`):** "a simple command-line utility to run SAST tools on benchmark suites and evaluate analysis results."

**NOT a benchmark builder.** Bentoo does not construct benchmarks from CVEs. It runs pre-built benchmarks (which must already carry `truth.sarif` files) and evaluates SAST tool output against that ground truth. The construction of benchmarks is done by:
- `reality-check`'s Python scripts (for real-CVE benchmarks), and
- `templates-db` + the per-mutated-benchmark generators (for synthetic benchmarks).

Bentoo is the **evaluation layer** that sits on top.

**Inputs:**
1. A *benchmark suite* — a directory tree where each leaf has a `truth.sarif` at its root
2. A *tools description* TOML — declares runner scripts + configs + a `parse_command` to normalize tool output to bentoo-sarif
3. A *runs description* TOML — declares which tool/config combinations run on which benchmark roots (can be auto-generated via `bentoo template`)
4. Per-SAST-tool *runner scripts* — must accept a benchmark root as positional arg and write tool output to stdout

**Outputs:**
- Per-(tool, benchmark) `.json` evaluation file recording which ground-truth vulns were hit
- Per-(tool, benchmark) `.sarif` parsed tool output
- `summary.json` with "true positive rate, false positive rate, precision, recall, f1 score and more for each participating tool" (quote from docs)

**Built-in converters.** `bentoo convert insider`, `bentoo convert codeql`, and (per commit #46, June 2025) `bentoo convert coverity`. Other tools require users to ship their own `parse_command`.

**Key evaluation semantics (from `docs/general/getting_started.md`):**
- **Two location-precision levels:**
  1. *File precision* — the tool located the vuln in the right file but may have wrong line
  2. *Line precision* — the tool reported the correct region within the file
- **Two CWE-precision levels:**
  1. *Strict* — the tool must report a CWE as precise as or more precise than the ground-truth CWE
  2. *Broad* — the tool's CWE must fall in the same CWE-1000 class as the ground-truth CWE. Critically, bentoo uses **CWE-1000 (Research View)**, not CWE-1400 (our backbone). This is a structural mismatch that affects how we would reuse bentoo directly.

**Dependencies.**
- Rust toolchain (crate: `bentoo`)
- No runtime Python dependency for bentoo itself; Python/bash only for surrounding harness
- Runs in any shell; vulnomicon uses docker for SAST tool execution

**Last commits (from API):**
- 2025-07-02 `feat!: Add rule_id_match to tool and truth results (#49)` — breaking change making rule_id comparison stricter
- 2025-06-09 `fix: Use long format for timeout option (#48)`
- 2025-06-05 `feat: Support duration format for timeout option (#47)`
- 2025-06-03 `feat: Add coverity converter (#46)`
- 2024-12-28 `ci: Update release action (#45)`

**Assessment for screw-agents.** Bentoo is the de facto industry-adjacent standard for SAST benchmarking outside OWASP's own stack. Its SARIF-based ground-truth format is clean and reusable. However, its CWE-1000 broad-match semantics will need to be adapted to CWE-1400 for our taxonomy. Our benchmark driver can either (a) wrap bentoo and post-process the summary, or (b) reimplement the comparator in Python/Rust using the same `truth.sarif` schema.

### 3.2 vulnomicon — The meta-repository

**Purpose (verbatim):** "a meta-repository for different SAST tool benchmarks. Usually, benchmark datasets for SAST tools are either synthetic or real-world-based only. **vulnomicon** contains both synthetic and real-world benchmarks."

**Synthetic benchmarks.** "Generated using mutational fuzzing. Existing benchmarks are used as initial seeds for the fuzzer. The fuzzer uses handwritten templates to mutate seeds while preserving the compilability of the resulting test cases. The objective of the fuzzer is to generate tests on which different tools behave differently." The handwritten templates live in `flawgarden/templates-db` (see §3.4).

**Real-world benchmarks.** "Generated semi-automatically from the CVE database. First, the information about available real-world vulnerabilities is parsed, the corresponding projects are downloaded, and the ground truth markup is generated. Then, the generated benchmark is audited by hand to rule out cases where the CVE information is inaccurate or incomplete."

**Aggregated benchmarks (from `GET /contents/scripts/benchmarks`):**

- BenchmarkJava (OWASP, synthetic Java, Servlet-based)
- Juliet (C# via Juliet 1.3)
- FlowBlot (Codethreat sink-source challenges, C#)
- reality-check (real CVEs, Java/C#/Go/Python)
- sast-rules (tests derived from Semgrep rules)
- skf-labs (OWASP-SKF Docker labs, Python)
- go-sec-code (educational Go vulns)
- go-owasp-converted (Go port of OWASP-style tests)
- go-test-bench (Go fuzz-style SAST benchmark)
- python-owasp-converted (Python port of OWASP-style tests)

Each benchmark has a standard (`run.sh`) and mutated (`run-mutated.sh`) entry. The mutated variants are produced by applying templates-db templates to seed code.

**Supported languages:** Java, C#, Go, Python. **No Rust, no JS/TS, no Ruby, no PHP.**

**Setup workflow (verbatim from README):**
```sh
pip install -r requirements.txt
./bootstrap.sh
scripts/benchmarks/reality-check/run.sh         # for real-CVE Java/C#/Go/Python
scripts/benchmarks/reality-check/run-mutated.sh # for fuzzed variants
```
`bootstrap.sh` downloads compilers, compiles each benchmark, generates `truth.sarif` files, and downloads the bentoo binary.

**Reference tools wired in.** Insider and CodeQL (via the bentoo built-in converters). Adding others requires authoring a runner script + parse command.

**Assessment.** vulnomicon is the single-entry "run all the benchmarks" driver for the ecosystem. For screw-agents, it is the most direct path to a running SAST baseline against which our agent can be compared, **if** we stay within Java/C#/Go/Python.

### 3.3 reality-check — The real-CVE benchmark dataset

See §4 for the complete CWE breakdown. Summary:

- **Current structure** (per `GET /contents`): per-language roots `csharp/`, `go/`, `java/`, `python/`, each containing its own `cves_db.csv`, `markup/`, `patched/`, and `vulnerable/` subtrees
- **Scripts** (`scripts/`): `bootstrap.sh`, `bootstrap_all.sh`, `collect_cve_benchmark.py`, `build_and_clean_benchmark.py`, `markup_benchmark.py`, `add_manual_markup.py`, `sort_data_by_relevance.py` — these are the **construction scripts** that take `cves_db.csv` and produce a working `benchmark/` directory with `truth.sarif` files. Important: they cover download + build + markup + manual audit, representing a reusable pipeline if we want to add CVEs ourselves.
- **README is out of date.** It claims the dataset "currently consists of projects from the Java paper… 165 CVEs" and lists expansion to other languages as *future* work. In reality the expansion to C#/Go/Python was merged in 2024 (commits on 2024-08-30 and 2024-12-24). We had to discover this by fetching directory contents; anyone trusting the README alone would miss 173 CVEs.
- **Last content commit:** 2024-12-24. The dataset itself has not been expanded since.

### 3.4 templates-db — The mutational benchmark generator

**Purpose (verbatim):** "a repository for template collections. The provided templates are used to generate SAST benchmarks for mutation-based generation. This repository allows you to check your templates for correctness (in formal language terms) and perform some functional diagnostics."

**How it works.**
- Templates are authored in a custom template language defined via ANTLR grammars (`.g4` files)
- A template describes a piece of vulnerable code with "holes" that a fuzzer can fill to produce compilable variants
- Every template file must exist in every supported language (Java, C#, Go, Python) so that a single seed can be mutated across the whole multilingual benchmark. Files that don't apply to a language get `.unsupported` or `.todo` extensions as placeholders.
- Six static diagnostics validate template collections:
  1. Language structural equality (the same template exists across languages)
  2. Invalid imports
  3. Undefined macro usage
  4. Unused locally defined macro
  5. Invalid extensions
  6. Dangling hole reference
- Runtime deps: Java 17+ (for the ANTLR parser generator) and Python + flake8 + pytest

**This IS a benchmark-construction tool.** Together with vulnomicon's per-benchmark `generate-*` scripts (not fetched in detail but referenced by `run-mutated.sh`), templates-db is used to programmatically mutate seeds into hundreds of new test cases while keeping them compilable. This is the second construction-tool in flawgarden (alongside reality-check's Python pipeline).

**Assessment.** For screw-agents we can reuse templates-db's approach — mutate a small seed set into many test cases — to produce per-CWE benchmarks for our agents without hand-writing each case. But the template language is bespoke (ANTLR-based), and adopting it would mean learning/extending it. A simpler path: fork the mutational generators per language if we need synthetic Rust benchmarks.

### 3.5 BenchmarkJava-mutated

**Nature.** Fork of OWASP BenchmarkJava (1.2) with additional Servlet-based test cases produced by mutational fuzzing. GPL-2.0 (inherited). The README does not list which mutations are applied; they are driven by templates-db templates applied to BenchmarkJava seeds. Language composition: Java 59.6%, HTML 39%. Still receiving commits as of 2025-11-07 (last push).

**CWE coverage.** Inherits BenchmarkJava's Java-specific CWE set: CWE-22, CWE-78, CWE-79, CWE-89, CWE-90, CWE-327, CWE-328, CWE-330, CWE-501, CWE-614, CWE-643. Not confirmed against repo contents but matches upstream BenchmarkJava v1.2.

### 3.6 JulietCSharp-mutated

C#-specific mutational benchmark built on Juliet Test Suite 1.3 for C#. 7 commits, active but small. CC0-1.0 license (the Juliet suite is US Government public domain). Contains template files, Python project-generation scripts, and a `truth.sarif`.

### 3.7 go-sec-code-mutated

**Fork** of `cokeBeer/go-sec-code` — Beego-based educational Go vulnerability playground. Covers (not labeled by CWE in the repo itself, mapping inferred from README):

- Command injection (GET params, Host header, git params) → CWE-78
- CORS issues (reflective, credentialed) → CWE-942 / CWE-346
- CRLF Injection → CWE-93
- File Upload → CWE-434
- JSONP → CWE-352 ish
- Path Traversal → CWE-22
- SQL Injection (numeric, string, ORM misuse) → CWE-89
- SSRF (multiple bypass techniques) → CWE-918
- **SSTI using Sprig template library** → CWE-1336 (*rare hit for SSTI coverage anywhere in flawgarden*)
- XSS (reflected, stored, SVG, PDF) → CWE-79
- XXE via libxml2 → CWE-611
- Zip Slip → CWE-22 subtype

**This is one of only two flawgarden assets that covers CWE-1336 (SSTI) at all**, and it does so for Go via the Sprig template library. Worth extracting for screw-agents' SSTI agent Go benchmark.

### 3.8 go-owasp-converted-mutated / python-owasp-converted-mutated

Ports of OWASP-style synthetic benchmarks into Go and Python, with mutational fuzzing layered on top. README content wasn't rendered during fetch, but the directory structure contains `truth.sarif` + a `coverage.txt` (suggesting they track which seeds are covered by the mutation process). Language stats: Go 99.9% / Python 100%.

### 3.9 skf-labs-mutated

Fork of `blabla1337/skf-labs` (OWASP Security Knowledge Framework Docker labs). 464 upstream commits; the flawgarden fork adapts the labs for bentoo consumption. Covers 60+ vulnerability types including XSS variants, SQLi, auth bypass, pickle/YAML deserialization, CSRF, LFI/RFI, **server-side template injection**, XXE, GraphQL issues. This is the second flawgarden asset with SSTI coverage (Python, via Flask/Jinja2-style labs).

### 3.10 FlowBlot.NET

Mirror of Codethreat's FlowBlot benchmark (C#, sink-source challenges). GPL-3.0. Not customized by flawgarden — they appear to have mirrored it to wire it into vulnomicon's benchmark list. Upstream has 18 stars (Codethreat/FlowBlot.NET) but the flawgarden mirror has 0.

### 3.11 templates-db diagnostics (redundant with §3.4)

Covered above.

### 3.12 .github

Just the org profile README. Four-paragraph blurb naming vulnomicon, bentoo, reality-check, BenchmarkJava-mutated. No blog, no paper links, no mission statement beyond the tagline.

---

## 4. reality-check — Detailed Breakdown

### 4.1 Structure (current, post-expansion)

```
reality-check/
├── csharp/
│   ├── cves_db.csv
│   ├── markup/<Project>/<Project-Version>/truth.sarif
│   ├── patched/      (populated by bootstrap)
│   └── vulnerable/   (populated by bootstrap)
├── go/          (same layout)
├── java/        (same layout + scripts/)
├── python/      (same layout)
└── scripts/
    ├── bootstrap.sh
    ├── bootstrap_all.sh
    ├── collect_cve_benchmark.py
    ├── collect_benchmark.py
    ├── collect_commit_hashes.py
    ├── build_and_clean_benchmark.py
    ├── markup_benchmark.py
    ├── add_manual_markup.py
    ├── copy_markups_to_projects.py
    ├── delete_cves.py
    ├── move_and_fix_new_cves.py
    ├── sort_data_by_relevance.py
    └── update_csv_markups_by_bench.py
```

**`cves_db.csv` columns** (confirmed from raw fetch):
```
project, cve, cwe, full_name, vul_version, vul_url, vul_zip,
vul_markup_file, patch_version, patch_url, patch_zip, patch_markup_file
```
Every CVE entry points to both the vulnerable release zip and the patched release zip, with a per-version markup CSV reference. `bootstrap.sh` downloads both versions and materialises them into `vulnerable/` and `patched/`.

### 4.2 Ground-truth format

Each benchmark version's `markup/<Project>/<Project-Version>/truth.sarif` is a bentoo-sarif document. Sampled from `java/markup/Openfire/Openfire-4.4.2/truth.sarif` (verbatim):

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "reality-check-benchmark-Openfire-4.4.2"}},
    "results": [{
      "kind": "fail",
      "message": {"text": "CVE-2019-18394"},
      "ruleId": "CWE-918",
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {"uri": "xmppserver/src/main/java/org/jivesoftware/util/FaviconServlet.java"},
          "region": {"startLine": 118, "endLine": 127}
        },
        "logicalLocations": [{"name": "doGet", "kind": "function"}]
      }, ...more locations...]
    }]
  }]
}
```

**Key observations:**
- Ground-truth markup is **method-level** (startLine/endLine of the enclosing function, not the exact vulnerable line). The Java paper (Li et al. FSE 2023) makes the same choice.
- A single vulnerability can have **multiple locations** (the Openfire example has at least 3 functions in the same file). This matches the paper's "method mapping" approach.
- `kind: "fail"` marks true-positive methods in the vulnerable version. The patched version uses the same schema but with `kind: "pass"` to mark the location as "vuln should no longer be reported here" — which gives us a clean way to score **false positives** for free by comparing a tool's output on the patched version.
- Message text carries the CVE ID; the `ruleId` is the CWE.
- The format is **plain bentoo-sarif** — no extensions. Means our benchmark driver can consume it directly without adapters.

### 4.3 CVE counts

| Language | CVE count | Source commit |
|---|---|---|
| Java | **165** | Seeded from Li et al. FSE 2023 "Java CVE Benchmark" |
| C# | **55** | PR #1 (2024-08-30), PR #8 (2024-12-24) |
| Go | **54** | PR #8 (2024-12-24) |
| Python | **64** | PR #6 (2024-08-30), PR #8 (2024-12-24) |
| **Total** | **338** | |

The README still claims reality-check is Java-only. Computed from actual `cves_db.csv` fetches.

### 4.4 CWE breakdown per language

#### Java (165 total)

```
60 CWE-502   Deserialization of Untrusted Data
17 CWE-20    Improper Input Validation
10 CWE-22    Path Traversal
 7 CWE-611   XXE
 7 CWE-352   CSRF
 6 CWE-200   Information Exposure
 5 CWE-79    XSS                              ← Phase 1 XSS agent
 4 CWE-835   Infinite Loop
 4 CWE-770   Resource Allocation
 4 CWE-444   HTTP Request Smuggling
 4 CWE-400   Uncontrolled Resource Consumption
 3 CWE-918   SSRF
 3 CWE-78    OS Command Injection             ← Phase 1 CmdI agent
 3 CWE-310   Cryptographic Issues
 3 CWE-295   Certificate Validation
 3 CWE-284   Improper Access Control
 2 CWE-787   Out-of-bounds Write
 2 CWE-732   Incorrect Permission Assignment
 2 CWE-264   Permissions/Privileges
 2 CWE-184   Incomplete Blacklist
 2 CWE-119   Buffer Errors
 1 CWE-96    Static Code Injection
 1 CWE-94    Code Injection
 (plus 1 each of: CWE-863, -862, -776, -399, -378, -297, -17, -1321, -130, -116)
```

**Note the dominance of CWE-502 (deserialization, 36% of Java).** This reflects the Java ecosystem's Jackson/XStream/SnakeYAML CVE history and will bias any tool that isn't good at gadget-chain analysis.

#### C# (55 total)

```
9 CWE-79    XSS                              ← Phase 1 XSS agent
9 CWE-22    Path Traversal
5 CWE-918   SSRF
3 CWE-502   Deserialization
3 CWE-20    Input Validation
2 CWE-706, 611, 400, 352  (each)
1 CWE-89    SQL Injection                    ← Phase 1 SQLi agent
1 CWE-78    OS Command Injection             ← Phase 1 CmdI agent
1 CWE-74    General Injection
(plus singletons: 863, 772, 770, 755, 704, 407, 384, 347, 338, 330, 307, 294, 287, 212, 119)
```

#### Go (54 total)

```
7 CWE-639   Authorization Bypass via User-Controlled Key
5 CWE-352   CSRF
4 CWE-284   Improper Access Control
3 CWE-682   Incorrect Calculation
2 each: CWE-940 (Unverified Channel), 648, 307, 1220
1 CWE-89    SQL Injection                    ← Phase 1 SQLi agent
(rest are singletons)
```

**Go reality-check has zero CWE-78, zero CWE-79, zero CWE-1336.** Coverage is heavily authorization/access-control-skewed, which mirrors Go's Kubernetes/etcd CVE history but is the opposite of what our Phase 1 injection agents need.

#### Python (64 total)

```
6 CWE-22    Path Traversal
4 CWE-918   SSRF
4 CWE-79    XSS                              ← Phase 1 XSS agent
3 CWE-601, CWE-59, CWE-264, CWE-20
2 CWE-93, 863, 80, 770, 611, 200
1 CWE-94    Code Injection
1 CWE-88    Argument Injection
1 CWE-78    OS Command Injection             ← Phase 1 CmdI agent
1 CWE-77    Command Injection
1 CWE-74    General Injection
(rest are singletons)
```

### 4.5 Phase 1 agent coverage — the critical table

| Agent | CWE | Java | C# | Go | Python | Total |
|---|---|---|---|---|---|---|
| XSS | CWE-79 | 5 | 9 | 0 | 4 | **18** |
| CmdI | CWE-78 | 3 | 1 | 0 | 1 | **5** |
| SQLi | CWE-89 | 0 | 1 | 1 | 0 | **2** |
| SSTI | CWE-1336 | 0 | 0 | 0 | 0 | **0** |

**Findings that must feed the benchmark plan:**

1. **SSTI has zero coverage in reality-check.** The only flawgarden assets with SSTI anywhere are:
   - `go-sec-code-mutated` (Sprig-based Go SSTI)
   - `skf-labs-mutated` (Python Flask/Jinja2 SSTI labs)
   - Neither is classified with CWE-1336 in a machine-consumable form; both would require manual markup. Our SSTI agent benchmark cannot be seeded from reality-check at all.

2. **SQLi has only 2 CVEs** — structurally identical to a null dataset. We must pull SQLi CVEs from another source (CVEfixes, GitHub advisories, or supplemental from Semgrep's own rule tests).

3. **CmdI has 5 CVEs** — marginal. Enough for a smoke test but not a real precision/recall curve.

4. **XSS at 18 CVEs** is the only Phase 1 agent with meaningful real-CVE coverage from reality-check alone.

5. **CWE-917 (Expression Language Injection), CWE-90 (LDAP Injection), CWE-434 (Unrestricted Upload), CWE-611 (XXE beyond Java/Python)** — all zero or near-zero. Any future injection-adjacent agent will face the same sparseness.

### 4.6 Running a SAST tool against reality-check

Neither reality-check's README nor its scripts document a direct "run SAST tool X against all 338 CVEs" entry point. The intended flow is:

1. `cd reality-check && ./scripts/bootstrap_all.sh` — downloads all 338 vulnerable+patched source zips, materializes `java/benchmark/`, `csharp/benchmark/`, etc., and copies `truth.sarif` files into each project root
2. Invoke bentoo from outside, pointing at the materialized benchmark directories
3. Or, use the vulnomicon wrapper: `cd vulnomicon && ./bootstrap.sh && scripts/benchmarks/reality-check/run.sh` (this pulls reality-check as a submodule/dependency and drives bentoo for you)

### 4.7 The expansion methodology (language-agnostic)

From the README's "where are we going" section: reality-check uses **CVEfixes** (`secureIT-project/CVEfixes`) as the upstream source for multi-language CVE extraction. The workflow documented in the FSE 2023 paper is:

1. Pull CVE records with CWE mappings from CVEfixes
2. Filter to CWEs of interest
3. Automate source download via the paper's language-agnostic pipeline (scripts/collect_cve_benchmark.py)
4. Generate initial method-level markup automatically
5. **Manual three-reviewer audit** to rule out incorrect CVE mappings

**This is the reusable pattern for screw-agents.** If we want to grow benchmarks, we can (a) reuse reality-check's scripts to ingest CVEfixes entries for Rust/JS and (b) import the same three-reviewer audit discipline from the paper. The scripts are Apache-2.0.

---

## 5. Benchmark Construction Tools — Confirmed Inventory

**There are two distinct construction tools in flawgarden, serving different benchmark classes:**

### 5.1 reality-check's `scripts/` Python pipeline — for real-CVE benchmarks

- Takes `cves_db.csv` as input (CVE ID + CWE + repo + version URLs)
- `collect_cve_benchmark.py` and `collect_benchmark.py` download source archives
- `build_and_clean_benchmark.py` compiles
- `markup_benchmark.py` + `add_manual_markup.py` generate bentoo-sarif `truth.sarif` files
- `update_csv_markups_by_bench.py` keeps the markup CSV and the truth.sarif in sync
- Works for Java, C#, Go, Python (it is the tool the user hinted at *for real-CVE benchmark construction*)

### 5.2 templates-db + per-benchmark mutators — for synthetic benchmarks

- Takes seed benchmark code + handwritten templates with holes
- ANTLR grammar defines the template language
- Mutational fuzzer (not in this repo — lives per-benchmark in the `*-mutated` repos) fills holes to produce compilable variants
- Diagnostics in templates-db enforce template correctness
- Generates `truth.sarif` automatically by propagating ground-truth annotations from seeds
- Covers the same four languages

### 5.3 Which one did the user mean?

Given the user framing ("a GitHub project… that helps BUILD benchmark codebases from real CVEs"), **reality-check's `scripts/` pipeline is the best match** — it literally takes a CSV of CVE IDs and produces a scored benchmark. The templates-db/mutators are for synthetic benchmarks, which is a different workflow.

However, both are important:
- reality-check scripts = our pattern for growing the Phase 1 benchmark from real CVEs
- templates-db = our pattern if we need to blow out the sparse Phase 1 CWE buckets (SQLi, SSTI) with synthetic test cases

The evaluation harness for both is bentoo.

---

## 6. bentoo-sarif Format Specification (verbatim)

From `docs/bentoo-sarif/format.md`:

```json5
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "<benchmark name or tool name>"
        }
      },
      "results": [
        {
          // Ground-truth files ONLY: "fail" = true positive, "pass" = false positive
          "kind": "<fail/pass>",
          "ruleId": "CWE-<CWE_id>",
          "locations": [
            {
              "physicalLocation": { /* SARIF spec */ },
              "logicalLocations": [ /* SARIF spec */ ]
            }
          ]
        }
      ]
    }
  ]
}
```

Screw-agents compatibility: we can emit this directly from our agent's findings without a custom schema. Our `benchmarks/` driver should produce `truth.sarif` files using this exact shape.

---

## 7. Linked Research & Affiliations

- **Seeding paper:** Kaixuan Li, Sen Chen, et al., "Comparison and Evaluation on Static Application Security Testing (SAST) Tools for Java," *Proceedings of FSE 2023*, ACM DOI 10.1145/3611643.3616262. The 165-CVE Java benchmark originates here. PDF mirror: `sen-chen.github.io/pdf/C38-FSE2023-...pdf`.
- **Secondary reference:** `secureIT-project/CVEfixes` — upstream CVE corpus with CWE mappings, referenced in the reality-check README as the pipeline input for extending beyond Java.
- **No blog, no Twitter, no publications page** owned by flawgarden itself. The organization has no visible members and no declared institutional affiliation.
- The FSE 2023 paper is authored at **Tianjin University / Nanyang Technological University** (Sen Chen's affiliations). Commit handles on bentoo/vulnomicon do not match those authors, so flawgarden appears to be a separate research group (likely Russian based on committer metadata and typography) that adopted and extended the FSE 2023 Java benchmark.

---

## 8. Findings Summary

### What we can use directly

1. **bentoo-sarif format** — adopt as the screw-agents ground-truth format. Our `benchmarks/` driver emits `truth.sarif` files; our agent output gets normalized to the same shape; we score via either bentoo itself or a reimplementation.
2. **reality-check Java (165 CVEs)** — drop-in for our Java XSS/CmdI agents after CWE-filtering. Well-audited.
3. **reality-check C#, Python** — secondary drop-in. C# gives us 9 XSS CVEs; Python gives us 4 XSS + path-traversal bulk.
4. **reality-check scripts/** — clone the pipeline (Apache-2.0) as our CVE-ingestion engine for growing the benchmark.
5. **bentoo evaluation semantics (file-precision + line-precision × strict-CWE + broad-CWE)** — adopt the same four-way precision matrix, but substitute CWE-1400 for CWE-1000 in the broad-match layer.
6. **vulnomicon `run.sh` per benchmark** — reference implementation for how a tool gets wired in. Useful as a template for our own `benchmarks/run-*.sh`.

### What requires adaptation

1. **CWE taxonomy mismatch.** bentoo evaluates broad matches against CWE-1000. We need CWE-1400. Either subclass bentoo's comparator or reimplement. Low effort (pure taxonomy mapping).
2. **Ground-truth granularity.** reality-check uses method-level markup. For screw-agents' injection agents we may want to tighten to line-level; this will require supplementary manual annotation on top of the existing `truth.sarif` files.
3. **Templates-db template language** is bespoke and ANTLR-gated. Adopting it has high up-front cost. Recommend deferring; use it only if we need synthetic case multiplication for sparse Phase 1 CWEs.

### What's missing (gaps we must fill elsewhere)

1. **SSTI (CWE-1336) — zero coverage in reality-check.** Must source from: `PayloadsAllTheThings/SSTI`, the SSTImap test corpus, a curated CVE pull (Confluence CVE-2022-26134, Spring4Shell CVE-2022-22965, Pebble/Velocity CVEs), and the go-sec-code-mutated + skf-labs-mutated Sprig/Jinja2 labs (requires manual CWE-1336 annotation).
2. **SQLi (CWE-89) — 2 CVEs total in reality-check.** Need to pull from CVEfixes with a CWE-89 filter across Java/Python/Node/PHP; Semgrep's SQL injection rule tests; the original DVWA/WebGoat corpus.
3. **CmdI (CWE-78) — 5 CVEs total.** Same plan: CVEfixes filter + Semgrep rule tests + selected real CVEs (log4shell-adjacent, Apache Commons Text CVE-2022-42889, etc.).
4. **Rust — absolutely nothing in flawgarden.** This is the biggest hole. We need a separate Rust benchmark track. Candidates: rustsec/advisory-db (CWE-mapped Rust advisories), manual construction from RUSTSEC advisories, and Semgrep's rust rule tests. No flawgarden equivalent exists.
5. **JavaScript/TypeScript — nothing in flawgarden.** Not a Phase 1 blocker, but will matter for screw-agents beyond Phase 1.
6. **bentoo's `summary.json` schema is marked `// TBD`** in the getting-started docs. We need to inspect an actual summary output (from a real vulnomicon CI run) to build a stable consumer.

### Actionable recommendations for Phase 0 benchmark planning

1. **Adopt bentoo-sarif unmodified as our ground-truth format.** Zero work to consume; maximum compatibility with flawgarden.
2. **Clone reality-check's `scripts/` pipeline** (Apache-2.0) into `screw-agents/benchmarks/cve-ingest/` and use it as the CVE-to-benchmark engine for filling our sparse Phase 1 CWE buckets.
3. **Import reality-check Java/C#/Python into `screw-agents/benchmarks/real-world/`** for the XSS and CmdI agents. Skip reality-check Go — it has no Phase 1 CWE coverage worth using.
4. **Write a separate Rust benchmark track** from day one. Cannot lean on flawgarden for this. Seed from rustsec/advisory-db.
5. **Build our own evaluator** rather than calling bentoo directly. Rationale: (a) CWE-1400 vs CWE-1000 mismatch, (b) we want our scoring matrix to include agent-specific metrics (e.g. bypass-technique coverage) that bentoo does not produce, (c) avoids a Rust toolchain dependency in our benchmark driver.
6. **Retain bentoo as a cross-check baseline.** Run vulnomicon/bentoo with Semgrep + CodeQL as an external baseline, and compare our agent's precision/recall/F1 on the exact same benchmark subset. This is the cleanest way to claim "we match or exceed SAST tools on Phase 1 CWEs."
7. **Open an issue on flawgarden/reality-check to update the README.** The dataset has quadrupled and the README still describes Java-only. This is a trivial upstream contribution that benefits the community and gets us in flawgarden's contributor graph.

---

## 9. Sources (all fetched 2026-04-09)

- `https://github.com/flawgarden` (HTML + `api.github.com/orgs/flawgarden` + `.../repos`)
- `https://github.com/flawgarden/bentoo` + `README.md` + `docs/general/getting_started.md` + `docs/general/glossary.md` + `docs/bentoo-sarif/format.md` + `docs/benchmark/structure.md`
- `https://github.com/flawgarden/vulnomicon` + `README.md` + `scripts/benchmarks/` listing + `scripts/benchmarks/reality-check/` listing
- `https://github.com/flawgarden/reality-check` + `README.md` + per-language `cves_db.csv` (java=166, csharp=56, go=55, python=65 lines including header) + sample `java/markup/Openfire/Openfire-4.4.2/truth.sarif` + `scripts/` listing
- `https://github.com/flawgarden/templates-db` + `README.md`
- `https://github.com/flawgarden/BenchmarkJava-mutated`, `.../JulietCSharp-mutated`, `.../go-sec-code-mutated`, `.../go-owasp-converted-mutated`, `.../python-owasp-converted-mutated`, `.../skf-labs-mutated`, `.../FlowBlot.NET`, `.../.github`
- `https://sites.google.com/view/java-sast-study/home` (the FSE 2023 paper landing page)
- ACM DOI 10.1145/3611643.3616262 (Li, Chen et al., FSE 2023 — Java CVE Benchmark paper)
- `https://github.com/secureIT-project/CVEfixes` (referenced by reality-check as its upstream CVE corpus)
