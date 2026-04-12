# Benchmark Research Tier 4 — Rust Corpus (Phase 4 Reference) and Modern Ecosystems

_Date: 2026-04-09_
_Status: Reference document for Phase 4 Rust corpus construction (deferred from Phase 0.5)_
_Purpose: Inventory Rust CVE sources and evaluate multi-language CVE extraction tools_

> NOTE: This is a forward-looking reference document. Phase 0.5 will NOT build a Rust benchmark corpus. This file captures what is available and must be revisited when Phase 4 begins.

---

## 1. Rust Advisory Inventory (Phase 4 Corpus Seed)

### 1.1 Methodology

Source data:
- Local clone of `rustsec/advisory-db` at commit HEAD of 2026-04-09 (1,010 advisory TOMLs under `crates/`).
- GitHub GHSA API (`gh api /advisories/{ghsa_id}`) for CWE authority. The GHSA `cwes[]` field is curated by GitHub's Security Lab and is the source of truth used by Dependabot and `gh`. It overrides the free-form `categories`/`keywords` in RustSec TOMLs.
- GHSA search: `gh api "advisories?ecosystem=rust&cwes={id}&per_page=50"`.

Key finding about the RustSec taxonomy: its `categories = ["format-injection"]` label is a CATCH-ALL for "data goes into a format/protocol/DSL incorrectly". It covers SQL injection, HTTP request smuggling (CWE-444), ANSI injection (CWE-150), open redirects (CWE-601), email header injection, and XSS. You CANNOT map RustSec `format-injection` to a single CWE — you must look up each advisory's GHSA alias.

### 1.2 Advisories matching our 4 Phase 1 CWEs

Each row has its CWE classification taken from the GHSA API (authoritative). Where GHSA returned an empty `cwes` array, the row is marked `unverified (GHSA lists no CWE)`.

#### CWE-89 — SQL Injection

| RustSec ID | Crate | GHSA | CVE | GHSA CWE(s) | Affected function | Pre-fix commit | Crate type |
|---|---|---|---|---|---|---|---|
| RUSTSEC-2025-0043 | matrix-sdk-sqlite | GHSA-275g-g844-73jh | CVE-2025-53549 | **CWE-89** | `SqliteEventCacheStore::find_event_with_relations` (>= 0.11.0) | Advisory URL: matrix-rust-sdk GHSA page | Library (Matrix SDK SQLite backend) |
| RUSTSEC-2024-0365 | diesel | GHSA-wq9x-qwcq-mmgf | — | **CWE-89** | `diesel::pg::connection::stmt` truncating cast at `diesel/src/pg/connection/stmt/mod.rs#L36` | Fix PR: diesel-rs/diesel#4170 | ORM |
| RUSTSEC-2024-0363 | sqlx | GHSA-xmrp-424f-vfpx | — | unverified (GHSA lists no CWE; RustSec labels `format-injection` + `sql injection`; CVSS unset; DEFCON 32 "SQL Injection Smuggling" class — truncating cast at `sqlx-postgres/src/arguments.rs#L163`) | SQLx issue #3440 | ORM / DB toolkit |

Notes:
- The `sqlx` advisory is the same 4-GiB length-prefix smuggling attack class as the `diesel` one (same DEFCON 32 talk by Paul Gerste). GHSA has not filed a formal CWE for this advisory, but the Diesel twin IS CWE-89 per GHSA. It is reasonable to treat `sqlx` as CWE-89 in Phase 4 but the label must be noted as "derived, not GHSA-assigned".
- There are NO other CWE-89 advisories in the Rust ecosystem per GHSA search (2026-04-09). These three are the entire corpus.

#### CWE-78 / CWE-77 — OS Command Injection and Command Injection

GitHub's GHSA uses CWE-77 ("generic command injection") and CWE-78 ("OS command injection") somewhat interchangeably. I list both, since CWE-78 is the most specific match for our agent scope. I exclude advisories whose CWE-77 is clearly about database-query injection (SurrealQL) or memory data-races (the `kekbit`/`bunch`/etc cluster — these are MITRE CWE-77 mislabels, they are actually CWE-362 race conditions).

| RustSec ID | Crate | GHSA | CVE | GHSA CWE(s) | Affected function | Pre-fix commit | Crate type |
|---|---|---|---|---|---|---|---|
| RUSTSEC-2024-0446 | starship | GHSA-vx24-x4mv-vwr5 | CVE-2024-41815 | **CWE-77, CWE-78** | Custom command expansion in bash | Patched >= 1.20.0 | CLI tool (shell prompt) |
| RUSTSEC-2024-0335 | gix-transport | GHSA-98p4-xjmm-8mfh | CVE-2024-32884 | **CWE-77, CWE-88** | Malicious username passed to git binary | gitoxide GHSA page | Library (Git transport) |
| RUSTSEC-2023-0064 | gix-transport | GHSA-rrjw-j4m2-mf34 | CVE-2023-53158 | **CWE-78** | git-transport protocol handler | RustSec URL | Library (Git transport) |
| RUSTSEC-2021-0071 | grep-cli | (via `ripgrep` GHSA-g4xg-fxmg-vcg5) | CVE-2021-3013 | **CWE-78** | Windows PATH precedence (pwd-first) in ripgrep preprocessor | ripgrep CHANGELOG 13.0.0 | CLI tool |
| RUSTSEC-2020-0069 | lettre | GHSA-vc2p-r46x-m3vx | CVE-2020-28247 | **CWE-77** | `lettre::sendmail::SendmailTransport::send` — forged `to` addresses pass args to sendmail | lettre PR #508 commit bbe7cc53 | Email client library |
| (no RUSTSEC; external) | aliyundrive-webdav | GHSA-73v2-rxqp-7q4f | CVE-2024-29640 | **CWE-77** | — | Vuln writeup in external repo | Application (WebDAV bridge) |
| (no RUSTSEC; external) | deno | GHSA-hmh4-3xvx-q5hr | CVE-2026-27190 | **CWE-78** | Node compat shell metachar blocklist | deno commit 9132ad958c83 | JS runtime written in Rust |
| (no RUSTSEC; external) | deno | GHSA-4c96-w8v2-p28j | CVE-2026-32260 | **CWE-78** | Same class (incomplete blocklist) | deno GHSA page | JS runtime |
| (no RUSTSEC; external) | deno | GHSA-m2gf-x3f6-8hq3 | CVE-2025-61787 | **CWE-77** | Windows batch file execution | deno GHSA page | JS runtime |
| (no RUSTSEC; external) | deno | GHSA-m3c4-prhw-mrx6 | CVE-2026-22864 | **CWE-77** | Incomplete case-insensitive fix (Windows) | deno GHSA page | JS runtime |

Notes and exclusions:
- The `shlex` RUSTSEC-2024-0006 advisory (`GHSA-r7qv-8r2h-pg27`) has an EMPTY `cwes` field at GHSA, but its duplicate `GHSA-286m-6pg9-v42v` lists **CWE-116** (Improper Encoding/Escaping). This is "incorrect neutralization helper", which is CmdI-adjacent but not CWE-78 itself. I include it as a CmdI-relevant training example but NOT as a CWE-78 leaf.
- Pure Rust command-injection bugs where the vulnerable binary is itself a web/CLI app (not a library):
  - `starship`, `gix-transport` (x2), `grep-cli`/ripgrep, `lettre`, `aliyundrive-webdav` are RUSTSEC-visible.
  - The `deno` cluster is in GHSA Rust ecosystem but has no `crates/deno/` in rustsec/advisory-db (deno publishes through GHSA directly).
- Data-race advisories (`kekbit`, `bunch`, `dces`, `lexer`, `lever`, `multiqueue`, `rcu_cell`, `syncpool`, `toolshed`, `slock`, `cache`, `noise_search`, `v9`) returned from the CWE-77 search are NOT command injection. They are MITRE labeling errors; real CWE is CWE-362 (race condition). EXCLUDE from our corpus.

#### CWE-79 — Cross-Site Scripting

| RustSec ID | Crate | GHSA | CVE | GHSA CWE(s) | Affected function | Pre-fix commit | Crate type |
|---|---|---|---|---|---|---|---|
| RUSTSEC-2021-0074 | ammonia | GHSA-5325-xw5m-phm3 | CVE-2021-38193 | **CWE-79** | Mutation XSS via embedded SVG/MathML | ammonia PR #142 | HTML sanitizer library |
| RUSTSEC-2022-0003 | ammonia | GHSA-p2g9-94wh-65c2 | — | **CWE-79** | `ammonia::clean_text` space bug | ammonia PR #147 | HTML sanitizer library |
| RUSTSEC-2025-0071 | ammonia | GHSA-mm7x-qfjj-5g2c | — | **CWE-79** | Mutation XSS after removal (SVG/MathML) | Patched >= 4.1.2 | HTML sanitizer library |
| RUSTSEC-2021-0063 | comrak | GHSA-6wj2-g87r-pm62 | CVE-2021-38186 | **CWE-79** | Ampersand unescape in link targets | Patched >= 0.10.1 | Markdown → HTML library |
| RUSTSEC-2021-0026 | comrak | GHSA-xmr7-v725-2jjr | CVE-2021-27671 | **CWE-79** | Case-sensitive unsafe-scheme filter | Patched >= 0.9.1 | Markdown → HTML library |
| RUSTSEC-2021-0001 | mdbook | GHSA-gx5w-rrhp-f436 | CVE-2020-26297 | **CWE-79** | Search-page JS execution via crafted book | Patched >= 0.4.5 | Static site generator (Rust) |
| (no RUSTSEC) | cargo | GHSA-wrrj-h57r-vx9p | CVE-2023-40030 | **CWE-79** | cargo-timings HTML injection from dep names | rust-lang/cargo commit 9835622853f | Build tool |
| (no RUSTSEC) | rustfs | GHSA-v9fg-3cr2-277j | CVE-2026-27822 | **CWE-79** | Stored XSS in Preview Modal → admin takeover | rustfs GHSA page | Object-store server |
| (no RUSTSEC) | salvo | GHSA-rjf8-2wcw-f6mp | CVE-2026-22256 | **CWE-79** | Reflected XSS in `serve-static/dir.rs::list_html` L593 | salvo commit 16efeba312 | **Web framework** |
| (no RUSTSEC) | salvo | GHSA-54m3-5fxr-2f3j | CVE-2026-22257 | **CWE-79** | Stored XSS in `serve-static/dir.rs::list_html` L581 (upload filenames) | salvo commit 16efeba312 | **Web framework** |
| (no RUSTSEC) | vaultwarden | GHSA-vprm-27pv-jp3w | CVE-2024-55226 | **CWE-79** | Authenticated reflected XSS | vaultwarden 1.32.4 tag | Web application |
| (no RUSTSEC) | vaultwarden | GHSA-g5x8-v2ch-gj2g | CVE-2024-55224 | **CWE-79** | HTML injection | vaultwarden 1.32.4 tag | Web application |
| (no RUSTSEC) | deno_doc | GHSA-qqwr-j9mm-fhw6 | CVE-2024-32468 | **CWE-79** | HTML generator XSS | deno_doc commit 0f1ef3efbf16 | Doc generator |
| (no RUSTSEC) | pagefind | GHSA-gprj-6m2f-j9hx | CVE-2024-45389 | **CWE-79** | DOM clobbering → XSS in search UI | CloudCannon/pagefind GHSA | Static search library (Rust + JS output) |
| (no RUSTSEC) | static-web-server | GHSA-rwfq-v4hq-h7fg | CVE-2024-32966 | **CWE-79, CWE-80** | Stored XSS in directory listing | SWS GHSA page | **HTTP server** |
| (no RUSTSEC) | microbin | GHSA-mphm-gqh9-q59x | CVE-2023-27075 | **CWE-79** | Stored XSS in paste UI | microbin#142 | Web application (pastebin) |

#### CWE-1336 — Server-Side Template Injection

Search result: **zero advisories** match CWE-1336 in the Rust ecosystem on GHSA as of 2026-04-09.

The single GHSA hit (`GHSA-qp6f-w4r3-h8wg` / zebrad) is a mislabel — it is a Zcash node crash, not template injection.

Related but not CWE-1336:
- `better-macro` (GHSA-79wf-qcqv-r22r, CVE-2021-38196, CWE-94) — proc-macro RCE at compile time. Not runtime SSTI.
- `rssn` (GHSA-9c4h-pwmf-m6fj, CVE-2026-30960, CWE-94) — JIT code generation. Not SSTI.

**Conclusion:** there is NO real-world Rust SSTI CVE corpus to seed Phase 4 from. We will have to synthesize SSTI fixtures by auditing Tera / MiniJinja / Askama / Handlebars-rust APIs for misuse patterns (dynamic template string construction, `Tera::one_off` with attacker-controlled templates, etc.) and constructing synthetic benchmarks inspired by the Python Jinja2 SSTI corpus.

### 1.3 GHSA CWE Authoritative Mapping — How-To

For any RustSec TOML at `crates/{pkg}/{RUSTSEC-YYYY-NNNN}.md`:

1. Parse the `aliases` TOML array. It contains `CVE-*` and/or `GHSA-*` IDs.
2. For each `GHSA-*` alias, run `gh api /advisories/GHSA-xxxx-xxxx-xxxx --jq '.cwes'` to get the authoritative CWE list.
3. If the `cwes` array is empty AND the advisory has no CVE number, either:
   - Accept "unverified" and manually triage from the description, OR
   - Check whether a DUPLICATE GHSA exists (some shlex-style advisories have duplicate IDs created months later with better CWE data).
4. Do NOT trust the RustSec `categories` or `keywords` fields — they are free-form and label-unreliable. `format-injection` in particular conflates CWE-89 / CWE-79 / CWE-444 / CWE-150 / CWE-601 / CWE-116.
5. Inverse mapping (start from CWE): `gh api "advisories?ecosystem=rust&cwes={N}&per_page=50"`. Paginate for large CWEs.

### 1.4 Rust CVE landscape per CWE (summary counts after GHSA verification)

- **CWE-89 (SQL Injection):** 2 verified + 1 unverified-but-derived = **3** Rust advisories total. Crates: `matrix-sdk-sqlite`, `diesel`, `sqlx`.
- **CWE-78 (OS Command Injection):** 3 verified in RustSec (`starship`, `grep-cli`/ripgrep, `gix-transport` RUSTSEC-2023-0064) + 2 Deno (GHSA only) = **5**. Excluding the Deno JS-runtime noise, the Rust-library universe is effectively 3.
- **CWE-77 (Command Injection, generic):** ~5 real hits (`lettre`, `gix-transport` 2024, `starship` [dual label], `aliyundrive-webdav`, Deno) + ~14 false positives (data-race mislabels) = **~5** true hits.
- **CWE-79 (XSS):** **16** real hits after filtering. Strongest crate seeds for Phase 4: `ammonia` (×3), `comrak` (×2), `salvo` (×2 — web framework with clear pre-fix commits), `static-web-server`, `rustfs`, `mdbook`, `pagefind`, `cargo` (cargo-timings), `vaultwarden` (×2), `microbin`, `deno_doc`.
- **CWE-1336 (SSTI):** **0** Rust advisories. This is a gap — SSTI fixtures for Rust must be synthesized against Tera / MiniJinja / Askama / Handlebars-rust API surfaces.

**Total Rust Phase-5 seed CVEs matching our 4 Phase 1 CWEs: ~24 advisories (3 + 5 + 16 + 0).**

This is enough for an evaluation corpus (low double digits per CWE is the flawgarden reality-check norm) but tight. For CWE-1336 it is zero and we MUST synthesize.

---

## 2. CVE-to-Code Extraction Tools

### 2.1 CVEfixes (secureIT-project/CVEfixes)

- **Tool or dump?** BOTH. The repo contains the Python pipeline; the actual dataset is a SQLite/Postgres relational DB released via Zenodo (DOI 10.5281/zenodo.4476563).
- **Language support:** Language-agnostic — it mines any git repository referenced from an NVD CVE. Files are labeled with detected language.
- **CWE filtering:** Yes — the dataset is indexed by CWE and covers 272 distinct CWE types in v1.0.8.
- **Method-level pre/post code pairs:** YES — this is its headline feature. It extracts commit-, file-, AND method-level before/after code for every fix commit.
- **Coverage:** v1.0.8 (released) covers CVEs published up to **23 July 2024**. 12,107 vulnerability-fixing commits across 4,249 projects for 11,873 CVEs. 51,342 changed files, 138,974 changed functions.
- **Freshness:** Snapshot releases (not continuous). Current snapshot is 2024-07-23; last published release is v1.0.8.
- **OSV/GHSA integration:** NVD-driven (not OSV). You can cross-reference OSV manually.
- **Rust usability:** Yes for Rust advisories that have NVD CVE records — but Rust advisories without a CVE (many in RustSec) will not appear. Expect a CWE-79 / CWE-89 / CWE-78 overlap of only a handful of Rust crates.
- **License:** Code MIT, data CC BY 4.0.

### 2.2 MoreFixes (JafarAkhondali/Morefixes)

- **Tool or dump?** BOTH, but the README strongly recommends using the DB dump — running the pipeline from scratch takes multiple days.
- **Structure:** MoreFixes is explicitly built on top of CVEfixes and uses GHSA (GitHub Security Advisory DB) in addition to NVD for repository discovery. It is the strict superset.
- **Language support:** Language-agnostic (same mechanism as CVEfixes — any git repo).
- **CWE filtering:** Yes (via the relational schema).
- **Method-level pre/post code pairs:** YES — retains CVEfixes' commit/file/method extraction pipeline.
- **Coverage:** DB dump is `postgrescvedumper-2024-09-26.sql` (Zenodo DOI 10.5281/zenodo.13983082). Covers CVEs through 26 Sept 2024.
- **Freshness:** Snapshot; can be updated by re-running the pipeline against current GHSA+NVD.
- **Quality control:** Commits have a confidence `score` column; the README recommends a threshold of ≥65 to reduce noise. Commits below 65 are excluded from the `commits`, `file_change`, and `method_change` tables (but retained as metadata in `fixes`).
- **OSV/GHSA integration:** YES — this is the key differentiator from CVEfixes. MoreFixes clones `github/advisory-database` as a submodule to enrich repository discovery.
- **Rust usability:** Better than CVEfixes because GHSA covers Rust-only advisories (those without NVD CVEs), though the ecosystem-level hit count remains small.
- **Dependencies:** Python 3.10+, Docker, docker-compose, Postgres. Not macOS/Windows for full pipeline (dump restore works everywhere Docker works).

### 2.3 Recommendation for Phase 0.5

**Use MoreFixes.** Rationale:

1. **Strict superset.** MoreFixes pipeline is CVEfixes-derived and uses both NVD AND GHSA for discovery. For the same investment you get every CVEfixes row plus GHSA-only rows.
2. **Freshness.** 2024-09-26 vs 2024-07-23 (two extra months of 2024 disclosures including the second wave of LangChain/LLM SSTI CVEs).
3. **Rust coverage.** Only MoreFixes sees the GHSA-only Rust advisories (most Rust advisories lack NVD CVE numbers because RustSec publishes directly to GHSA without requesting a CVE).
4. **Score column.** Having an explicit confidence metric lets us threshold noise before spending compute on fixture generation.
5. **For Phase 0.5 our scope is JS/TS/Python/Ruby/PHP/Java/C#/Go** — all eight are first-class in both tools, but only MoreFixes has the GHSA ingestion that matters for the long tail (npm, RubyGems, Packagist, Maven, NuGet, Go modules).

**Deployment plan for Phase 0.5:** Download the Zenodo dump, restore into Docker postgres, query by CWE for our four IDs, filter to score ≥ 65, filter to the 8 target languages via the `language` field on `file_change`, materialize pre/post pairs. Do NOT run the full pipeline from scratch (the README explicitly warns against it).

Fallback if MoreFixes dump is stale or broken: use CVEfixes v1.0.8 from Zenodo as a drop-in replacement (same schema for the overlapping tables).

---

## 3. Additional Advisory Databases

### 3.1 rubysec/ruby-advisory-db
Alive, 1,057 stars, updated 2026-04-01. YAML-per-advisory flat-file database used by `bundler-audit`. Advisory schema includes `cvss_v3`, `url`, `patched_versions`, `unaffected_versions`, and optional `cwe` field (NOT always populated — many pre-2020 advisories have no CWE). CWE-79 and CWE-89 are well represented (Rails, Devise, Sinatra, Liquid, Nokogiri, etc.). CWE-1336 coverage is strong (Liquid / ERB / Haml SSTI advisories). Usable standalone OR through MoreFixes (GHSA mirror).

### 3.2 FriendsOfPHP/security-advisories
Alive, 2,108 stars, updated 2026-04-07 (daily). YAML-per-advisory flat-file database used by `composer audit`. Schema has `reference`, `branches` (with `versions` and `time`), and an optional `cve` field. Does NOT use CWE natively — classification is loose strings in the `title`. For CWE mapping we must cross-reference CVE → NVD → CWE. Strong coverage of CWE-89 (Symfony, Doctrine, Zend), CWE-79 (Twig, WordPress plugins via standalone advisories), CWE-78 (phpMailer, swiftmailer, Symfony Process), CWE-1336 (Twig, Smarty — historically rich SSTI landscape). Our CWE mapping should go through OSV.dev (which wraps this DB and normalizes CWE).

### 3.3 OSV.dev (google/osv.dev)
Unified OSS vulnerability DB with HTTP API (`https://api.osv.dev/v1/query`, 2,580 stars). Ingests from GHSA, PyPA, RustSec, Go, Maven, npm, NuGet, RubySec, Packagist, Debian, Alpine, Android, OSS-Fuzz, Linux kernel, UVI/UBUNTU, and more. Verified available 2026-04-09 (query endpoint returns HTTP 200). For our 4 CWEs OSV is the best single normalized API — query by `ecosystem` (`crates.io`, `npm`, `PyPI`, `Maven`, `RubyGems`, `Packagist`, `NuGet`, `Go`) then filter `database_specific.cwe_ids` or `aliases[]` for GHSA cross-reference. Do NOT use OSV in isolation for code extraction — it lacks pre/post code pairs; pair it with MoreFixes for the code half.

### 3.4 WPScan WordPress vulnerability database
`wpscanteam/wpscan` (9,539 stars). The database itself is at `https://wpscan.com/api/` and is commercial (free tier + paid). Schema covers WordPress core, plugins, themes — massive CWE-79 and CWE-89 corpus (plugins historically dominate XSS and SQLi counts ecosystem-wide). For Phase 0.5 and Phase 4 we probably DO NOT want raw WPScan data — the signal-to-noise is poor (many dupes, many theme-bundled jQuery issues, many unpatched plugins). Treat as supplementary only.

---

## 4. Phase 4 Rust Corpus Construction Plan

When we return to Rust corpus construction in Phase 4:

1. **Re-verify the advisory list.** Re-clone `rustsec/advisory-db` and re-run `gh api "advisories?ecosystem=rust&cwes={N}"` for CWE-78, 79, 89, 1336, 77, 80, 94, 116, 917. New Rust advisories land every month; our 2026-04-09 snapshot will be stale.
2. **Build from the GHSA side.** GHSA ecosystem filter is more complete than the RustSec categories. Start with GHSA, backfill with RustSec's affected-function metadata (which GHSA often lacks).
3. **Resolve pre-fix commits.** For each advisory, walk the `references[]` and the RustSec `url` to find the exact pre-fix commit SHA. When the advisory links to a GitHub commit or PR, clone the repo, check out SHA^1, extract the function body.
4. **Use RustSec `affected.functions`** — many advisories already pinpoint `crate::module::Type::method`. For these, the tree-sitter query is trivial. For others (starship, mdbook) we must read the fix PR manually.
5. **Synthesize CWE-1336.** No real Rust SSTI corpus exists. Build Tera / MiniJinja / Askama / Handlebars-rust misuse fixtures from the template-engine audit pattern set (dynamic template string construction, `render_str` with untrusted template text, helper-registration from user input, etc.).
6. **Integrate into autoresearch.** Treat the Rust corpus as a fourth benchmark tier alongside flawgarden/reality-check, with its own `metrics.yaml` output.

**Projected Phase 4 corpus size:** 20-30 Rust CVEs across CWE-78/79/89 plus 10-20 synthesized CWE-1336 fixtures. Small but usable for regression testing.

**Top-5 Phase-5 Rust seed crates** (highest real-world realism, cleanest pre-fix commits, best library-level detection signal):

1. **salvo** (web framework) — 2 XSS CVEs with explicit file:line refs in `serve-static/dir.rs` (commit `16efeba312a274`). Web framework is the most realistic detection context.
2. **diesel** (ORM) — CVE RUSTSEC-2024-0365, GHSA-wq9x-qwcq-mmgf, CWE-89, pre-fix file `diesel/src/pg/connection/stmt/mod.rs` at commit `ae82c4a5a133`. Already cited in our sqli.yaml.
3. **ammonia** (HTML sanitizer, 3 CVEs) — CWE-79, repeated mutation-XSS class, gives us multiple same-library fixtures at different points in time.
4. **lettre** (email library) — RUSTSEC-2020-0069, CWE-77 argument injection in `SendmailTransport::send`, pre-fix commit `bbe7cc5381c5380b54fb8bbb4f77a3725917ff0b`. Clean function-level target for CmdI agent.
5. **matrix-sdk-sqlite** — RUSTSEC-2025-0043, CWE-89, `format!()`-based SQL in `SqliteEventCacheStore::find_event_with_relations`. This is the canonical Rust SQLi textbook pattern: `format!("SELECT ... WHERE id = '{}'", user_input)` in a library maintained by a serious org.

---

## 5. Deferred Obligations (CRITICAL — do not forget)

Before Phase 4 kickoff, these actions must be executed and the results folded back into the sqli/cmdi/xss/ssti agents:

- [ ] Re-run `gh api "advisories?ecosystem=rust&cwes={N}"` for CWE-78/79/89/1336/77/94/116 and diff against the 24-advisory baseline in §1.2. New hits must be triaged.
- [ ] Clone the affected repo for each advisory in §1.2 and extract pre-fix (commit^1) and post-fix (fix commit) file+function pairs for the "affected.functions" entries.
- [ ] Synthesize a Rust SSTI fixture set covering Tera, MiniJinja, Askama, and Handlebars-rust since GHSA has zero real advisories for CWE-1336 in Rust (§1.2, §1.4).
- [ ] Reconcile the `sqlx` RUSTSEC-2024-0363 CWE classification with upstream. GHSA has no CWE assigned; we inherit the Diesel twin's CWE-89 but should request a proper GHSA CWE label from the SQLx maintainers or file a correction via the `rustsec/advisory-db` PR path.
- [ ] Validate RUSTSEC-2024-0006 (`shlex`). Its primary GHSA has empty CWE but the duplicate lists CWE-116. Decide whether to treat as CmdI training example or exclude.
- [ ] Add the Phase-5 Rust corpus to the benchmark `metrics.yaml` schema as a distinct tier.
- [ ] On return, re-pull MoreFixes for an updated dump (2024-09-26 will be ~18 months stale by Phase 4).
- [ ] Cross-reference the `cargo` cargo-timings XSS (CVE-2023-40030) — interesting edge case because the vulnerability is in build-tool output, not a web context. Decide whether this belongs in the XSS agent or is a separate "dev-tool output injection" sub-class.
- [ ] Verify the data-race CWE-77 mislabel cluster (kekbit/bunch/lexer/dces/...) is still filtered out of any automated GHSA ingestion — they are MITRE labeling errors and must NEVER end up in the CmdI corpus.
- [ ] Investigate Rust web frameworks beyond `salvo` and `actix-http`: `axum`, `rocket`, `warp`, `poem`, `loco-rs`. As of 2026-04-09 none of these have CWE-78/79/89 advisories in GHSA Rust-ecosystem search, but Phase 4 re-scan must confirm.
- [ ] Cross-reference the Phase-5 Rust corpus with the `domains/sqli.yaml` / `cmdi.yaml` / `xss.yaml` / `ssti.yaml` `few_shot_examples` sections — any corpus CVE that is ALREADY cited in a YAML must not be reused as a hold-out benchmark (data leakage into the agent knowledge base).
