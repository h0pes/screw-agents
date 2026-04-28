"""Extract benchmark cases from the MoreFixes Postgres database.

MoreFixes (Zenodo: https://doi.org/10.5281/zenodo.13983082) is a large-scale
CVE fix dataset with ~200k commits and method-level diffs. This script:
  1. Connects to the local Docker Postgres instance (see docker-compose.yml).
  2. Queries commits with score >= 65 that match active CWEs and supported
     languages.
  3. Maps each fix commit + its pre-patch parent to a BenchmarkCase with
     method-granular ground truth findings.

Run deploy_morefixes.sh first to bring the DB up. This script does NOT run
automatically — human invocation only (no CI autorun without a DB).

Usage:
    uv run python -m benchmarks.scripts.morefixes_extract
    # or with custom DSN:
    MOREFIXES_DSN="postgres://morefixes:morefixes@localhost:54321/morefixes" \
        uv run python -m benchmarks.scripts.morefixes_extract

Actual MoreFixes schema (verified against postgrescvedumper-2024-09-26.sql):

  fixes (cve_id, hash, repo_url, rel_type, score, extraction_status)
  commits (hash, repo_url, author, committer, msg, committer_date, ...)
  cwe_classification (cve_id, cwe_id)
  file_change (file_change_id, hash, filename, programming_language, code_before, code_after, ...)
  method_change (method_change_id, file_change_id, name, start_line, end_line, code, before_change, ...)

Join path:
  fixes.hash → commits.hash (commit metadata)
  fixes.cve_id → cwe_classification.cve_id (CWE mapping)
  fixes.hash → file_change.hash (file-level changes)
  file_change.file_change_id → method_change.file_change_id (method-level changes)
"""
from __future__ import annotations

import os
import sys
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import quote

from benchmarks.runner.models import (
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)
from benchmarks.scripts._active_cwes import ACTIVE_CWE_INTS
from benchmarks.scripts.ingest_base import IngestBase

# ---------------------------------------------------------------------------
# Supported languages — subset of Language enum that MoreFixes covers well.
# ---------------------------------------------------------------------------
MOREFIXES_LANGUAGES: frozenset[str] = frozenset({
    "python",
    "javascript",
    "typescript",
    "java",
    "go",
    "ruby",
    "php",
    "csharp",
    "c#",
})

# ---------------------------------------------------------------------------
# Map MoreFixes language strings → our Language enum values.
# MoreFixes stores languages as lowercase strings in file_change.programming_language.
# ---------------------------------------------------------------------------
LANGUAGE_MAP: dict[str, Language] = {
    "python":     Language.PYTHON,
    "javascript": Language.JAVASCRIPT,
    "typescript": Language.TYPESCRIPT,
    "java":       Language.JAVA,
    "go":         Language.GO,
    "golang":     Language.GO,
    "ruby":       Language.RUBY,
    "php":        Language.PHP,
    "csharp":     Language.CSHARP,
    "c#":         Language.CSHARP,
}

# Minimum quality score threshold (0-100, MoreFixes confidence).
MIN_SCORE = 65


def build_query(min_score: int = MIN_SCORE) -> str:
    """Return the SQL string that extracts qualifying MoreFixes commits.

    Join path (verified against actual schema):
      fixes → cwe_classification (via cve_id) for CWE filtering
      fixes → file_change (via hash) for language filtering + file info
      file_change → method_change (via file_change_id) for method-level location

    Filters:
      fixes.score >= min_score (quality gate)
      cwe_classification.cwe_id IN (active CWE strings like 'CWE-89')
      file_change.programming_language IN (supported languages)
    """
    cwe_placeholders = ", ".join(["%s"] * len(ACTIVE_CWE_INTS))
    lang_placeholders = ", ".join(["%s"] * len(MOREFIXES_LANGUAGES))

    return f"""
SELECT
    f.cve_id,
    cw.cwe_id                        AS cwe,
    fc.programming_language          AS language,
    f.repo_url                       AS project,
    c.committer_date                 AS published_date,
    f.hash                           AS commit_hash,
    fc.filename                      AS file_path,
    fc.code_before                   AS code_before,
    fc.code_after                    AS code_after,
    mc.name                          AS method_name,
    mc.start_line,
    mc.end_line
FROM fixes f
JOIN cwe_classification cw ON cw.cve_id = f.cve_id
JOIN commits c ON c.hash = f.hash
JOIN file_change fc ON fc.hash = f.hash
JOIN method_change mc ON mc.file_change_id = fc.file_change_id
WHERE f.score >= {min_score}
  AND cw.cwe_id IN ({cwe_placeholders})
  AND lower(fc.programming_language) IN ({lang_placeholders})
ORDER BY f.cve_id, fc.filename, mc.start_line
"""


class MoreFixesExtractor(IngestBase):
    """Extract BenchmarkCases from the MoreFixes Postgres database.

    Requires the Docker container to be running (see deploy_morefixes.sh).
    The DSN is read from the MOREFIXES_DSN environment variable or falls back
    to the default localhost:54321 credentials.
    """

    dataset_name = "morefixes"
    source_url = "https://doi.org/10.5281/zenodo.13983082"

    DEFAULT_DSN = (
        "host=localhost port=54321 dbname=morefixes user=morefixes password=morefixes"
    )

    def __init__(self, root: Path, dsn: str | None = None) -> None:
        super().__init__(root)
        self.dsn = dsn or os.environ.get("MOREFIXES_DSN", self.DEFAULT_DSN)
        self._conn: Any = None  # psycopg connection, opened lazily
        self._rows_by_case_id: dict[str, list[dict[str, Any]]] = {}

    # ------------------------------------------------------------------
    # IngestBase protocol
    # ------------------------------------------------------------------

    def ensure_downloaded(self) -> None:
        """Nothing to download — data lives in the Postgres DB.

        Verifies connectivity so callers get a clear error early rather than
        a confusing failure deep in extract_cases().
        """
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
        print(f"  [{self.dataset_name}] Postgres connection OK: {self.dsn}")

    def extract_cases(self) -> list[BenchmarkCase]:
        """Query MoreFixes and return one BenchmarkCase per CVE+repo pair."""
        conn = self._connect()
        query = build_query(MIN_SCORE)

        # Build ordered parameter list: CWE strings first, then language strings.
        # cwe_classification.cwe_id stores strings like "CWE-89", so we format
        # ACTIVE_CWE_INTS into that form.
        cwe_params = [f"CWE-{i}" for i in sorted(ACTIVE_CWE_INTS)]
        lang_params = sorted(MOREFIXES_LANGUAGES)
        params = cwe_params + lang_params

        with conn.cursor() as cur:
            cur.execute(query, params)
            rows = cur.fetchall()
            col_names = [desc[0] for desc in cur.description]

        # Group rows by (cve_id, project) → one BenchmarkCase each
        from collections import defaultdict
        groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for raw_row in rows:
            row = dict(zip(col_names, raw_row))
            key = (
                str(row.get("cve_id") or ""),
                str(row.get("project") or ""),
            )
            groups[key].append(row)

        cases: list[BenchmarkCase] = []
        for (cve_id, project), group_rows in groups.items():
            case = self._rows_to_case(cve_id, project, group_rows)
            if case is not None:
                cases.append(case)

        return cases

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self) -> Any:
        """Open (or return cached) psycopg connection."""
        if self._conn is not None:
            return self._conn
        try:
            import psycopg  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "psycopg is required for MoreFixes extraction. "
                "Run: uv sync"
            ) from exc
        self._conn = psycopg.connect(self.dsn)
        return self._conn

    def _rows_to_case(
        self,
        cve_id: str,
        project: str,
        rows: list[dict[str, Any]],
    ) -> BenchmarkCase | None:
        """Convert a group of DB rows (one CVE+project, multiple methods) to a BenchmarkCase."""
        if not rows:
            return None

        first = rows[0]
        raw_lang = str(first.get("language") or "").lower()
        language = LANGUAGE_MAP.get(raw_lang)
        if language is None:
            return None  # unsupported language

        raw_cwe = first.get("cwe") or ""
        # cwe_classification.cwe_id is a string like "CWE-89"
        cwe_id_str = str(raw_cwe)
        try:
            cwe_int = int(cwe_id_str.replace("CWE-", "").replace("cwe-", ""))
        except (TypeError, ValueError):
            return None
        if cwe_int not in ACTIVE_CWE_INTS:
            return None

        commit_hash = str(first.get("commit_hash") or "")

        # Parse commit date → published_date
        raw_date = first.get("published_date")
        published: date | None = None
        if raw_date is not None:
            try:
                if hasattr(raw_date, "date"):
                    published = raw_date.date()
                else:
                    from datetime import datetime
                    published = datetime.fromisoformat(str(raw_date)).date()
            except (ValueError, AttributeError):
                pass

        # Build ground truth from method_change rows
        ground_truth: list[Finding] = []
        for row in rows:
            findings = self._row_to_findings(row, cwe_id_str, cve_id)
            if findings is not None:
                ground_truth.extend(findings)

        if not ground_truth:
            # Fallback: create a minimal file-level finding
            ground_truth = [
                Finding(
                    cwe_id=cwe_id_str,
                    kind=FindingKind.FAIL,
                    cve_id=cve_id or None,
                    location=CodeLocation(
                        file="<unknown>",
                        start_line=1,
                        end_line=1,
                    ),
                ),
                Finding(
                    cwe_id=cwe_id_str,
                    kind=FindingKind.PASS,
                    cve_id=cve_id or None,
                    location=CodeLocation(
                        file="<unknown>",
                        start_line=1,
                        end_line=1,
                    ),
                ),
            ]

        safe_project = (project or "unknown").replace("/", "__").replace(":", "_")
        case_id = f"morefixes-{cve_id or commit_hash[:12]}-{safe_project}"

        case = BenchmarkCase(
            case_id=case_id,
            project=project or "unknown",
            language=language,
            vulnerable_version=f"pre-{commit_hash[:12]}",
            patched_version=commit_hash[:12],
            ground_truth=ground_truth,
            published_date=published,
            source_dataset=self.dataset_name,
        )
        self._rows_by_case_id[case.case_id] = rows
        return case

    def materialize(self, cases: list[BenchmarkCase]) -> None:
        """Write truth.sarif plus file-level before/after code snapshots."""
        super().materialize(cases)
        for case in cases:
            rows = self._rows_by_case_id.get(case.case_id, [])
            case_dir = self.download_dir / case.case_id
            for row in rows:
                rel_file = str(row.get("file_path") or "")
                if not rel_file:
                    continue
                _write_snapshot(
                    case_dir / "code" / "vulnerable" / _snapshot_name(rel_file),
                    row.get("code_before"),
                )
                _write_snapshot(
                    case_dir / "code" / "patched" / _snapshot_name(rel_file),
                    row.get("code_after"),
                )

    def _row_to_findings(
        self,
        row: dict[str, Any],
        cwe_id_str: str,
        cve_id: str,
    ) -> list[Finding] | None:
        """Convert a single method_change row to a fail+pass Finding pair.

        Returns None if the row lacks sufficient location information.
        """
        file_path = row.get("file_path")
        start_line = row.get("start_line")
        end_line = row.get("end_line")

        if not file_path or start_line is None:
            return None

        try:
            start = int(start_line)
            end = int(end_line) if end_line is not None else start
        except (TypeError, ValueError):
            return None

        if start > end:
            end = start

        location = CodeLocation(
            file=str(file_path),
            start_line=start,
            end_line=end,
            function_name=row.get("method_name") or None,
        )
        return [
            Finding(
                cwe_id=cwe_id_str,
                kind=FindingKind.FAIL,
                cve_id=cve_id or None,
                location=location,
            ),
            Finding(
                cwe_id=cwe_id_str,
                kind=FindingKind.PASS,
                cve_id=cve_id or None,
                location=location,
            ),
        ]


def _snapshot_name(rel_file: str) -> str:
    return quote(rel_file, safe="")


def _write_snapshot(path: Path, content: Any) -> None:
    if content is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(content), encoding="utf-8")


def main() -> int:
    root = Path("benchmarks")
    extractor = MoreFixesExtractor(root=root)
    extractor.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
