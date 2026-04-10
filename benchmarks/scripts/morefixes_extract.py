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
"""
from __future__ import annotations

import os
import sys
from datetime import date
from pathlib import Path
from typing import Any

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
})

# ---------------------------------------------------------------------------
# Map MoreFixes language strings → our Language enum values.
# MoreFixes stores languages as lowercase strings; some have aliases.
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

# ---------------------------------------------------------------------------
# Schema configuration — MoreFixes column names vary across tables.
# Adjust here if a schema migration changes column names.
# ---------------------------------------------------------------------------
SCHEMA_CONFIG: dict[str, Any] = {
    # fixes table
    "fixes_table": "fixes",
    "fixes_cve_col": "cve_id",
    "fixes_score_col": "score",
    # commits table
    "commits_table": "commits",
    "commits_hash_col": "hash",
    "commits_repo_col": "repo",
    "commits_language_col": "language",
    "commits_cwe_col": "cwe",
    "commits_date_col": "committer_date",
    # method_change table
    "method_change_table": "method_change",
    "method_file_col": "file_name",
    "method_name_col": "name",
    "method_start_col": "start_line",
    "method_end_col": "end_line",
    "method_commit_col": "commit_hash",
    # Minimum quality score threshold (0-100, MoreFixes confidence)
    "min_score": 65,
}


def build_query(min_score: int = 65) -> str:
    """Return the SQL string that extracts qualifying MoreFixes commits.

    Filters applied:
    - fixes.score >= min_score (quality gate)
    - commits.cwe IN (active CWE integers)
    - commits.language IN (MOREFIXES_LANGUAGES)

    Returns a parameterised query with no interpolated values; callers must
    pass parameters to the DB driver to avoid injection (% placeholders for
    psycopg).
    """
    cfg = SCHEMA_CONFIG
    cwe_placeholders = ", ".join(["%s"] * len(ACTIVE_CWE_INTS))
    lang_placeholders = ", ".join(["%s"] * len(MOREFIXES_LANGUAGES))

    # IMPORTANT: These join conditions are SPECULATIVE — based on the documented
    # MoreFixes schema. After deploying the DB (Task 21 Step 4), inspect the
    # actual schema with \dt and \d <table> and update SCHEMA_CONFIG + this
    # query to match the real column names and foreign key relationships.
    return f"""
SELECT
    f.{cfg['fixes_cve_col']}          AS cve_id,
    f.{cfg['commits_cwe_col']}        AS cwe,
    f.{cfg['commits_language_col']}   AS language,
    f.{cfg['commits_repo_col']}       AS project,
    f.{cfg['commits_date_col']}       AS published_date,
    mc.{cfg['method_file_col']}       AS file_path,
    mc.{cfg['method_name_col']}       AS method_name,
    mc.{cfg['method_start_col']}      AS start_line,
    mc.{cfg['method_end_col']}        AS end_line
FROM {cfg['fixes_table']} f
JOIN {cfg['method_change_table']} mc USING ({cfg['fixes_cve_col']})
WHERE f.{cfg['fixes_score_col']} >= {min_score}
  AND f.{cfg['commits_cwe_col']} IN ({cwe_placeholders})
  AND lower(f.{cfg['commits_language_col']}) IN ({lang_placeholders})
ORDER BY f.{cfg['fixes_cve_col']}, mc.{cfg['method_file_col']}, mc.{cfg['method_start_col']}
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
        min_score: int = SCHEMA_CONFIG["min_score"]
        query = build_query(min_score)

        # Build ordered parameter list: CWE ints first, then language strings
        cwe_params = sorted(ACTIVE_CWE_INTS)
        lang_params = sorted(MOREFIXES_LANGUAGES)
        params = cwe_params + lang_params

        with conn.cursor() as cur:
            cur.execute(query, params)
            rows = cur.fetchall()
            col_names = [desc[0] for desc in cur.description]

        # Group rows by (cve_id, repo, commit_hash) → one BenchmarkCase each
        from collections import defaultdict
        groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
        for raw_row in rows:
            row = dict(zip(col_names, raw_row))
            key = (
                str(row.get("cve_id") or ""),
                str(row.get("repo") or ""),
                str(row.get("commit_hash") or ""),
            )
            groups[key].append(row)

        cases: list[BenchmarkCase] = []
        for (cve_id, repo, commit_hash), group_rows in groups.items():
            case = self._rows_to_case(cve_id, repo, commit_hash, group_rows)
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
        repo: str,
        commit_hash: str,
        rows: list[dict[str, Any]],
    ) -> BenchmarkCase | None:
        """Convert a group of DB rows (one commit, multiple methods) to a BenchmarkCase."""
        if not rows:
            return None

        first = rows[0]
        raw_lang = str(first.get("language") or "").lower()
        language = LANGUAGE_MAP.get(raw_lang)
        if language is None:
            return None  # unsupported language

        raw_cwe = first.get("cwe")
        try:
            cwe_int = int(raw_cwe) if raw_cwe is not None else None
        except (TypeError, ValueError):
            cwe_int = None
        if cwe_int not in ACTIVE_CWE_INTS:
            return None

        cwe_id_str = f"CWE-{cwe_int}"

        # Parse commit date → published_date
        raw_date = first.get("commit_date")
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
            finding = self._row_to_case(row, cwe_id_str, cve_id)
            if finding is not None:
                ground_truth.extend(finding)

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

        safe_repo = (repo or "unknown").replace("/", "__")
        case_id = f"morefixes-{cve_id or commit_hash[:12]}-{safe_repo}"

        return BenchmarkCase(
            case_id=case_id,
            project=repo or "unknown",
            language=language,
            vulnerable_version=f"pre-{commit_hash[:12]}",
            patched_version=commit_hash[:12],
            ground_truth=ground_truth,
            published_date=published,
            source_dataset=self.dataset_name,
        )

    def _row_to_case(
        self,
        row: dict[str, Any],
        cwe_id_str: str,
        cve_id: str,
    ) -> list[Finding] | None:
        """Convert a single method_change row to a fail+pass Finding pair.

        Returns None if the row lacks sufficient location information.
        """
        file_name = row.get("file_name")
        start_line = row.get("start_line")
        end_line = row.get("end_line")

        if not file_name or start_line is None:
            return None

        try:
            start = int(start_line)
            end = int(end_line) if end_line is not None else start
        except (TypeError, ValueError):
            return None

        if start > end:
            end = start

        location = CodeLocation(
            file=str(file_name),
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


def main() -> int:
    root = Path("benchmarks")
    extractor = MoreFixesExtractor(root=root)
    extractor.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
