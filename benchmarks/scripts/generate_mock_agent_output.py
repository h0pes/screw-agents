"""Generate mock agent output for end-to-end smoke testing.

Walks all truth.sarif files in benchmarks/external/, generates mock agent
output at ~60% TPR and ~20% FPR as vuln/patched SARIF files per case.
Uses a deterministic RNG seeded from the file path so output is reproducible.
"""
from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path

from benchmarks.runner.sarif import load_bentoo_sarif, write_bentoo_sarif
from benchmarks.runner.models import Finding, FindingKind


# Mock agent parameters
TPR = 0.60   # probability of correctly flagging a vulnerable finding
FPR = 0.20   # probability of incorrectly flagging a patched finding


def _seed_from_path(path: Path) -> int:
    """Derive a deterministic integer seed from a file path."""
    digest = hashlib.sha256(str(path).encode()).hexdigest()
    return int(digest[:16], 16)


def generate_mock_output(
    truth_path: Path,
    *,
    tpr: float = TPR,
    fpr: float = FPR,
) -> tuple[list[Finding], list[Finding]]:
    """Generate mock vuln/patched findings from a truth.sarif.

    Returns (vuln_findings, patched_findings).
    - vuln_findings: each FAIL truth finding is included with probability tpr
    - patched_findings: each PASS truth finding is included with probability fpr
    """
    rng = random.Random(_seed_from_path(truth_path))
    ground_truth = load_bentoo_sarif(truth_path)

    vuln_findings: list[Finding] = []
    patched_findings: list[Finding] = []

    for f in ground_truth:
        mock = Finding(
            cwe_id=f.cwe_id,
            kind=f.kind,
            location=f.location,
            cve_id=f.cve_id,
            agent_name="mock",
            confidence=round(rng.uniform(0.5, 1.0), 3),
            message=f.message,
        )
        if f.kind == FindingKind.FAIL:
            if rng.random() < tpr:
                vuln_findings.append(mock)
        else:
            if rng.random() < fpr:
                patched_findings.append(mock)

    return vuln_findings, patched_findings


def main() -> None:
    """Walk all truth.sarif in benchmarks/external/ and write mock agent output."""
    root = Path(__file__).parent.parent
    external_dir = root / "external"

    if not external_dir.exists():
        print(f"No external/ directory found at {external_dir}")
        return

    count = 0
    for truth_path in sorted(external_dir.rglob("truth.sarif")):
        case_dir = truth_path.parent
        vuln_findings, patched_findings = generate_mock_output(truth_path)

        vuln_path = case_dir / "mock_agent_vuln.sarif"
        patched_path = case_dir / "mock_agent_patched.sarif"

        write_bentoo_sarif(vuln_path, vuln_findings, tool_name="mock")
        write_bentoo_sarif(patched_path, patched_findings, tool_name="mock")
        count += 1

    print(f"Generated mock agent output for {count} cases")


if __name__ == "__main__":
    main()
