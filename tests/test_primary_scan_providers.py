from screw_agents.primary_scan import (
    FixturePrimaryScanRunner,
    PrimaryScanInput,
    PrimaryScanParticipant,
)


def _finding_dict():
    return {
        "id": "sqli-001",
        "agent": "sqli",
        "domain": "injection-input-handling",
        "timestamp": "2026-05-04T10:00:00Z",
        "location": {"file": "src/app.py", "line_start": 12},
        "classification": {
            "cwe": "CWE-89",
            "cwe_name": "SQL Injection",
            "severity": "high",
            "confidence": "high",
        },
        "analysis": {"description": "Unsafely concatenated SQL query."},
        "remediation": {"recommendation": "Use parameterized queries."},
    }


def test_fixture_primary_scan_runner_returns_validated_findings():
    participant = PrimaryScanParticipant(provider="fixture", transport="fixture")
    runner = FixturePrimaryScanRunner(
        participant=participant,
        findings=[_finding_dict()],
        provider_metadata={"model": "fixture"},
    )
    scan_input = PrimaryScanInput(
        run_id="run-1",
        session_id="session-1",
        participant=participant,
        agents=["sqli"],
        target={"path": "src/app.py"},
        prompt="Scan for SQL injection.",
    )

    result = runner.run(scan_input)

    assert runner.run_count == 1
    assert result.run_id == "run-1"
    assert result.transport_kind == "fixture"
    assert result.findings[0].id == "sqli-001"
    assert result.provider_metadata == {"model": "fixture"}
    assert result.guardrails == {"fixture_runner": True}
