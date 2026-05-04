import json

import pytest

from screw_agents.models import (
    Finding,
    FindingAnalysis,
    FindingClassification,
    FindingLocation,
    FindingRemediation,
)
from screw_agents.primary_scan import (
    PrimaryScanInput,
    PrimaryScanParticipant,
    SourceChunk,
    parse_primary_scan_output,
)


def _finding_dict(**overrides):
    data = {
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
    data.update(overrides)
    return data


def test_primary_scan_input_accepts_provider_neutral_payload():
    scan_input = PrimaryScanInput(
        run_id="run-1",
        session_id="session-1",
        participant=PrimaryScanParticipant(provider="codex", transport="cli"),
        agents=["sqli"],
        target={"path": "src/app.py"},
        prompt="Use the YAML knowledge to scan the target.",
        source_chunks=[
            SourceChunk(
                path="src/app.py",
                language="python",
                line_start=1,
                line_end=20,
                content="query = f\"select * from users where id = {user_id}\"",
            )
        ],
    )

    assert scan_input.participant.provider == "codex"
    assert scan_input.source_chunks[0].path == "src/app.py"


def test_primary_scan_input_requires_agents_and_prompt():
    participant = PrimaryScanParticipant(provider="fixture", transport="fixture")
    with pytest.raises(ValueError, match="at least one agent"):
        PrimaryScanInput(
            run_id="run-1",
            session_id="session-1",
            participant=participant,
            agents=[],
            target={},
            prompt="scan",
        )
    with pytest.raises(ValueError, match="prompt must not be empty"):
        PrimaryScanInput(
            run_id="run-1",
            session_id="session-1",
            participant=participant,
            agents=["sqli"],
            target={},
            prompt=" ",
        )


def test_parse_primary_scan_output_accepts_object_payload():
    participant = PrimaryScanParticipant(provider="codex", transport="cli")
    result = parse_primary_scan_output(
        json.dumps(
            {
                "findings": [_finding_dict()],
                "provider_metadata": {"model": "test-model"},
                "guardrails": {"source_sharing_allowed": True},
            }
        ),
        run_id="run-1",
        participant=participant,
        transport_kind="cli",
    )

    assert result.provider == "codex"
    assert result.transport_kind == "cli"
    assert result.findings == [Finding.model_validate(_finding_dict())]
    assert result.provider_metadata == {"model": "test-model"}
    assert result.guardrails == {"source_sharing_allowed": True}


def test_parse_primary_scan_output_accepts_bare_finding_list():
    participant = PrimaryScanParticipant(provider="fixture", transport="fixture")
    result = parse_primary_scan_output(
        [_finding_dict(id="xss-001", agent="xss", classification={
            "cwe": "CWE-79",
            "cwe_name": "Cross-Site Scripting",
            "severity": "medium",
            "confidence": "medium",
        })],
        run_id="run-2",
        participant=participant,
        transport_kind="fixture",
    )

    assert result.findings[0].id == "xss-001"
    assert result.raw_output["findings"][0]["agent"] == "xss"


def test_parse_primary_scan_output_rejects_invalid_json():
    participant = PrimaryScanParticipant(provider="fixture", transport="fixture")
    with pytest.raises(ValueError, match="must be JSON"):
        parse_primary_scan_output(
            "{not json",
            run_id="run-1",
            participant=participant,
        )


def test_parse_primary_scan_output_rejects_invalid_findings():
    participant = PrimaryScanParticipant(provider="fixture", transport="fixture")
    with pytest.raises(ValueError):
        parse_primary_scan_output(
            {"findings": [{"id": "missing-required-fields"}]},
            run_id="run-1",
            participant=participant,
        )


def test_primary_scan_participant_validates_identifiers():
    with pytest.raises(ValueError, match="provider/transport"):
        PrimaryScanParticipant(provider="OpenAI", transport="cli")


def test_fixture_finding_builder_uses_core_model_shape():
    finding = Finding(
        id="sqli-001",
        agent="sqli",
        domain="injection-input-handling",
        timestamp="2026-05-04T10:00:00Z",
        location=FindingLocation(file="src/app.py", line_start=12),
        classification=FindingClassification(
            cwe="CWE-89",
            cwe_name="SQL Injection",
            severity="high",
            confidence="high",
        ),
        analysis=FindingAnalysis(description="Unsafely concatenated SQL query."),
        remediation=FindingRemediation(recommendation="Use parameterized queries."),
    )

    assert finding.id == "sqli-001"
