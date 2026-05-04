from __future__ import annotations

from screw_agents.challenger import (
    ChallengerAssessment,
    ChallengerConsent,
    ChallengerParticipant,
    ChallengerRunInput,
    ChallengerTransportConfig,
    FixtureProviderRunner,
    capabilities_from_transport,
    preflight_capabilities,
)


def _participant(
    *,
    provider: str = "codex",
    transport: str = "fixture",
    role: str = "challenger",
) -> ChallengerParticipant:
    return ChallengerParticipant(
        provider=provider,
        transport=transport,
        role=role,  # type: ignore[arg-type]
    )


def _finding(finding_id: str = "sqli-001") -> dict:
    return {
        "id": finding_id,
        "agent": "sqli",
        "location": {"file": "src/app.py", "line_start": 42},
        "classification": {"cwe": "CWE-89", "severity": "high"},
    }


def _assessment(
    *,
    provider: str = "codex",
    transport: str = "fixture",
    role: str = "challenger",
    finding_id: str = "sqli-001",
) -> ChallengerAssessment:
    return ChallengerAssessment(
        provider=provider,
        transport=transport,
        role=role,  # type: ignore[arg-type]
        finding_id=finding_id,
        exploitability="agree",
        severity="agree",
        remediation="agree",
        confidence="high",
        reasoning="fixture agreement",
    )


def _run_input(
    *,
    participant: ChallengerParticipant | None = None,
    findings: list[dict] | None = None,
) -> ChallengerRunInput:
    return ChallengerRunInput(
        run_id="run-001",
        session_id="session-001",
        participant=participant or _participant(),
        agents=["sqli"],
        target={"type": "file", "path": "src/app.py"},
        prompt="fixture prompt",
        findings=findings or [_finding()],
        metadata={"mode": "fixture", "primary_provider": "claude"},
    )


def test_capabilities_from_cli_transport_do_not_require_api_billing() -> None:
    participant = _participant(provider="claude", transport="cli", role="primary")
    transport = ChallengerTransportConfig(
        kind="cli",
        enabled=True,
        command="claude",
        use_api_key=False,
    )

    capabilities = capabilities_from_transport(participant, transport)

    assert capabilities.provider == "claude"
    assert capabilities.transport == "cli"
    assert capabilities.command == "claude"
    assert capabilities.required_env_vars == []
    assert not capabilities.may_bill_api_credits


def test_capabilities_from_api_transport_surface_env_and_billing() -> None:
    participant = _participant(provider="codex", transport="api")
    transport = ChallengerTransportConfig(
        kind="api",
        enabled=True,
        api_key_env="OPENAI_API_KEY",
        allow_api_billing=True,
    )

    capabilities = capabilities_from_transport(participant, transport)

    assert capabilities.required_env_vars == ["OPENAI_API_KEY"]
    assert capabilities.may_bill_api_credits


def test_preflight_blocks_api_billing_without_consent() -> None:
    report = preflight_capabilities(
        capabilities_from_transport(
            _participant(provider="codex", transport="api"),
            ChallengerTransportConfig(
                kind="api",
                enabled=True,
                api_key_env="OPENAI_API_KEY",
                allow_api_billing=True,
            ),
        ),
        ChallengerConsent(
            cost_acknowledged=True,
            privacy_acknowledged=True,
            api_billing_allowed=False,
            source_sharing_allowed=True,
        ),
    )

    assert not report.allowed
    assert "api_billing_not_allowed" in report.blockers


def test_preflight_blocks_external_source_without_consent() -> None:
    report = preflight_capabilities(
        capabilities_from_transport(
            _participant(provider="claude", transport="cli"),
            ChallengerTransportConfig(kind="cli", enabled=True, command="claude"),
        ),
        ChallengerConsent(
            cost_acknowledged=True,
            privacy_acknowledged=True,
            api_billing_allowed=False,
            source_sharing_allowed=False,
        ),
    )

    assert not report.allowed
    assert "source_sharing_not_allowed" in report.blockers


def test_fixture_runner_does_not_invoke_external_transport() -> None:
    participant = _participant()
    runner = FixtureProviderRunner(
        participant=participant,
        transport=ChallengerTransportConfig(
            kind="fixture",
            enabled=True,
            sends_source_externally=False,
        ),
        assessments=[_assessment()],
    )

    report = runner.preflight(ChallengerConsent())
    result = runner.run(_run_input(participant=participant))

    assert report.allowed
    assert report.capabilities.is_fixture
    assert report.capabilities.command is None
    assert runner.run_count == 1
    assert result.assessments[0].provider == "codex"
    assert result.guardrails == {"fixture_runner": True}


def test_fixture_runner_outputs_feed_reconciliation() -> None:
    participant = _participant()
    runner = FixtureProviderRunner(
        participant=participant,
        transport=ChallengerTransportConfig(
            kind="fixture",
            enabled=True,
            sends_source_externally=False,
        ),
        assessments=[_assessment()],
    )

    result = runner.run(_run_input(participant=participant))

    assert len(result.reconciliations) == 1
    assert result.reconciliations[0].status == "agreed"
    assert result.reconciliations[0].participant_providers == ["claude", "codex"]


def test_fixture_runner_filters_assessments_to_its_participant() -> None:
    participant = _participant(provider="codex")
    runner = FixtureProviderRunner(
        participant=participant,
        transport=ChallengerTransportConfig(
            kind="fixture",
            enabled=True,
            sends_source_externally=False,
        ),
        assessments=[
            _assessment(provider="codex"),
            _assessment(provider="gemini"),
        ],
    )

    result = runner.run(_run_input(participant=participant))

    assert [assessment.provider for assessment in result.assessments] == ["codex"]
