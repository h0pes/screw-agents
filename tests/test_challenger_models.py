from __future__ import annotations

import pytest
from pydantic import ValidationError

from screw_agents.challenger import (
    ChallengerAssessment,
    ChallengerConfig,
    ChallengerConsent,
    ChallengerModeConfig,
    ChallengerParticipant,
    ChallengerProviderConfig,
    ChallengerReconciliation,
    ChallengerRunResult,
    ChallengerTransportConfig,
)
from screw_agents.models import ScrewConfig


def test_cli_transport_is_subscription_backed_without_api_key() -> None:
    transport = ChallengerTransportConfig(
        kind="cli",
        enabled=True,
        command="claude",
        use_api_key=False,
    )

    assert not transport.requires_api_key()
    assert not transport.may_bill_api_credits()


def test_enabled_api_transport_requires_billing_permission() -> None:
    with pytest.raises(ValidationError, match="allow_api_billing=true"):
        ChallengerTransportConfig(
            kind="api",
            enabled=True,
            api_key_env="OPENAI_API_KEY",
        )


def test_enabled_api_transport_requires_api_key_env() -> None:
    with pytest.raises(ValidationError, match="api_key_env"):
        ChallengerTransportConfig(
            kind="api",
            enabled=True,
            allow_api_billing=True,
        )


def test_enabled_api_transport_records_api_billing_risk() -> None:
    transport = ChallengerTransportConfig(
        kind="api",
        enabled=True,
        api_key_env="OPENAI_API_KEY",
        allow_api_billing=True,
    )

    assert transport.requires_api_key()
    assert transport.may_bill_api_credits()


def test_non_api_transport_cannot_allow_api_billing() -> None:
    with pytest.raises(ValidationError, match="cannot set allow_api_billing"):
        ChallengerTransportConfig(
            kind="cli",
            enabled=True,
            command="codex",
            allow_api_billing=True,
        )


def test_provider_transport_key_must_match_transport_kind() -> None:
    with pytest.raises(ValidationError, match="must match kind"):
        ChallengerProviderConfig(
            assistant="claude",
            transports={
                "subscription": ChallengerTransportConfig(
                    kind="cli",
                    enabled=True,
                    command="claude",
                )
            },
        )


def test_enabled_config_requires_consent_and_enabled_mode() -> None:
    with pytest.raises(ValidationError, match="cost acknowledgement"):
        ChallengerConfig(enabled=True)


def test_enabled_config_requires_source_sharing_for_external_transports() -> None:
    with pytest.raises(ValidationError, match="source_sharing_allowed=true"):
        _valid_cli_only_config(source_sharing_allowed=False)


def test_enabled_config_requires_api_billing_consent_for_api_transport() -> None:
    with pytest.raises(ValidationError, match="api_billing_allowed=true"):
        _valid_api_config(api_billing_allowed=False)


def test_config_rejects_modes_referencing_disabled_transport() -> None:
    with pytest.raises(ValidationError, match="is not enabled"):
        ChallengerConfig(
            providers={
                "claude": ChallengerProviderConfig(
                    assistant="claude",
                    transports={
                        "cli": ChallengerTransportConfig(
                            kind="cli",
                            enabled=False,
                            command="claude",
                        )
                    },
                ),
                "codex": ChallengerProviderConfig(
                    assistant="codex",
                    transports={
                        "cli": ChallengerTransportConfig(
                            kind="cli",
                            enabled=True,
                            command="codex",
                        )
                    },
                ),
            },
            modes={
                "claude_primary_codex_challenger": ChallengerModeConfig(
                    enabled=True,
                    participants=[
                        ChallengerParticipant(
                            provider="claude",
                            transport="cli",
                            role="primary",
                        ),
                        ChallengerParticipant(
                            provider="codex",
                            transport="cli",
                            role="challenger",
                        ),
                    ],
                )
            },
        )


def test_valid_cli_only_config_needs_no_api_billing() -> None:
    config = _valid_cli_only_config()

    assert config.api_billing_transports() == []
    assert config.external_source_transports() == [("claude", "cli"), ("codex", "cli")]
    assert not config.providers["claude"].transports["cli"].requires_api_key()
    assert config.consent.allows_external_execution()


def test_valid_api_config_records_api_billing_transports() -> None:
    config = _valid_api_config(api_billing_allowed=True)

    assert config.api_billing_transports() == [("codex", "api")]
    assert config.providers["codex"].transports["api"].requires_api_key()


def test_project_config_accepts_challenger_guardrails() -> None:
    config = ScrewConfig(
        challenger=_valid_cli_only_config().model_dump(mode="json")
    )

    assert config.challenger.enabled
    assert config.challenger.api_billing_transports() == []


def test_project_config_rejects_challenger_api_billing_without_consent() -> None:
    with pytest.raises(ValidationError, match="api_billing_allowed=true"):
        ScrewConfig(challenger=_valid_api_config(api_billing_allowed=False))


def _valid_cli_only_config(source_sharing_allowed: bool = True) -> ChallengerConfig:
    return ChallengerConfig(
        enabled=True,
        consent=ChallengerConsent(
            cost_acknowledged=True,
            privacy_acknowledged=True,
            api_billing_allowed=False,
            source_sharing_allowed=source_sharing_allowed,
        ),
        providers={
            "claude": ChallengerProviderConfig(
                assistant="claude",
                transports={
                    "cli": ChallengerTransportConfig(
                        kind="cli",
                        enabled=True,
                        command="claude",
                    )
                },
                default_transport="cli",
            ),
            "codex": ChallengerProviderConfig(
                assistant="codex",
                transports={
                    "cli": ChallengerTransportConfig(
                        kind="cli",
                        enabled=True,
                        command="codex",
                    )
                },
                default_transport="cli",
            ),
        },
        modes={
            "claude_primary_codex_challenger": ChallengerModeConfig(
                enabled=True,
                participants=[
                    ChallengerParticipant(
                        provider="claude",
                        transport="cli",
                        role="primary",
                    ),
                    ChallengerParticipant(
                        provider="codex",
                        transport="cli",
                        role="challenger",
                    ),
                ],
            ),
            "parallel": ChallengerModeConfig(
                enabled=False,
                participants=[
                    ChallengerParticipant(
                        provider="claude",
                        transport="cli",
                        role="parallel",
                    ),
                    ChallengerParticipant(
                        provider="codex",
                        transport="cli",
                        role="parallel",
                    ),
                ],
            ),
        },
    )


def _valid_api_config(api_billing_allowed: bool) -> ChallengerConfig:
    return ChallengerConfig(
        enabled=True,
        consent=ChallengerConsent(
            cost_acknowledged=True,
            privacy_acknowledged=True,
            api_billing_allowed=api_billing_allowed,
            source_sharing_allowed=True,
        ),
        providers={
            "claude": ChallengerProviderConfig(
                assistant="claude",
                transports={
                    "cli": ChallengerTransportConfig(
                        kind="cli",
                        enabled=True,
                        command="claude",
                    )
                },
            ),
            "codex": ChallengerProviderConfig(
                assistant="codex",
                transports={
                    "api": ChallengerTransportConfig(
                        kind="api",
                        enabled=True,
                        api_key_env="OPENAI_API_KEY",
                        allow_api_billing=True,
                    )
                },
            ),
        },
        modes={
            "claude_primary_codex_challenger": ChallengerModeConfig(
                enabled=True,
                participants=[
                    ChallengerParticipant(
                        provider="claude",
                        transport="cli",
                        role="primary",
                    ),
                    ChallengerParticipant(
                        provider="codex",
                        transport="api",
                        role="challenger",
                    ),
                ],
            )
        },
    )


def test_assessment_and_result_contracts_are_json_serializable() -> None:
    assessment = ChallengerAssessment(
        provider="codex",
        transport="cli",
        role="challenger",
        finding_id="sqli-001",
        exploitability="agree",
        severity="uncertain",
        remediation="agree",
        confidence="medium",
        reasoning="The sink is reachable, but authentication context is unclear.",
    )
    reconciliation = ChallengerReconciliation(
        finding_ids=["sqli-001"],
        status="uncertain",
        primary_provider="claude",
        participant_providers=["claude", "codex"],
        confidence="medium",
        rationale="Both providers agree on reachability but not final severity.",
    )
    result = ChallengerRunResult(
        run_id="run-001",
        mode="claude_primary_codex_challenger",
        assessments=[assessment],
        reconciliations=[reconciliation],
        provider_metadata={"codex": {"transport": "cli"}},
        guardrails={"api_billing_transports": []},
    )

    dumped = result.model_dump(mode="json")

    assert dumped["assessments"][0]["provider"] == "codex"
    assert dumped["reconciliations"][0]["status"] == "uncertain"
    assert dumped["guardrails"]["api_billing_transports"] == []
