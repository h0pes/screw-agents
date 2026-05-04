"""Provider runner contracts and fixture runner for Phase 5.

This module defines the non-live provider boundary. Real CLI/API adapters will
arrive in later Phase 5 slices; the fixture runner here proves the contract and
guardrail plumbing without invoking external commands or providers.
"""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from screw_agents.challenger.models import (
    ChallengerAssessment,
    ChallengerConsent,
    ChallengerParticipant,
    ChallengerRunInput,
    ChallengerRunResult,
    ChallengerTransportConfig,
)
from screw_agents.challenger.reconciliation import reconcile_findings


class ProviderRunnerCapabilities(BaseModel):
    """Static capability and risk metadata declared by a provider runner."""

    model_config = ConfigDict(extra="forbid")

    provider: str
    transport: str
    sends_source_externally: bool
    may_bill_api_credits: bool
    required_env_vars: list[str] = Field(default_factory=list)
    command: str | None = None
    endpoint: str | None = None
    supports_prompt_budget: bool = False
    is_fixture: bool = False


class ProviderGuardrailReport(BaseModel):
    """Pre-execution guardrail assessment for one provider run."""

    model_config = ConfigDict(extra="forbid")

    provider: str
    transport: str
    allowed: bool
    blockers: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    capabilities: ProviderRunnerCapabilities


class ProviderRunner(Protocol):
    """Protocol implemented by Phase 5 provider runners."""

    @property
    def capabilities(self) -> ProviderRunnerCapabilities:
        """Return static provider/transport metadata."""

    def preflight(self, consent: ChallengerConsent) -> ProviderGuardrailReport:
        """Return guardrail status without invoking the provider."""

    def run(self, run_input: ChallengerRunInput) -> ChallengerRunResult:
        """Run provider analysis and return structured result data."""


def capabilities_from_transport(
    participant: ChallengerParticipant,
    transport: ChallengerTransportConfig,
    *,
    is_fixture: bool = False,
) -> ProviderRunnerCapabilities:
    """Build runner capability metadata from provider config."""
    required_env_vars: list[str] = []
    if transport.requires_api_key() and transport.api_key_env:
        required_env_vars.append(transport.api_key_env)

    return ProviderRunnerCapabilities(
        provider=participant.provider,
        transport=participant.transport,
        sends_source_externally=transport.sends_source_externally,
        may_bill_api_credits=transport.may_bill_api_credits(),
        required_env_vars=required_env_vars,
        command=transport.command,
        endpoint=transport.endpoint,
        supports_prompt_budget=transport.max_prompt_chars is not None,
        is_fixture=is_fixture,
    )


def preflight_capabilities(
    capabilities: ProviderRunnerCapabilities,
    consent: ChallengerConsent,
) -> ProviderGuardrailReport:
    """Evaluate cost/privacy guardrails before provider execution."""
    blockers: list[str] = []
    warnings: list[str] = []

    if capabilities.may_bill_api_credits and not consent.api_billing_allowed:
        blockers.append("api_billing_not_allowed")
    if capabilities.sends_source_externally and not consent.source_sharing_allowed:
        blockers.append("source_sharing_not_allowed")
    if capabilities.may_bill_api_credits and not consent.cost_acknowledged:
        blockers.append("cost_not_acknowledged")
    if capabilities.sends_source_externally and not consent.privacy_acknowledged:
        blockers.append("privacy_not_acknowledged")
    if capabilities.required_env_vars:
        warnings.append("requires_env_vars")
    if capabilities.command:
        warnings.append("would_invoke_command")

    return ProviderGuardrailReport(
        provider=capabilities.provider,
        transport=capabilities.transport,
        allowed=not blockers,
        blockers=blockers,
        warnings=warnings,
        capabilities=capabilities,
    )


class FixtureProviderRunner:
    """Deterministic in-memory provider runner for tests and orchestration dry-runs."""

    def __init__(
        self,
        *,
        participant: ChallengerParticipant,
        transport: ChallengerTransportConfig,
        assessments: list[ChallengerAssessment] | None = None,
        findings: list[dict] | None = None,
    ) -> None:
        self._participant = participant
        self._capabilities = capabilities_from_transport(
            participant,
            transport,
            is_fixture=True,
        )
        self._assessments = assessments or []
        self._findings = findings or []
        self.run_count = 0

    @property
    def capabilities(self) -> ProviderRunnerCapabilities:
        return self._capabilities

    def preflight(self, consent: ChallengerConsent) -> ProviderGuardrailReport:
        return preflight_capabilities(self.capabilities, consent)

    def run(self, run_input: ChallengerRunInput) -> ChallengerRunResult:
        self.run_count += 1

        findings = self._findings or run_input.findings
        assessments = [
            assessment
            for assessment in self._assessments
            if assessment.provider == self._participant.provider
            and assessment.transport == self._participant.transport
            and assessment.role == self._participant.role
        ]

        return ChallengerRunResult(
            run_id=run_input.run_id,
            mode=run_input.metadata.get("mode", "fixture"),
            assessments=assessments,
            reconciliations=reconcile_findings(
                findings,
                assessments,
                primary_provider=run_input.metadata.get("primary_provider"),
            ),
            provider_metadata={
                self._participant.provider: self.capabilities.model_dump(mode="json")
            },
            guardrails={"fixture_runner": True},
        )
