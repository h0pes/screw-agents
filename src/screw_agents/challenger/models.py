"""Provider-neutral Phase 5 challenger contracts.

These models intentionally describe providers, assistants, transports, roles,
consent, and structured outputs without binding the scan engine to Claude,
Codex, Anthropic, OpenAI, or API billing. Runtime adapters will consume these
contracts in later Phase 5 slices.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Identifier = str
TransportKind = Literal["cli", "api", "local", "fixture"]
ParticipantRole = Literal["primary", "challenger", "parallel"]
Verdict = Literal["agree", "disagree", "uncertain", "unsupported"]
ReconciliationStatus = Literal[
    "agreed",
    "disputed",
    "unique",
    "uncertain",
    "unsupported",
]

_IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9_-]*$")


def _validate_identifier(value: str, field_name: str) -> str:
    if not _IDENTIFIER_RE.fullmatch(value):
        raise ValueError(
            f"{field_name} must match '^[a-z][a-z0-9_-]*$'; got {value!r}"
        )
    return value


class ChallengerConsent(BaseModel):
    """Cost, billing, and privacy acknowledgement for challenger execution."""

    model_config = ConfigDict(extra="forbid")

    cost_acknowledged: bool = False
    privacy_acknowledged: bool = False
    api_billing_allowed: bool = False
    source_sharing_allowed: bool = False

    def allows_external_execution(self) -> bool:
        """Return whether code can be sent to an external provider."""
        return self.privacy_acknowledged and self.source_sharing_allowed


class ChallengerTransportConfig(BaseModel):
    """One provider invocation mechanism.

    API billing is explicit and opt-in. CLI/local transports may use external
    services, but they do not imply API-key billing and they do not require an
    API key by default. This supports Pro/subscription-backed local assistants
    as first-class Phase 5 transports.
    """

    model_config = ConfigDict(extra="forbid")

    kind: TransportKind
    enabled: bool = False
    command: str | None = None
    primary_command: str | None = None
    challenger_command: str | None = None
    endpoint: str | None = None
    api_key_env: str | None = None
    use_api_key: bool = False
    allow_api_billing: bool = False
    sends_source_externally: bool = True
    max_prompt_chars: int | None = Field(default=None, ge=1)

    @field_validator("api_key_env")
    @classmethod
    def _validate_api_key_env(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", value):
            raise ValueError(
                "api_key_env must be an uppercase environment variable name"
            )
        return value

    @model_validator(mode="after")
    def _validate_transport_requirements(self) -> ChallengerTransportConfig:
        if self.kind == "api":
            if self.enabled and not self.allow_api_billing:
                raise ValueError(
                    "enabled API transports require allow_api_billing=true"
                )
            if self.enabled and not self.api_key_env:
                raise ValueError(
                    "enabled API transports require api_key_env"
                )
            if self.use_api_key and not self.api_key_env:
                raise ValueError("use_api_key=true requires api_key_env")
            return self

        if self.allow_api_billing:
            raise ValueError(
                f"{self.kind} transports cannot set allow_api_billing=true"
            )

        if self.kind != "cli" and (self.primary_command or self.challenger_command):
            raise ValueError(f"{self.kind} transports cannot set CLI command overrides")

        if (
            self.kind == "cli"
            and self.enabled
            and not self.command
            and not self.primary_command
            and not self.challenger_command
        ):
            raise ValueError(
                "enabled CLI transports require command or command overrides"
            )

        if self.kind == "local" and self.enabled and not self.endpoint:
            raise ValueError("enabled local transports require endpoint")

        if self.use_api_key and not self.api_key_env:
            raise ValueError("use_api_key=true requires api_key_env")

        return self

    def requires_api_key(self) -> bool:
        """Return whether this transport expects an API key env var."""
        return self.kind == "api" or self.use_api_key

    def may_bill_api_credits(self) -> bool:
        """Return whether this transport may consume provider API credits."""
        return self.kind == "api" and self.enabled and self.allow_api_billing

    def command_for_primary_scan(self) -> str | None:
        """Return the configured CLI command for first-pass scanning."""
        return self.primary_command or self.command

    def command_for_challenger_review(self) -> str | None:
        """Return the configured CLI command for challenger review."""
        return self.challenger_command or self.command


class ChallengerProviderConfig(BaseModel):
    """A provider/assistant and its supported transports."""

    model_config = ConfigDict(extra="forbid")

    assistant: Identifier
    display_name: str | None = None
    transports: dict[Identifier, ChallengerTransportConfig] = Field(
        default_factory=dict
    )
    default_transport: Identifier | None = None

    @field_validator("assistant")
    @classmethod
    def _validate_assistant(cls, value: str) -> str:
        return _validate_identifier(value, "assistant")

    @model_validator(mode="after")
    def _validate_transports(self) -> ChallengerProviderConfig:
        for name, transport in self.transports.items():
            _validate_identifier(name, "transport name")
            if name != transport.kind:
                raise ValueError(
                    f"transport key {name!r} must match kind {transport.kind!r}"
                )

        if self.default_transport is not None:
            _validate_identifier(self.default_transport, "default_transport")
            if self.default_transport not in self.transports:
                raise ValueError(
                    "default_transport must reference a configured transport"
                )

        return self

    def enabled_transport(self, name: str) -> ChallengerTransportConfig:
        """Return one enabled transport by name, or raise ValueError."""
        if name not in self.transports:
            raise ValueError(f"unknown transport {name!r}")
        transport = self.transports[name]
        if not transport.enabled:
            raise ValueError(f"transport {name!r} is not enabled")
        return transport


class ChallengerParticipant(BaseModel):
    """A provider/transport pair acting in one Phase 5 role."""

    model_config = ConfigDict(extra="forbid")

    provider: Identifier
    transport: Identifier
    role: ParticipantRole

    @field_validator("provider", "transport")
    @classmethod
    def _validate_identifier_fields(cls, value: str) -> str:
        return _validate_identifier(value, "provider/transport")


class ChallengerModeConfig(BaseModel):
    """One configured execution mode."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    participants: list[ChallengerParticipant]

    @model_validator(mode="after")
    def _validate_mode(self) -> ChallengerModeConfig:
        if len(self.participants) < 2:
            raise ValueError("challenger modes require at least two participants")

        roles = [participant.role for participant in self.participants]
        if "parallel" in roles:
            if any(role != "parallel" for role in roles):
                raise ValueError(
                    "parallel modes cannot mix parallel with primary/challenger roles"
                )
            return self

        if roles.count("primary") != 1 or roles.count("challenger") < 1:
            raise ValueError(
                "primary/challenger modes require one primary and at least one challenger"
            )
        return self


class ChallengerConfig(BaseModel):
    """Top-level Phase 5 challenger configuration."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    consent: ChallengerConsent = Field(default_factory=ChallengerConsent)
    providers: dict[Identifier, ChallengerProviderConfig] = Field(default_factory=dict)
    modes: dict[Identifier, ChallengerModeConfig] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_config(self) -> ChallengerConfig:
        for provider_name in self.providers:
            _validate_identifier(provider_name, "provider name")
        for mode_name, mode in self.modes.items():
            _validate_identifier(mode_name, "mode name")
            for participant in mode.participants:
                if participant.provider not in self.providers:
                    raise ValueError(
                        f"mode {mode_name!r} references unknown provider "
                        f"{participant.provider!r}"
                    )
                provider = self.providers[participant.provider]
                provider.enabled_transport(participant.transport)

        if self.enabled:
            if not self.consent.cost_acknowledged:
                raise ValueError("enabled challenger config requires cost acknowledgement")
            if not self.consent.privacy_acknowledged:
                raise ValueError(
                    "enabled challenger config requires privacy acknowledgement"
                )
            if self.api_billing_transports() and not self.consent.api_billing_allowed:
                raise ValueError(
                    "enabled API billing transports require api_billing_allowed=true"
                )
            if self.external_source_transports() and not self.consent.source_sharing_allowed:
                raise ValueError(
                    "enabled external-source transports require "
                    "source_sharing_allowed=true"
                )
            if not any(mode.enabled for mode in self.modes.values()):
                raise ValueError("enabled challenger config requires an enabled mode")

        return self

    def api_billing_transports(self) -> list[tuple[str, str]]:
        """Return enabled transports that may bill provider API credits."""
        billing: list[tuple[str, str]] = []
        for provider_name, provider in self.providers.items():
            for transport_name, transport in provider.transports.items():
                if transport.may_bill_api_credits():
                    billing.append((provider_name, transport_name))
        return billing

    def external_source_transports(self) -> list[tuple[str, str]]:
        """Return enabled transports that may send source outside the process."""
        external: list[tuple[str, str]] = []
        for provider_name, provider in self.providers.items():
            for transport_name, transport in provider.transports.items():
                if transport.enabled and transport.sends_source_externally:
                    external.append((provider_name, transport_name))
        return external


class ChallengerRunInput(BaseModel):
    """Structured input for a primary or challenger run."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    session_id: str
    participant: ChallengerParticipant
    agents: list[str]
    target: dict[str, Any]
    prompt: str
    findings: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ChallengerAssessment(BaseModel):
    """One provider's review of a finding or scan result."""

    model_config = ConfigDict(extra="forbid")

    provider: Identifier
    transport: Identifier
    role: ParticipantRole
    finding_id: str | None = None
    exploitability: Verdict
    severity: Verdict
    remediation: Verdict
    confidence: Literal["low", "medium", "high"]
    reasoning: str
    additional_findings: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("provider", "transport")
    @classmethod
    def _validate_provider_transport(cls, value: str) -> str:
        return _validate_identifier(value, "provider/transport")


class ChallengerReconciliation(BaseModel):
    """Provider-neutral reconciliation summary for one finding cluster."""

    model_config = ConfigDict(extra="forbid")

    finding_ids: list[str]
    status: ReconciliationStatus
    primary_provider: Identifier | None = None
    participant_providers: list[Identifier] = Field(default_factory=list)
    agreed_severity: str | None = None
    confidence: Literal["low", "medium", "high"] | None = None
    rationale: str = ""


class ChallengerRunResult(BaseModel):
    """Serializable result envelope for Phase 5 orchestration."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    mode: Identifier
    assessments: list[ChallengerAssessment] = Field(default_factory=list)
    reconciliations: list[ChallengerReconciliation] = Field(default_factory=list)
    provider_metadata: dict[str, Any] = Field(default_factory=dict)
    guardrails: dict[str, Any] = Field(default_factory=dict)
