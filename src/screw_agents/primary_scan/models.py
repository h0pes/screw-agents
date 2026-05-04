"""Provider-neutral primary scan contracts.

These contracts describe the backend boundary for first-pass scanning from the
shared YAML agent knowledge. They intentionally avoid provider-specific names
so Codex, Claude, Gemini, local models, or fixture runners can all occupy the
same scanner role through different transports.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from screw_agents.challenger.models import TransportKind
from screw_agents.models import Finding

Identifier = str

_IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9_-]*$")


def _validate_identifier(value: str, field_name: str) -> str:
    if not _IDENTIFIER_RE.fullmatch(value):
        raise ValueError(
            f"{field_name} must match '^[a-z][a-z0-9_-]*$'; got {value!r}"
        )
    return value


class PrimaryScanParticipant(BaseModel):
    """A provider/transport pair acting as a first-pass scanner."""

    model_config = ConfigDict(extra="forbid")

    provider: Identifier
    transport: Identifier

    @field_validator("provider", "transport")
    @classmethod
    def _validate_identifier_fields(cls, value: str) -> str:
        return _validate_identifier(value, "provider/transport")


class SourceChunk(BaseModel):
    """A source excerpt packaged for provider-neutral scanner execution."""

    model_config = ConfigDict(extra="forbid")

    path: str
    content: str
    language: str | None = None
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("path")
    @classmethod
    def _validate_path(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("path must not be empty")
        return value


class PrimaryScanInput(BaseModel):
    """Structured input for a provider-neutral first-pass scan."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    session_id: str
    participant: PrimaryScanParticipant
    agents: list[Identifier]
    target: dict[str, Any]
    prompt: str
    source_chunks: list[SourceChunk] = Field(default_factory=list)
    output_schema: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("agents")
    @classmethod
    def _validate_agents(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("primary scan input requires at least one agent")
        return [_validate_identifier(agent, "agent") for agent in value]

    @field_validator("prompt")
    @classmethod
    def _validate_prompt(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("prompt must not be empty")
        return value


class PrimaryScanResult(BaseModel):
    """Validated provider-neutral result envelope for first-pass scanning."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    provider: Identifier
    transport: Identifier
    transport_kind: TransportKind | None = None
    findings: list[Finding] = Field(default_factory=list)
    raw_output: dict[str, Any] = Field(default_factory=dict)
    provider_metadata: dict[str, Any] = Field(default_factory=dict)
    guardrails: dict[str, Any] = Field(default_factory=dict)

    @field_validator("provider", "transport")
    @classmethod
    def _validate_provider_transport(cls, value: str) -> str:
        return _validate_identifier(value, "provider/transport")


def parse_primary_scan_output(
    raw_output: str | bytes | dict[str, Any] | list[Any],
    *,
    run_id: str,
    participant: PrimaryScanParticipant,
    transport_kind: TransportKind | None = None,
) -> PrimaryScanResult:
    """Parse provider output into validated first-pass scan findings.

    Providers may return either a JSON object with a ``findings`` list or a bare
    JSON/list of finding objects. Finding entries are validated through the same
    core ``Finding`` model used by existing reports and MCP tools.
    """

    payload = _coerce_payload(raw_output)
    findings_payload, payload_object = _extract_findings(payload)
    findings = [_finding_from_payload(item) for item in findings_payload]

    return PrimaryScanResult(
        run_id=run_id,
        provider=participant.provider,
        transport=participant.transport,
        transport_kind=transport_kind,
        findings=findings,
        raw_output=payload_object,
        provider_metadata=payload_object.get("provider_metadata", {}),
        guardrails=payload_object.get("guardrails", {}),
    )


def _coerce_payload(raw_output: str | bytes | dict[str, Any] | list[Any]) -> Any:
    if isinstance(raw_output, bytes):
        raw_output = raw_output.decode("utf-8")
    if isinstance(raw_output, str):
        if not raw_output.strip():
            return {}
        try:
            return json.loads(raw_output)
        except json.JSONDecodeError as exc:
            raise ValueError("primary scan provider output must be JSON") from exc
    return raw_output


def _extract_findings(payload: Any) -> tuple[list[Any], dict[str, Any]]:
    if isinstance(payload, list):
        return payload, {"findings": payload}
    if not isinstance(payload, dict):
        raise ValueError("primary scan provider output must be a JSON object or list")

    raw_findings = payload.get("findings", [])
    if raw_findings is None:
        raw_findings = []
    if not isinstance(raw_findings, list):
        raise ValueError("primary scan findings payload must be a list")
    return raw_findings, payload


def _finding_from_payload(item: Any) -> Finding:
    if not isinstance(item, dict):
        raise ValueError("primary scan finding entries must be JSON objects")
    return Finding.model_validate(item)
