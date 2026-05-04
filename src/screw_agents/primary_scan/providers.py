"""Provider runner contracts for provider-neutral primary scanning."""

from __future__ import annotations

from typing import Protocol

from screw_agents.models import Finding
from screw_agents.primary_scan.models import (
    PrimaryScanInput,
    PrimaryScanParticipant,
    PrimaryScanResult,
)


class PrimaryScanRunner(Protocol):
    """Protocol implemented by first-pass scanner provider runners."""

    def run(self, scan_input: PrimaryScanInput) -> PrimaryScanResult:
        """Run first-pass analysis and return validated findings."""


class FixturePrimaryScanRunner:
    """Deterministic in-memory primary scanner for tests and dry runs."""

    def __init__(
        self,
        *,
        participant: PrimaryScanParticipant,
        findings: list[Finding | dict] | None = None,
        provider_metadata: dict | None = None,
        guardrails: dict | None = None,
    ) -> None:
        self._participant = participant
        self._findings = [Finding.model_validate(finding) for finding in findings or []]
        self._provider_metadata = provider_metadata or {}
        self._guardrails = guardrails or {"fixture_runner": True}
        self.run_count = 0

    def run(self, scan_input: PrimaryScanInput) -> PrimaryScanResult:
        self.run_count += 1
        return PrimaryScanResult(
            run_id=scan_input.run_id,
            provider=self._participant.provider,
            transport=self._participant.transport,
            transport_kind="fixture",
            findings=list(self._findings),
            raw_output={
                "findings": [
                    finding.model_dump(mode="json") for finding in self._findings
                ]
            },
            provider_metadata=self._provider_metadata,
            guardrails=self._guardrails,
        )
