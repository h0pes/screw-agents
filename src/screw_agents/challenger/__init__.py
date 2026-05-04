"""Provider-neutral contracts for Phase 5 challenger execution."""

from screw_agents.challenger.models import (
    ChallengerAssessment,
    ChallengerConfig,
    ChallengerConsent,
    ChallengerModeConfig,
    ChallengerParticipant,
    ChallengerProviderConfig,
    ChallengerReconciliation,
    ChallengerRunInput,
    ChallengerRunResult,
    ChallengerTransportConfig,
)
from screw_agents.challenger.providers import (
    FixtureProviderRunner,
    ProviderGuardrailReport,
    ProviderRunnerCapabilities,
    capabilities_from_transport,
    preflight_capabilities,
)
from screw_agents.challenger.reconciliation import (
    finding_key,
    reconcile_findings,
)

__all__ = [
    "ChallengerAssessment",
    "ChallengerConfig",
    "ChallengerConsent",
    "ChallengerModeConfig",
    "ChallengerParticipant",
    "ChallengerProviderConfig",
    "ChallengerReconciliation",
    "ChallengerRunInput",
    "ChallengerRunResult",
    "ChallengerTransportConfig",
    "FixtureProviderRunner",
    "ProviderGuardrailReport",
    "ProviderRunnerCapabilities",
    "capabilities_from_transport",
    "finding_key",
    "preflight_capabilities",
    "reconcile_findings",
]
