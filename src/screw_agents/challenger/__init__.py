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
from screw_agents.challenger.orchestrator import (
    participant_label,
    participant_runner_key,
    run_challenger_mode,
)
from screw_agents.challenger.providers import (
    ClaudeCliProviderRunner,
    CliCommandResult,
    CliInvocation,
    CliProviderRunner,
    CodexCliProviderRunner,
    FixtureProviderRunner,
    ProviderGuardrailReport,
    ProviderRunner,
    ProviderRunnerCapabilities,
    capabilities_from_transport,
    preflight_capabilities,
)
from screw_agents.challenger.reconciliation import (
    finding_key,
    reconcile_findings,
)
from screw_agents.challenger.runner_factory import build_runners_for_mode

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
    "ClaudeCliProviderRunner",
    "CliCommandResult",
    "CliInvocation",
    "CliProviderRunner",
    "CodexCliProviderRunner",
    "FixtureProviderRunner",
    "ProviderGuardrailReport",
    "ProviderRunner",
    "ProviderRunnerCapabilities",
    "build_runners_for_mode",
    "capabilities_from_transport",
    "finding_key",
    "participant_label",
    "participant_runner_key",
    "preflight_capabilities",
    "reconcile_findings",
    "run_challenger_mode",
]
