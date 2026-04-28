"""Phase 4 autoresearch scaffolding.

The initial public surface is deliberately planning-only: it inventories
benchmark inputs and gate definitions without invoking LLMs or mutating agent
YAML.
"""

from screw_agents.autoresearch.controlled_executor import (
    SCHEMA_VERSION as CONTROLLED_EXECUTOR_SCHEMA_VERSION,
)
from screw_agents.autoresearch.controlled_executor import (
    ControlledExecutorCase,
    ControlledExecutorConfig,
    ControlledExecutorIssue,
    ControlledExecutorReport,
    build_controlled_executor_report,
    render_controlled_executor_report_markdown,
)
from screw_agents.autoresearch.controlled_run import (
    SCHEMA_VERSION as CONTROLLED_RUN_SCHEMA_VERSION,
)
from screw_agents.autoresearch.controlled_run import (
    ControlledExecutionPlan,
    ControlledRunConfig,
    ControlledRunSelection,
    ReadinessIssue,
    build_controlled_execution_plan,
    render_controlled_execution_plan_markdown,
)
from screw_agents.autoresearch.failure_input import (
    SCHEMA_VERSION as FAILURE_INPUT_SCHEMA_VERSION,
)
from screw_agents.autoresearch.failure_input import (
    AgentSourceVersion,
    BenchmarkRunMetadata,
    CaseProvenance,
    FailureAnalysisInput,
    FailureExample,
    GuardrailState,
)
from screw_agents.autoresearch.planner import (
    DatasetPlan,
    GateAudit,
    RetiredGate,
    RunPlan,
    build_run_plan,
    render_run_plan_markdown,
)

__all__ = [
    "CONTROLLED_RUN_SCHEMA_VERSION",
    "CONTROLLED_EXECUTOR_SCHEMA_VERSION",
    "FAILURE_INPUT_SCHEMA_VERSION",
    "AgentSourceVersion",
    "BenchmarkRunMetadata",
    "CaseProvenance",
    "ControlledExecutionPlan",
    "ControlledExecutorCase",
    "ControlledExecutorConfig",
    "ControlledExecutorIssue",
    "ControlledExecutorReport",
    "ControlledRunConfig",
    "ControlledRunSelection",
    "DatasetPlan",
    "FailureAnalysisInput",
    "FailureExample",
    "GateAudit",
    "GuardrailState",
    "ReadinessIssue",
    "RetiredGate",
    "RunPlan",
    "build_controlled_execution_plan",
    "build_controlled_executor_report",
    "build_run_plan",
    "render_controlled_execution_plan_markdown",
    "render_controlled_executor_report_markdown",
    "render_run_plan_markdown",
]
