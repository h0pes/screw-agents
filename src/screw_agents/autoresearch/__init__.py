"""Phase 4 autoresearch scaffolding.

The initial public surface is deliberately planning-only: it inventories
benchmark inputs and gate definitions without invoking LLMs or mutating agent
YAML.
"""

from screw_agents.autoresearch.planner import DatasetPlan
from screw_agents.autoresearch.planner import GateAudit
from screw_agents.autoresearch.planner import RunPlan
from screw_agents.autoresearch.planner import build_run_plan
from screw_agents.autoresearch.planner import render_run_plan_markdown

__all__ = [
    "DatasetPlan",
    "GateAudit",
    "RunPlan",
    "build_run_plan",
    "render_run_plan_markdown",
]
