"""Scan engine — ties registry, resolver, and formatter together.

Assembles detection prompts from agent YAML + resolved code. Does NOT
call Claude — the MCP tool returns the assembled prompt for Claude to
process. Claude then returns structured findings which are passed to
format_findings() for output formatting.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from screw_agents.formatter import format_findings
from screw_agents.learning import load_exclusions
from screw_agents.models import AgentDefinition, Finding, HeuristicEntry
from screw_agents.registry import AgentRegistry
from screw_agents.resolver import ResolvedCode, filter_by_relevance, resolve_target


class ScanEngine:
    """Orchestrates scan assembly across registry, resolver, and formatter."""

    def __init__(self, registry: AgentRegistry) -> None:
        self._registry = registry

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_domains(self) -> dict[str, int]:
        """Return a mapping of domain names to agent counts."""
        return self._registry.list_domains()

    def list_agents(self, domain: str | None = None) -> list[dict]:
        """Return agent metadata dicts, optionally filtered by domain."""
        return self._registry.list_agents(domain=domain)

    def assemble_scan(
        self,
        agent_name: str,
        target: dict[str, Any],
        thoroughness: str = "standard",
        project_root: Path | None = None,
    ) -> dict[str, Any]:
        """Assemble a scan payload for a single agent.

        Args:
            agent_name: Registered agent identifier (e.g. "sqli").
            target: Target spec dict (PRD §5 format).
            thoroughness: One of "standard", "deep". Controls which
                heuristic tiers are included in the prompt.

        Returns:
            Dict with keys:
                - agent_name: str
                - core_prompt: str  (assembled prompt)
                - code: str         (formatted code context)
                - resolved_files: list[str]
                - meta: dict        (agent metadata summary)

        Raises:
            ValueError: If agent_name is not registered.
        """
        agent = self._registry.get_agent(agent_name)
        if agent is None:
            raise ValueError(f"Unknown agent: {agent_name!r}")

        # Resolve target to code chunks
        codes = resolve_target(target)

        # For broad targets, filter by agent relevance signals
        target_type = target.get("type", "")
        if target_type in ("codebase", "glob"):
            signals = agent.target_strategy.relevance_signals
            codes = filter_by_relevance(codes, signals)

        prompt = self._build_prompt(agent, thoroughness)
        code_context = self._format_code_context(codes)

        result: dict[str, Any] = {
            "agent_name": agent_name,
            "core_prompt": prompt,
            "code": code_context,
            "resolved_files": [c.file_path for c in codes],
            "meta": {
                "name": agent.meta.name,
                "display_name": agent.meta.display_name,
                "domain": agent.meta.domain,
                "cwe_primary": agent.meta.cwes.primary,
                "cwe_related": agent.meta.cwes.related,
            },
        }
        if project_root is not None:
            all_exclusions = load_exclusions(project_root)
            agent_exclusions = [e for e in all_exclusions if e.agent == agent_name]
            result["exclusions"] = [e.model_dump() for e in agent_exclusions]
        return result

    def assemble_domain_scan(
        self,
        domain: str,
        target: dict[str, Any],
        thoroughness: str = "standard",
        project_root: Path | None = None,
    ) -> list[dict[str, Any]]:
        """Assemble scan payloads for every agent in a domain.

        Args:
            domain: Domain name (e.g. "injection-input-handling").
            target: Target spec dict.
            thoroughness: Passed through to assemble_scan.
            project_root: Optional project root for exclusion loading.

        Returns:
            List of assemble_scan results, one per agent in the domain.
        """
        agents = self._registry.get_agents_by_domain(domain)
        return [
            self.assemble_scan(a.meta.name, target, thoroughness, project_root)
            for a in agents
        ]

    def assemble_full_scan(
        self,
        target: dict[str, Any],
        thoroughness: str = "standard",
        project_root: Path | None = None,
    ) -> list[dict[str, Any]]:
        """Assemble scan payloads for all registered agents.

        Args:
            target: Target spec dict.
            thoroughness: Passed through to assemble_scan.
            project_root: Optional project root for exclusion loading.

        Returns:
            List of assemble_scan results for every registered agent.
        """
        return [
            self.assemble_scan(name, target, thoroughness, project_root)
            for name in self._registry.agents
        ]

    def format_output(
        self,
        findings: list[Finding],
        output_format: str = "json",
        scan_metadata: dict[str, Any] | None = None,
    ) -> str:
        """Format scan findings via the formatter module.

        Args:
            findings: List of Finding objects.
            output_format: "json", "sarif", or "markdown".
            scan_metadata: Optional metadata dict for the report header.

        Returns:
            Formatted string output.
        """
        return format_findings(findings, format=output_format, scan_metadata=scan_metadata)

    def list_tool_definitions(self) -> list[dict[str, Any]]:
        """Return MCP tool definitions for all registered agents + static tools.

        Returns a list of tool definition dicts, each with:
            - name: str
            - description: str
            - input_schema: JSON Schema dict
        """
        tools: list[dict[str, Any]] = []

        # Static tools
        tools.append({
            "name": "list_domains",
            "description": "List all available vulnerability domain groups with agent counts.",
            "input_schema": self._scan_input_schema(extra_required=[], extra_props={}),
        })
        tools.append({
            "name": "list_agents",
            "description": "List all registered security agents, optionally filtered by domain.",
            "input_schema": self._scan_input_schema(
                extra_required=[],
                extra_props={
                    "domain": {
                        "type": "string",
                        "description": "Filter by domain name (optional).",
                    }
                },
            ),
        })
        tools.append({
            "name": "scan_domain",
            "description": (
                "Run all agents in a vulnerability domain against the target. "
                "Returns assembled prompt payloads for each agent."
            ),
            "input_schema": self._scan_input_schema(
                extra_required=["target", "domain"],
                extra_props={
                    "target": _target_schema(),
                    "domain": {
                        "type": "string",
                        "description": "Domain name (e.g. 'injection-input-handling').",
                    },
                    "thoroughness": _thoroughness_schema(),
                    "project_root": _project_root_schema(),
                },
            ),
        })
        tools.append({
            "name": "scan_full",
            "description": (
                "Run all registered agents against the target. "
                "Use for comprehensive security audits."
            ),
            "input_schema": self._scan_input_schema(
                extra_required=["target"],
                extra_props={
                    "target": _target_schema(),
                    "thoroughness": _thoroughness_schema(),
                    "project_root": _project_root_schema(),
                },
            ),
        })

        # Per-agent scan tools
        for agent in self._registry.agents.values():
            tools.append({
                "name": f"scan_{agent.meta.name}",
                "description": (
                    f"Run the {agent.meta.display_name} against the target. "
                    f"Detects {agent.meta.cwes.primary} vulnerabilities."
                ),
                "input_schema": self._scan_input_schema(
                    extra_required=["target"],
                    extra_props={
                        "target": _target_schema(),
                        "thoroughness": _thoroughness_schema(),
                        "project_root": _project_root_schema(),
                    },
                ),
            })

        # Phase 2: format_output
        tools.append({
            "name": "format_output",
            "description": (
                "Format scan findings as JSON, SARIF 2.1.0, or Markdown report. "
                "Pass the structured findings array from your analysis."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "findings": {
                        "type": "array",
                        "description": "Array of Finding objects (see models.py Finding schema).",
                    },
                    "format": {
                        "type": "string",
                        "enum": ["json", "sarif", "markdown"],
                        "description": "Output format.",
                        "default": "json",
                    },
                    "scan_metadata": {
                        "type": "object",
                        "description": "Optional metadata (target, agents, timestamp) for report header.",
                    },
                },
                "required": ["findings"],
            },
        })

        # Phase 2: record_exclusion
        tools.append({
            "name": "record_exclusion",
            "description": (
                "Record a false positive exclusion in .screw/learning/exclusions.yaml. "
                "Call this when the user marks a finding as a false positive."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "project_root": {
                        "type": "string",
                        "description": "Absolute path to the project root directory.",
                    },
                    "exclusion": {
                        "type": "object",
                        "description": "Exclusion data: agent, finding, reason, scope.",
                        "properties": {
                            "agent": {"type": "string"},
                            "finding": {
                                "type": "object",
                                "properties": {
                                    "file": {"type": "string"},
                                    "line": {"type": "integer"},
                                    "code_pattern": {"type": "string"},
                                    "cwe": {"type": "string"},
                                },
                                "required": ["file", "line", "code_pattern", "cwe"],
                            },
                            "reason": {"type": "string"},
                            "scope": {
                                "type": "object",
                                "properties": {
                                    "type": {
                                        "type": "string",
                                        "enum": ["exact_line", "pattern", "function", "file", "directory"],
                                    },
                                    "pattern": {"type": "string"},
                                    "path": {"type": "string"},
                                    "name": {"type": "string"},
                                },
                                "required": ["type"],
                            },
                        },
                        "required": ["agent", "finding", "reason", "scope"],
                    },
                },
                "required": ["project_root", "exclusion"],
            },
        })

        # Phase 2: check_exclusions
        tools.append({
            "name": "check_exclusions",
            "description": (
                "Load exclusions from .screw/learning/exclusions.yaml, "
                "optionally filtered by agent name."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "project_root": {
                        "type": "string",
                        "description": "Absolute path to the project root directory.",
                    },
                    "agent": {
                        "type": "string",
                        "description": "Filter exclusions to this agent (optional).",
                    },
                },
                "required": ["project_root"],
            },
        })

        return tools

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_prompt(self, agent: AgentDefinition, thoroughness: str) -> str:
        """Assemble the detection prompt from agent fields.

        Includes core_prompt, detection heuristics (high + medium always;
        context_required only for "deep"), bypass techniques, and
        few-shot examples (up to 3 vulnerable + 3 safe).
        """
        parts: list[str] = []

        # Core prompt
        parts.append(agent.core_prompt.strip())

        # Detection Heuristics
        heuristics = agent.detection_heuristics
        heuristic_lines: list[str] = []

        high = heuristics.high_confidence
        # quick: high-confidence only; standard/deep: include medium; deep: also context_required
        medium = [] if thoroughness == "quick" else heuristics.medium_confidence
        context_req = heuristics.context_required if thoroughness == "deep" else []

        if high:
            heuristic_lines.append("### High Confidence")
            for item in high:
                heuristic_lines.append(_format_heuristic_item(item))

        if medium:
            heuristic_lines.append("### Medium Confidence")
            for item in medium:
                heuristic_lines.append(_format_heuristic_item(item))

        if context_req:
            heuristic_lines.append("### Context Required")
            for item in context_req:
                heuristic_lines.append(_format_heuristic_item(item))

        if heuristic_lines:
            parts.append("## Detection Heuristics\n\n" + "\n".join(heuristic_lines))

        # Bypass techniques — omitted for quick scans
        if agent.bypass_techniques and thoroughness != "quick":
            bypass_lines = ["## Bypass Techniques to Watch For"]
            for bt in agent.bypass_techniques:
                bypass_lines.append(f"**{bt.name}:** {bt.description}")
                if bt.detection_hint:
                    bypass_lines.append(f"  Detection hint: {bt.detection_hint}")
            parts.append("\n".join(bypass_lines))

        # Few-shot examples — omitted for quick scans
        vulnerable_examples = [] if thoroughness == "quick" else agent.few_shot_examples.vulnerable[:3]
        safe_examples = [] if thoroughness == "quick" else agent.few_shot_examples.safe[:3]

        if vulnerable_examples or safe_examples:
            example_lines = ["## Examples"]

            if vulnerable_examples:
                example_lines.append("### Vulnerable Patterns")
                for ex in vulnerable_examples:
                    label = ex.label or "Vulnerable"
                    example_lines.append(f"**{label}** ({ex.language})")
                    example_lines.append(f"```{ex.language}")
                    example_lines.append(ex.code.strip())
                    example_lines.append("```")
                    if ex.explanation:
                        example_lines.append(ex.explanation)

            if safe_examples:
                example_lines.append("### Safe Patterns")
                for ex in safe_examples:
                    label = ex.label or "Safe"
                    example_lines.append(f"**{label}** ({ex.language})")
                    example_lines.append(f"```{ex.language}")
                    example_lines.append(ex.code.strip())
                    example_lines.append("```")
                    if ex.explanation:
                        example_lines.append(ex.explanation)

            parts.append("\n".join(example_lines))

        return "\n\n".join(parts)

    def _format_code_context(self, codes: list[ResolvedCode]) -> str:
        """Format resolved code chunks with file headers into a single string."""
        if not codes:
            return ""

        sections: list[str] = []
        for code in codes:
            header_parts = [f"## File: {code.file_path}"]
            if code.language:
                header_parts.append(f"Language: {code.language}")
            if code.line_start is not None:
                loc = f"Lines: {code.line_start}"
                if code.line_end is not None:
                    loc += f"–{code.line_end}"
                header_parts.append(loc)

            lang_tag = code.language or ""
            sections.append(
                "\n".join(header_parts)
                + f"\n\n```{lang_tag}\n{code.content}\n```"
            )

        return "\n\n---\n\n".join(sections)

    def _scan_input_schema(
        self,
        extra_required: list[str],
        extra_props: dict[str, Any],
    ) -> dict[str, Any]:
        """Build a JSON Schema dict for scan tool inputs.

        Args:
            extra_required: Additional required field names.
            extra_props: Additional property definitions to merge in.

        Returns:
            A JSON Schema object dict.
        """
        schema: dict[str, Any] = {
            "type": "object",
            "properties": dict(extra_props),
        }
        if extra_required:
            schema["required"] = extra_required
        return schema


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------


def _format_heuristic_item(item: Any) -> str:
    """Format a heuristic item (str or HeuristicEntry) as a bullet string."""
    if isinstance(item, str):
        return f"- {item}"
    if isinstance(item, HeuristicEntry):
        langs = f" [{', '.join(item.languages)}]" if item.languages else ""
        return f"- {item.id}: {item.pattern}{langs}"
    # Fallback: duck-type for dict-like objects
    if hasattr(item, "pattern"):
        pattern = item.pattern
        item_id = getattr(item, "id", "")
        langs = getattr(item, "languages", [])
        lang_str = f" [{', '.join(langs)}]" if langs else ""
        prefix = f"{item_id}: " if item_id else ""
        return f"- {prefix}{pattern}{lang_str}"
    return f"- {item}"


def _project_root_schema() -> dict[str, Any]:
    """JSON Schema for the optional 'project_root' parameter."""
    return {
        "type": "string",
        "description": (
            "Absolute path to the project root directory. When provided, "
            "exclusions from .screw/learning/exclusions.yaml are loaded "
            "and included in the scan payload."
        ),
    }


def _target_schema() -> dict[str, Any]:
    """JSON Schema for the 'target' parameter."""
    return {
        "type": "object",
        "description": (
            "Target specification. Must include 'type' (one of: file, glob, lines, "
            "function, class, codebase, git_diff, git_commits, pull_request) "
            "plus type-specific fields."
        ),
        "properties": {
            "type": {"type": "string"},
        },
        "required": ["type"],
    }


def _thoroughness_schema() -> dict[str, Any]:
    """JSON Schema for the 'thoroughness' parameter."""
    return {
        "type": "string",
        "enum": ["quick", "standard", "deep"],
        "description": (
            "Scan depth. 'quick' includes high-confidence heuristics only. "
            "'standard' includes high + medium confidence heuristics. "
            "'deep' also includes context-required heuristics."
        ),
        "default": "standard",
    }
