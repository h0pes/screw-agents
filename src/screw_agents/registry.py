"""Agent registry — loads and validates YAML agent definitions.

Scans a domains directory for *.yaml files, validates each against the
AgentDefinition Pydantic model, and provides lookup by name and domain.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from screw_agents.models import AgentDefinition

logger = logging.getLogger(__name__)


class AgentRegistry:
    """Registry of validated agent definitions loaded from YAML files."""

    def __init__(self, domains_dir: Path) -> None:
        self._agents: dict[str, AgentDefinition] = {}
        self._domains: dict[str, list[str]] = {}
        self._agent_paths: dict[str, Path] = {}
        self._load(domains_dir)

    def _load(self, domains_dir: Path) -> None:
        """Recursively load and validate all YAML files under domains_dir."""
        if not domains_dir.is_dir():
            logger.warning("Domains directory does not exist: %s", domains_dir)
            return

        for yaml_path in sorted(domains_dir.rglob("*.yaml")):
            logger.debug("Loading agent definition: %s", yaml_path)
            with open(yaml_path) as f:
                raw = yaml.safe_load(f)

            if raw is None:
                continue

            agent = AgentDefinition.model_validate(raw)
            # T-SCAN-REFACTOR Task 1 (Section 10.3): YAML filename stem
            # must equal meta.name. Prevents copy-paste mistakes where a
            # duplicated YAML keeps the original meta.name.
            if yaml_path.stem != agent.meta.name:
                raise ValueError(
                    f"YAML filename stem {yaml_path.stem!r} does not match "
                    f"meta.name {agent.meta.name!r} in {yaml_path}. "
                    f"Convention: stem == meta.name."
                )
            name = agent.meta.name

            if name in self._agents:
                raise ValueError(
                    f"Duplicate agent name {name!r}: "
                    f"already loaded, conflict with {yaml_path}"
                )

            self._agents[name] = agent
            self._agent_paths[name] = yaml_path

            domain = agent.meta.domain
            if domain not in self._domains:
                self._domains[domain] = []
            self._domains[domain].append(name)

        logger.info(
            "Loaded %d agents across %d domains",
            len(self._agents),
            len(self._domains),
        )

        # T-SCAN-REFACTOR Task 1 (Section 10.2): agent names must not
        # collide with domain names. The slash command's bare-token parser
        # disambiguates a token by looking it up in both registries; without
        # this invariant a token could match both, producing ambiguous scope
        # resolution.
        collision = set(self._agents.keys()) & set(self._domains.keys())
        if collision:
            collision_paths = {n: str(self._agent_paths[n]) for n in sorted(collision)}
            raise ValueError(
                f"Agent name(s) collide with domain name(s): {sorted(collision)}. "
                f"Offending agent YAML(s): {collision_paths}. "
                f"Agent names and domain names share a global namespace; rename one."
            )

    @property
    def agents(self) -> dict[str, AgentDefinition]:
        return self._agents

    def get_agent(self, name: str) -> AgentDefinition | None:
        return self._agents.get(name)

    def get_agents_by_domain(self, domain: str) -> list[AgentDefinition]:
        names = self._domains.get(domain, [])
        return [self._agents[n] for n in names]

    def list_domains(self) -> dict[str, int]:
        """Return domain names with agent counts."""
        return {domain: len(names) for domain, names in self._domains.items()}

    def list_agents(self, domain: str | None = None) -> list[dict]:
        """Return agent metadata summaries, optionally filtered by domain."""
        agents = (
            self.get_agents_by_domain(domain)
            if domain
            else list(self._agents.values())
        )
        return [
            {
                "name": a.meta.name,
                "display_name": a.meta.display_name,
                "domain": a.meta.domain,
                "cwe_primary": a.meta.cwes.primary,
                "cwe_related": a.meta.cwes.related,
            }
            for a in agents
        ]
