"""CWE-1400 hierarchy traversal for the benchmark evaluator.

Loads `benchmarks/data/cwe-1400-hierarchy.yaml` (extracted from MITRE XML by
scripts/extract_cwe_1400.py) and exposes two comparison modes:

  strict_match(agent_cwe, truth_cwe) -- True if agent_cwe == truth_cwe OR
                                        agent_cwe is a descendant of truth_cwe.

  broad_match(agent_cwe, truth_cwe)  -- True if both CWEs share a CWE-1400
                                        category (CWE-14xx) ancestor.

See ADR-013 for why we use CWE-1400 (not CWE-1000 as bentoo does).
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, model_validator


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_HIERARCHY_PATH = REPO_ROOT / "benchmarks" / "data" / "cwe-1400-hierarchy.yaml"


class CweNode(BaseModel):
    cwe_id: str
    name: str
    abstraction: str  # "Base", "Variant", "Class", "Category"
    parents: list[str] = Field(default_factory=list)
    children: list[str] = Field(default_factory=list)


class Cwe1400Hierarchy(BaseModel):
    """In-memory CWE-1400 hierarchy with traversal helpers."""
    view_id: str
    view_name: str
    nodes: dict[str, CweNode]
    view_members: list[str]
    # Reverse index: parent -> children, built from nodes[*].parents.
    # The YAML only populates children on Category nodes; this index fills
    # the gap for Base/Variant/Class nodes so descendants_of works fully.
    _rev_children: dict[str, list[str]] = {}

    @model_validator(mode="after")
    def _build_reverse_index(self) -> "Cwe1400Hierarchy":
        rev: dict[str, list[str]] = {}
        for cwe_id, node in self.nodes.items():
            for p in node.parents:
                rev.setdefault(p, []).append(cwe_id)
        object.__setattr__(self, "_rev_children", rev)
        return self

    def ancestors_of(self, cwe_id: str) -> set[str]:
        """All transitive parents of cwe_id (not including cwe_id itself)."""
        seen: set[str] = set()
        stack = [cwe_id]
        while stack:
            current = stack.pop()
            node = self.nodes.get(current)
            if node is None:
                continue
            for p in node.parents:
                if p not in seen:
                    seen.add(p)
                    stack.append(p)
        return seen

    def descendants_of(self, cwe_id: str) -> set[str]:
        """All transitive children of cwe_id (not including cwe_id itself).

        Uses the reverse-parent index so that non-category nodes (Base/Variant/
        Class) whose YAML ``children`` list is empty are still traversed
        correctly via their children's ``parents`` back-references.
        """
        seen: set[str] = set()
        stack = list(self._rev_children.get(cwe_id, []))
        seen.update(stack)
        while stack:
            current = stack.pop()
            for c in self._rev_children.get(current, []):
                if c not in seen:
                    seen.add(c)
                    stack.append(c)
        return seen

    def category_of(self, cwe_id: str) -> str | None:
        """Return the first CWE-14xx category ancestor of cwe_id, or None."""
        if cwe_id not in self.nodes:
            return None
        if self._is_view_category(cwe_id):
            return cwe_id
        queue = list(self.nodes[cwe_id].parents)
        seen = set(queue)
        while queue:
            current = queue.pop(0)
            if self._is_view_category(current):
                return current
            node = self.nodes.get(current)
            if node is None:
                continue
            for p in node.parents:
                if p not in seen:
                    seen.add(p)
                    queue.append(p)
        return None

    def _is_view_category(self, cwe_id: str) -> bool:
        node = self.nodes.get(cwe_id)
        return (
            node is not None
            and node.abstraction == "Category"
            and cwe_id in self.view_members
        )

    def strict_match(self, agent_cwe: str, truth_cwe: str) -> bool:
        """True if agent_cwe == truth_cwe OR agent_cwe is a descendant of truth_cwe."""
        if agent_cwe not in self.nodes or truth_cwe not in self.nodes:
            return False
        if agent_cwe == truth_cwe:
            return True
        return agent_cwe in self.descendants_of(truth_cwe)

    def broad_match(self, agent_cwe: str, truth_cwe: str) -> bool:
        """True if both CWEs share a CWE-1400 category (CWE-14xx) ancestor."""
        if agent_cwe not in self.nodes or truth_cwe not in self.nodes:
            return False
        agent_cat = self.category_of(agent_cwe)
        truth_cat = self.category_of(truth_cwe)
        if agent_cat is None or truth_cat is None:
            return False
        return agent_cat == truth_cat


@lru_cache(maxsize=1)
def load_hierarchy(path: Path | None = None) -> Cwe1400Hierarchy:
    """Load CWE-1400 hierarchy YAML. Cached — loads once per process."""
    yaml_path = Path(path) if path else DEFAULT_HIERARCHY_PATH
    data = yaml.safe_load(yaml_path.read_text())
    return Cwe1400Hierarchy.model_validate(data)
