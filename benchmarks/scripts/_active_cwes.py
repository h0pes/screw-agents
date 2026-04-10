"""The set of CWEs currently covered by at least one screw-agents agent.

This module is the single source of truth for the active CWE filter across
all benchmark ingestion scripts and the MoreFixes extractor. Update this
file when adding a new agent — every ingest script imports from here.

Phase progression:
- Phase 1 (current): 5 CWEs — SQLi, CmdI, SSTI/Code Injection, XSS
- Phase 2+: Append new CWE strings as agents are authored.

Derived forms:
- ACTIVE_CWE_INTS — integer form for MoreFixes, which stores CWE as int column.
- ACTIVE_CWE_DIGITS — bare digit strings for CrossVul directory layout.
"""
from __future__ import annotations


# ---------------------------------------------------------------------------
# Update this set when adding a new agent. Every other name below is derived.
# ---------------------------------------------------------------------------
ACTIVE_CWES: frozenset[str] = frozenset({
    # Phase 1 — injection domain
    "CWE-78",    # OS Command Injection (cmdi.yaml)
    "CWE-79",    # Cross-Site Scripting (xss.yaml)
    "CWE-89",    # SQL Injection (sqli.yaml)
    "CWE-94",    # Code Injection — parent of CWE-1336 SSTI
    "CWE-1336",  # Server-Side Template Injection (ssti.yaml)
    # Phase 2+ additions go below this line, grouped by agent/domain:
})


# Derived forms — never edit these directly; they follow ACTIVE_CWES.
ACTIVE_CWE_INTS: frozenset[int] = frozenset(
    int(c.removeprefix("CWE-")) for c in ACTIVE_CWES
)

ACTIVE_CWE_DIGITS: frozenset[str] = frozenset(
    str(n) for n in ACTIVE_CWE_INTS
)
