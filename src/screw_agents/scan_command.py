"""Slash command scope-spec parser + resolver.

T-SCAN-REFACTOR Task 8: extracted from `plugins/screw/commands/scan.md`
for testability. The slash command's markdown body invokes these helpers
to convert raw `$ARGUMENTS` strings into resolved agent lists, then
dispatches `scan_agents` with the result.

Spec sections 6.1, 6.2, 6.3, 6.6.

Plan-fix decisions (post pre-audit on HEAD 9356593):

- E1=A: parser invocation moved from shell-injection-vulnerable Bash to
  MCP tool registration (`mcp__screw-agents__resolve_scope`). The MCP
  layer JSON-serializes input — no shell parsing. Eliminates the
  injection class entirely.
- E3=C: `resolve_scope` returns a flat sorted `list[str]` (security-
  critical, simple). The new `summarize_scope` returns the enriched
  per-domain "subset|full" annotation for the pre-execution summary.
- E4=A: `--adaptive` + `--no-confirm` mutually exclusive — combining is
  a hard error before scope parse. `validate_flags` enforces this.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from screw_agents.registry import AgentRegistry


# Quality review EQ1=B (Marco approved): cap total scope size at the parser
# layer so all callers (MCP traffic, direct Python tests) hit the same
# guard. 50 covers the future 41-agent CWE-1400 expansion plus headroom;
# beyond that, prefer `full` or split into multiple invocations.
MAX_SCOPE_SIZE = 50

# Quality review EQ2=B (Marco approved): reject any token not matching
# the agent/domain naming convention at parse time. Cleaner error than
# letting a control-character payload reach the registry-layer "Unknown
# agent" downstream rejection.
_VALID_TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


class ScopeResolutionError(ValueError):
    """Raised when scope-spec parsing or resolution fails.

    The slash command surfaces this as a user-facing error message before
    any dispatch.
    """


@dataclass(frozen=True)
class ParsedScope:
    """Result of `parse_scope_spec` — pre-registry-validation.

    Frozen for immutability so the dataclass itself never gets mutated
    after construction; the resolver consumes the typed form, not raw
    string state.

    The `form` field discriminates between the three exclusive scope
    grammars (spec section 6.1):
        - "bare-token": single token resolved by registry lookup
          (domain name OR agent name; collision invariant guarantees
          uniqueness; see registry.py).
        - "full": the `full` keyword — resolves to all registered agents.
        - "prefix-key": one or more `domains:` and/or `agents:` keys.
    """

    form: Literal["bare-token", "full", "prefix-key"]
    full_keyword: bool = False
    bare_token: str | None = None
    domains_explicit: tuple[str, ...] = ()
    agents_explicit: tuple[str, ...] = ()


def validate_flags(flags: list[str]) -> dict[str, bool]:
    """Validate flag combinations BEFORE scope parsing.

    Args:
        flags: list of flag tokens extracted from `$ARGUMENTS`.

    Returns:
        dict with `adaptive` and `no_confirm` booleans for the slash
        command body to consume.

    Raises:
        ValueError: if `--adaptive` and `--no-confirm` are both present
            (E4=A: hard error per Marco's approval). `--adaptive`
            requires interactive consent; `--no-confirm` signals
            non-interactive context — they cannot be combined.
    """
    adaptive = "--adaptive" in flags
    no_confirm = "--no-confirm" in flags
    if adaptive and no_confirm:
        raise ValueError(
            "Error: `--adaptive` requires interactive consent (5-section "
            "review prompts). `--no-confirm` signals non-interactive context. "
            "Pick one — they cannot be combined."
        )
    return {"adaptive": adaptive, "no_confirm": no_confirm}


def _split_csv(rest: str, key: str) -> list[str]:
    """Split a comma-separated value list and reject malformed tokens.

    A token like ``domains: foo`` (space after colon) would have ``rest =
    " foo"`` and be silently re-classified by an earlier permissive
    parser. We instead require the entire ``rest`` to be free of internal
    whitespace per the spec — pre-audit Edit 11.

    Quality review EQ2=B: every token must additionally match
    ``_VALID_TOKEN_RE`` so control characters, uppercase, leading dash
    etc. are rejected at parse time rather than reaching the registry-
    layer "Unknown agent" downstream rejection.
    """
    if any(ch.isspace() for ch in rest):
        raise ScopeResolutionError(
            "Whitespace not allowed inside prefix-key values. "
            "Use commas (no spaces) to separate names: "
            "'domains:foo,bar' or 'agents:baz,qux'."
        )
    tokens = [n.strip() for n in rest.split(",") if n.strip()]
    for tok in tokens:
        if not _VALID_TOKEN_RE.match(tok):
            raise ScopeResolutionError(
                f"Invalid token {tok!r} in {key!r} value. "
                f"Tokens must match ^[a-z0-9][a-z0-9_-]*$ (lowercase letter/digit "
                f"start; lowercase letters, digits, underscores, hyphens). "
                f"Use {key}:value1,value2 with bare names only."
            )
    return tokens


def parse_scope_spec(scope_text: str) -> ParsedScope:
    """Parse the scope-spec portion of `$ARGUMENTS`.

    The slash command's parser splits `$ARGUMENTS` at flags (--*) and the
    target spec separately; this helper takes only the scope-spec tokens.

    Args:
        scope_text: whitespace-separated tokens forming the scope spec.

    Returns:
        ParsedScope with `form` set to whichever of the three exclusive
        grammars was used.

    Raises:
        ScopeResolutionError: on empty, mixed forms, malformed prefix
            keys, or whitespace inside prefix-key values.
    """
    tokens = scope_text.strip().split()
    if not tokens:
        raise ScopeResolutionError("Scope-spec is empty; pass a scope token.")

    full_keyword = False
    bare_token: str | None = None
    domains_explicit: list[str] = []
    agents_explicit: list[str] = []

    has_full = False
    has_bare = False
    has_prefix = False

    for tok in tokens:
        if tok == "full":
            has_full = True
            full_keyword = True
            continue
        if ":" in tok:
            has_prefix = True
            prefix, _sep, rest = tok.partition(":")
            if prefix not in ("domains", "agents"):
                raise ScopeResolutionError(
                    f"Unknown prefix key {prefix!r}. Allowed: 'domains:', 'agents:'."
                )
            # Empty rest after `:` covers two cases:
            #   1. Bare prefix key with no value (e.g. `agents:`)
            #   2. Whitespace after colon (e.g. `domains: foo`) — shell-
            #      style tokenizer already split the value off into a
            #      separate token (pre-audit Edit 11).
            # Either way, raise an actionable error instead of silently
            # misclassifying.
            if rest == "":
                raise ScopeResolutionError(
                    f"Empty value after prefix key {prefix!r}. "
                    f"Use {prefix}:value1,value2 (no spaces, comma-separated)."
                )
            if prefix == "domains":
                domains_explicit.extend(_split_csv(rest, prefix))
            else:  # prefix == "agents"
                agents_explicit.extend(_split_csv(rest, prefix))
            continue
        # Bare token (no colon, not 'full')
        has_bare = True
        if bare_token is not None:
            raise ScopeResolutionError(
                "Multiple bare tokens not supported. Use 'domains:' / "
                "'agents:' prefix syntax for multi-scope."
            )
        bare_token = tok

    # Mutual exclusivity
    forms_used = sum([has_full, has_bare, has_prefix])
    if forms_used > 1:
        raise ScopeResolutionError(
            "Scope forms are exclusive: pick exactly one of 'full', a bare "
            "domain/agent name, or 'domains:'/'agents:' prefix-keys."
        )

    if has_full:
        form: Literal["bare-token", "full", "prefix-key"] = "full"
    elif has_bare:
        form = "bare-token"
    else:
        form = "prefix-key"

    # Quality review EQ1=B: reject oversized prefix-key requests at the
    # parser layer so all callers hit the same guard. `full` and bare-
    # token forms cap themselves (registry-bounded), so the limit only
    # matters for the prefix-key form.
    total = len(domains_explicit) + len(agents_explicit)
    if total > MAX_SCOPE_SIZE:
        raise ScopeResolutionError(
            f"Scope size {total} exceeds limit of {MAX_SCOPE_SIZE} "
            f"(domains={len(domains_explicit)}, agents={len(agents_explicit)}). "
            f"Use `full` for whole-registry scans, or split into multiple "
            f"smaller invocations."
        )

    return ParsedScope(
        form=form,
        full_keyword=full_keyword,
        bare_token=bare_token,
        domains_explicit=tuple(domains_explicit),
        agents_explicit=tuple(agents_explicit),
    )


def resolve_scope(parsed: ParsedScope, registry: AgentRegistry) -> list[str]:
    """Resolve a `ParsedScope` to a sorted, deduplicated list of agent names.

    Spec section 6.3. This is the security-critical path — registry
    allowlist (no agent ever runs unless it's in the loaded registry) plus
    cross-domain rejection (an agent name in `agents:` must belong to a
    listed `domains:` if `domains:` is non-empty). Kept simple per E3=C.

    Args:
        parsed: result of `parse_scope_spec`.
        registry: loaded AgentRegistry.

    Returns:
        Sorted, deduplicated list of agent names.

    Raises:
        ScopeResolutionError: on unknown domain/agent or cross-domain
            agent reference (spec section 6.6).
    """
    domain_names = set(registry.list_domains().keys())
    agent_names_known = set(registry.agents.keys())

    if parsed.full_keyword:
        return sorted(agent_names_known)

    if parsed.bare_token is not None:
        name = parsed.bare_token
        if name in domain_names:
            return sorted(a.meta.name for a in registry.get_agents_by_domain(name))
        if name in agent_names_known:
            return [name]
        raise ScopeResolutionError(
            f"{name!r} is not a domain or agent. Run "
            f"`mcp__screw-agents__list_domains` and "
            f"`mcp__screw-agents__list_agents` to see registered names."
        )

    # Prefix-key form
    final: set[str] = set()

    for domain in parsed.domains_explicit:
        if domain not in domain_names:
            raise ScopeResolutionError(
                f"Unknown domain {domain!r}. Run "
                f"`mcp__screw-agents__list_domains` to see registered domains."
            )
        agents_listed_in_domain = [
            name
            for name in parsed.agents_explicit
            if registry.get_agent(name) is not None
            and registry.get_agent(name).meta.domain == domain
        ]
        if agents_listed_in_domain:
            final.update(agents_listed_in_domain)
        else:
            final.update(a.meta.name for a in registry.get_agents_by_domain(domain))

    for agent in parsed.agents_explicit:
        if agent not in agent_names_known:
            raise ScopeResolutionError(
                f"Unknown agent {agent!r}. Run "
                f"`mcp__screw-agents__list_agents` to see registered agents."
            )
        agent_def = registry.get_agent(agent)
        if agent_def is None:
            # Unreachable in practice — `agent in agent_names_known`
            # was just verified above. Defensive raise instead of
            # `assert` so the invariant fires under `python -O` too
            # (assertions become no-ops; defensive raises always fire).
            raise ScopeResolutionError(
                f"Internal error: agent {agent!r} not found in registry "
                f"despite earlier validation. This is a bug; please report."
            )
        if (
            parsed.domains_explicit
            and agent_def.meta.domain not in parsed.domains_explicit
        ):
            raise ScopeResolutionError(
                f"Agent {agent!r} belongs to domain "
                f"{agent_def.meta.domain!r}, which is not in any of the "
                f"listed domains:{','.join(parsed.domains_explicit)}. "
                f"Either add {agent_def.meta.domain!r} to 'domains:', or "
                f"omit 'agents:{agent}'."
            )
        final.add(agent)

    if not final:
        raise ScopeResolutionError(
            "No agents resolved from the given scope. Pass 'full', a bare "
            "domain/agent name, or 'domains:'/'agents:' prefix-keys."
        )

    return sorted(final)


def summarize_scope(parsed: ParsedScope, registry: AgentRegistry) -> list[dict]:
    """Enriched per-domain summary for the pre-execution summary line.

    E3=C (Marco approved): split from resolve_scope so the security-
    critical resolution (registry allowlist + cross-domain rejection)
    stays simple and testable, while the UX-formatting concern lives
    separately.

    Returns a list of dicts:
        [{"domain": str, "mode": "subset"|"full", "agents": list[str]}, ...]

    Mode "full" = all agents in the domain (e.g., bare-token domain or
    `full` keyword path). Mode "subset" = only the explicitly-named
    agents from the domain (e.g., `agents:sqli` resolves to subset of
    injection-input-handling).

    Args:
        parsed: result of `parse_scope_spec`.
        registry: loaded AgentRegistry.

    Returns:
        Sorted-by-domain list of summary dicts. Each entry's `agents`
        list is also sorted. Used by `/screw:scan` body to render the
        per-domain "subset|full" annotation in the pre-execution summary.
    """
    domain_names = set(registry.list_domains().keys())
    agent_names_known = set(registry.agents.keys())

    # Group: domain_name -> {"mode": "full"|"subset", "agents": set[str]}
    groups: dict[str, dict] = {}

    if parsed.full_keyword:
        for domain in sorted(domain_names):
            groups[domain] = {
                "mode": "full",
                "agents": {a.meta.name for a in registry.get_agents_by_domain(domain)},
            }
    elif parsed.bare_token is not None:
        name = parsed.bare_token
        if name in domain_names:
            groups[name] = {
                "mode": "full",
                "agents": {a.meta.name for a in registry.get_agents_by_domain(name)},
            }
        elif name in agent_names_known:
            agent_def = registry.get_agent(name)
            if agent_def is None:
                # Unreachable — `name in agent_names_known` was just
                # verified. Defensive raise (assert is a no-op under -O).
                raise ScopeResolutionError(
                    f"Internal error: agent {name!r} not found in registry "
                    f"despite earlier validation. This is a bug; please report."
                )
            domain = agent_def.meta.domain
            groups[domain] = {"mode": "subset", "agents": {name}}
        # else: unknown bare token — resolve_scope raises; summarize is
        # called after a successful resolve, so we'd never see this path.
    else:
        # Prefix-key form. Walk domains: first to seed full-mode groups,
        # then narrow with agents: when both are present.
        for domain in parsed.domains_explicit:
            if domain not in domain_names:
                continue  # resolve_scope raises before summarize is called
            agents_listed_in_domain = {
                aname
                for aname in parsed.agents_explicit
                if registry.get_agent(aname) is not None
                and registry.get_agent(aname).meta.domain == domain
            }
            if agents_listed_in_domain:
                groups[domain] = {"mode": "subset", "agents": agents_listed_in_domain}
            else:
                groups[domain] = {
                    "mode": "full",
                    "agents": {a.meta.name for a in registry.get_agents_by_domain(domain)},
                }

        # agents: without (or in addition to) domains: contribute their
        # home domains. If a domain group already exists in "full" mode
        # (seeded by domains:), the agent is already covered. Otherwise,
        # add to (or create) a "subset" group.
        for agent in parsed.agents_explicit:
            if agent not in agent_names_known:
                continue  # resolve_scope raises before summarize is called
            agent_def = registry.get_agent(agent)
            if agent_def is None:
                # Unreachable — `agent in agent_names_known` was just
                # verified. Defensive raise (assert is a no-op under -O).
                raise ScopeResolutionError(
                    f"Internal error: agent {agent!r} not found in registry "
                    f"despite earlier validation. This is a bug; please report."
                )
            domain = agent_def.meta.domain
            if domain in groups:
                if groups[domain]["mode"] == "full":
                    # Domain already covered by domains: branch in full
                    # mode; the agent is part of the full set.
                    continue
                # Subset mode: append this agent.
                groups[domain]["agents"].add(agent)
            else:
                groups[domain] = {"mode": "subset", "agents": {agent}}

    return [
        {"domain": d, "mode": groups[d]["mode"], "agents": sorted(groups[d]["agents"])}
        for d in sorted(groups)
    ]
