# Agent Authoring Guide — screw-agents

> See `docs/PRD.md` §4 for the exact YAML agent definition schema.

## Global uniqueness invariants (T-SCAN-REFACTOR)

Three invariants are enforced at registry load time. Violations refuse server start.

1. **Agent names are globally unique across all domains.** Two YAMLs declaring the same `meta.name` raise `ValueError("Duplicate agent name X: ...")` at `registry.py:44-48`. This invariant is established since Phase 1.

2. **Agent names must not collide with any domain name.** A YAML declaring `meta.name: cryptography` (the same as the `domains/cryptography/` directory) raises `ValueError("Agent name(s) collide with domain name(s): ['cryptography']")`. Enforced since T-SCAN-REFACTOR. Reason: the slash command's bare-token parser disambiguates a token by registry lookup; without this invariant `/screw:scan cryptography` would be ambiguous.

3. **YAML filename stem must equal `meta.name`.** A YAML at `domains/X/foo.yaml` declaring `meta.name: bar` raises `ValueError("YAML filename stem 'foo' does not match meta.name 'bar'")`. Enforced since T-SCAN-REFACTOR. Reason: copy-paste protection — duplicate-and-modify workflows often miss the `meta.name` update.

## Schema validators (T-SCAN-REFACTOR Task 1)

Pydantic-level validators run on every loaded YAML:

- **`AgentMeta.name` and `AgentMeta.domain`** must match `^[a-z][a-z0-9_]*$` (lowercase identifier). Uppercase names like `SQLi` or hyphenated names are rejected.
- **`HeuristicEntry.languages`** entries must each appear in the project-wide `SUPPORTED_LANGUAGES` set (`src/screw_agents/models.py`). Today this is `{python, javascript, typescript, go, rust, java, ruby, php, c, c_sharp, cpp}` — note `c_sharp` (snake-case), not `csharp`.
- **`CodeExample.language`** carries the same `SUPPORTED_LANGUAGES` validator.

These validators surface typos during YAML authoring instead of at scan time.

## Adding a new agent (post-T-SCAN-REFACTOR)

Adding a new vulnerability agent NO LONGER requires a per-agent subagent file. Steps:

1. Create `domains/<domain-name>/<agent-name>.yaml` per the schema in `docs/PRD.md` §4.
2. Add language declarations to each `HeuristicEntry` in `detection_heuristics.{high_confidence,medium_confidence,context_required}` — these are the implicit relevance signals (T-SCAN-REFACTOR D4). Without them the agent is treated as universally relevant (fail-open).
3. Verify the agent loads: `uv run pytest tests/test_registry_invariants.py -v`.
4. Run round-trip: `/screw:scan <agent-name> <test-target>` to confirm the universal `screw-scan` subagent picks it up.

The universal `screw-scan` subagent handles all registered agents — no new subagent file needed.

## Implicit relevance derivation (T-SCAN-REFACTOR D4)

`_filter_relevant_agents` in `engine.py` computes per-agent supported-language sets by union over `HeuristicEntry.languages` across all three confidence tiers (`high_confidence`, `medium_confidence`, `context_required`). When a target's language set has no overlap with an agent's supported-language set, the agent is dropped from the scan and recorded under `agents_excluded_by_relevance` in the init-page response.

Agents declaring zero languages (no `languages` list on any heuristic) fail-open — they are kept on every scan regardless of target language. This deliberate fail-open behavior is documented in spec §8.5.

For explicit AST-based or content-based relevance signals beyond language matching, see deferred entry **T-SCAN-RELEV-1** in `docs/DEFERRED_BACKLOG.md`.
