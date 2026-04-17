"""Tests for Pydantic models — YAML agent schema."""

import yaml
import pytest
from pydantic import ValidationError

from screw_agents.models import (
    AgentDefinition,
    AgentMeta,
    AggregateReport,
    CWEs,
    DirectorySuggestion,
    FPPattern,
    FPReport,
    PatternSuggestion,
)


def test_cwes_model():
    cwes = CWEs(primary="CWE-89", related=["CWE-564", "CWE-566"])
    assert cwes.primary == "CWE-89"
    assert len(cwes.related) == 2


def test_cwes_requires_primary():
    with pytest.raises(Exception):
        CWEs(related=["CWE-564"])


def test_agent_meta_minimal():
    meta = AgentMeta(
        name="test",
        display_name="Test Agent",
        domain="test-domain",
        version="1.0.0",
        last_updated="2026-04-10",
        cwes=CWEs(primary="CWE-89"),
        capec=["CAPEC-66"],
        owasp={"top10": "A05:2025"},
        sources=[],
    )
    assert meta.name == "test"


def test_agent_definition_from_real_yaml(sqli_yaml_path):
    with open(sqli_yaml_path) as f:
        data = yaml.safe_load(f)
    agent = AgentDefinition.model_validate(data)
    assert agent.meta.name == "sqli"
    assert agent.meta.cwes.primary == "CWE-89"
    assert agent.core_prompt is not None
    assert len(agent.core_prompt) > 100
    assert agent.detection_heuristics.high_confidence is not None
    assert len(agent.detection_heuristics.high_confidence) > 0
    assert len(agent.bypass_techniques) > 0
    assert agent.target_strategy.scope == "function"


def test_all_phase1_yamls_validate(domains_dir):
    yaml_dir = domains_dir / "injection-input-handling"
    for yaml_path in yaml_dir.glob("*.yaml"):
        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        agent = AgentDefinition.model_validate(data)
        assert agent.meta.name in ("sqli", "cmdi", "ssti", "xss")
        assert agent.meta.domain == "injection-input-handling"


def test_agent_definition_missing_core_prompt_fails():
    data = {
        "meta": {
            "name": "bad",
            "display_name": "Bad",
            "domain": "test",
            "version": "1.0.0",
            "last_updated": "2026-01-01",
            "cwes": {"primary": "CWE-89"},
            "capec": [],
            "owasp": {"top10": "A05:2025"},
            "sources": [],
        },
        "detection_heuristics": {"high_confidence": ["pattern"]},
        "bypass_techniques": [],
        "remediation": {"preferred": "fix it"},
        "few_shot_examples": {"vulnerable": [], "safe": []},
        "target_strategy": {"scope": "function", "file_patterns": ["**/*.py"]},
    }
    with pytest.raises(Exception):
        AgentDefinition.model_validate(data)


def test_agent_definition_missing_detection_heuristics_fails():
    data = {
        "meta": {
            "name": "bad",
            "display_name": "Bad",
            "domain": "test",
            "version": "1.0.0",
            "last_updated": "2026-01-01",
            "cwes": {"primary": "CWE-89"},
            "capec": [],
            "owasp": {"top10": "A05:2025"},
            "sources": [],
        },
        "core_prompt": "You are a test agent.",
        "bypass_techniques": [],
        "remediation": {"preferred": "fix it"},
        "few_shot_examples": {"vulnerable": [], "safe": []},
        "target_strategy": {"scope": "function", "file_patterns": ["**/*.py"]},
    }
    with pytest.raises(Exception):
        AgentDefinition.model_validate(data)


from screw_agents.models import (
    Finding, FindingLocation, DataFlow, FindingClassification,
    FindingAnalysis, FindingRemediation, FindingTriage,
)


def test_finding_location_minimal():
    loc = FindingLocation(
        file="src/api/users.py",
        line_start=42,
    )
    assert loc.file == "src/api/users.py"
    assert loc.data_flow is None


def test_finding_location_with_data_flow():
    loc = FindingLocation(
        file="src/api/users.py",
        line_start=42,
        line_end=48,
        function="get_user",
        data_flow=DataFlow(
            source="request.getParameter('username')",
            source_location="UserController.java:42",
            sink="stmt.executeQuery(query)",
            sink_location="UserController.java:48",
        ),
    )
    assert loc.data_flow.source == "request.getParameter('username')"


def test_finding_complete():
    finding = Finding(
        id="sqli-001-abc123",
        agent="sqli",
        domain="injection-input-handling",
        timestamp="2026-04-10T14:30:00Z",
        location=FindingLocation(file="test.py", line_start=10),
        classification=FindingClassification(
            cwe="CWE-89",
            cwe_name="SQL Injection",
            severity="high",
            confidence="high",
        ),
        analysis=FindingAnalysis(
            description="SQL injection via f-string",
            impact="Data exfiltration",
            exploitability="Trivially exploitable",
        ),
        remediation=FindingRemediation(
            recommendation="Use parameterized queries",
        ),
    )
    assert finding.id == "sqli-001-abc123"
    assert finding.triage.status == "pending"


def test_finding_requires_location():
    with pytest.raises(Exception):
        Finding(
            id="test",
            agent="sqli",
            domain="test",
            timestamp="2026-01-01T00:00:00Z",
            classification=FindingClassification(
                cwe="CWE-89", cwe_name="SQLi",
                severity="high", confidence="high",
            ),
            analysis=FindingAnalysis(description="test"),
            remediation=FindingRemediation(recommendation="fix"),
        )


from screw_agents.models import (
    Exclusion,
    ExclusionFinding,
    ExclusionInput,
    ExclusionScope,
    FindingTriage,
    ReviewerKey,
    ScrewConfig,
)


class TestExclusionModels:
    def test_exclusion_scope_pattern(self):
        scope = ExclusionScope(type="pattern", pattern="db.text_search(*)")
        assert scope.type == "pattern"
        assert scope.pattern == "db.text_search(*)"

    def test_exclusion_scope_exact_line(self):
        scope = ExclusionScope(type="exact_line", path="src/api.py")
        assert scope.type == "exact_line"

    def test_exclusion_scope_directory(self):
        scope = ExclusionScope(type="directory", path="test/")
        assert scope.type == "directory"

    def test_exclusion_scope_function(self):
        scope = ExclusionScope(type="function", path="src/api.py", name="get_user")
        assert scope.type == "function"
        assert scope.name == "get_user"

    def test_exclusion_scope_file(self):
        scope = ExclusionScope(type="file", path="src/generated.py")
        assert scope.type == "file"

    def test_exclusion_finding(self):
        ef = ExclusionFinding(
            file="src/api.py", line=42, code_pattern="db.text_search(*)", cwe="CWE-89"
        )
        assert ef.file == "src/api.py"
        assert ef.line == 42

    def test_exclusion_input(self):
        ei = ExclusionInput(
            agent="sqli",
            finding=ExclusionFinding(
                file="src/api.py", line=42, code_pattern="db.query(*)", cwe="CWE-89"
            ),
            reason="uses parameterized queries",
            scope=ExclusionScope(type="pattern", pattern="db.query(*)"),
        )
        assert ei.agent == "sqli"
        assert ei.reason == "uses parameterized queries"

    def test_exclusion_full(self):
        exc = Exclusion(
            id="fp-2026-04-11-001",
            created="2026-04-11T14:35:00Z",
            agent="sqli",
            finding=ExclusionFinding(
                file="src/api.py", line=42, code_pattern="db.query(*)", cwe="CWE-89"
            ),
            reason="parameterized",
            scope=ExclusionScope(type="pattern", pattern="db.query(*)"),
            times_suppressed=0,
            last_suppressed=None,
        )
        assert exc.id == "fp-2026-04-11-001"
        assert exc.times_suppressed == 0

    def test_exclusion_defaults(self):
        exc = Exclusion(
            id="fp-2026-04-11-001",
            created="2026-04-11T14:35:00Z",
            agent="sqli",
            finding=ExclusionFinding(
                file="src/api.py", line=42, code_pattern="db.query(*)", cwe="CWE-89"
            ),
            reason="safe",
            scope=ExclusionScope(type="file", path="src/api.py"),
        )
        assert exc.times_suppressed == 0
        assert exc.last_suppressed is None

    # ----- Task 2 — signing field tests (moved into class) -----

    def test_exclusion_signing_fields_optional(self):
        """Phase 2 exclusions without signatures still parse (backwards compat)."""
        excl = Exclusion(
            id="fp-2026-04-14-001",
            created="2026-04-14T10:00:00Z",
            agent="sqli",
            finding=ExclusionFinding(
                file="src/services/user_service.py",
                line=42,
                code_pattern="db.text_search(*)",
                cwe="CWE-89",
            ),
            reason="uses parameterized internals",
            scope=ExclusionScope(type="pattern", pattern="db.text_search(*)"),
        )
        assert excl.signed_by is None
        assert excl.signature is None
        assert excl.signature_version == 1
        assert excl.quarantined is False

    def test_exclusion_signing_fields_optional_from_yaml_dict(self):
        """T2-I3: backwards-compat parse via YAML dict mirrors the production
        path in `learning.load_exclusions` (`Exclusion.model_validate(entry)`)
        rather than kwargs construction. A pre-Phase-3a exclusion entry that
        lacks `signed_by` / `signature` / `signature_version` keys must still
        parse cleanly with default values.
        """
        yaml_text = """
        id: fp-2026-04-14-001
        created: '2026-04-14T10:00:00Z'
        agent: sqli
        finding:
          file: src/services/user_service.py
          line: 42
          code_pattern: db.text_search(*)
          cwe: CWE-89
        reason: uses parameterized internals
        scope:
          type: pattern
          pattern: db.text_search(*)
        """
        entry = yaml.safe_load(yaml_text)
        excl = Exclusion.model_validate(entry)
        assert excl.signed_by is None
        assert excl.signature is None
        assert excl.signature_version == 1
        assert excl.quarantined is False

    def test_exclusion_signing_fields_round_trip(self):
        """T2-M2 rename: round-trips signing fields through Exclusion construction."""
        excl = Exclusion(
            id="fp-2026-04-14-002",
            created="2026-04-14T10:00:00Z",
            agent="sqli",
            finding=ExclusionFinding(
                file="src/auth.py", line=12, code_pattern="*", cwe="CWE-89"
            ),
            reason="test",
            scope=ExclusionScope(type="exact_line", path="src/auth.py"),
            signed_by="marco@example.com",
            signature="U1NIU0lH...",
            signature_version=1,
        )
        assert excl.signed_by == "marco@example.com"
        assert excl.signature is not None
        assert excl.quarantined is False

    def test_exclusion_model_dump_excludes_quarantined(self):
        """The runtime-only `quarantined` flag must never appear in serialized output."""
        excl = Exclusion(
            id="fp-dump-test",
            created="2026-04-14T10:00:00Z",
            agent="sqli",
            finding=ExclusionFinding(
                file="a.py", line=1, code_pattern="*", cwe="CWE-89"
            ),
            reason="test",
            scope=ExclusionScope(type="pattern", pattern="*"),
        )

        # Default — no user exclusions
        dumped = excl.model_dump()
        assert "quarantined" not in dumped

        # Even when quarantined is True, the serialized form omits it
        excl.quarantined = True
        dumped = excl.model_dump()
        assert "quarantined" not in dumped

        # User's explicit exclude= (set form) still respected and still excludes quarantined
        dumped = excl.model_dump(exclude={"reason"})
        assert "quarantined" not in dumped
        assert "reason" not in dumped

        # User's explicit exclude= (dict form) still respected and still excludes quarantined
        dumped = excl.model_dump(exclude={"reason": True})
        assert "quarantined" not in dumped
        assert "reason" not in dumped

    def test_exclusion_model_dump_json_excludes_quarantined(self):
        """model_dump_json must also omit the runtime-only quarantined flag.

        Pydantic v2's model_dump_json routes through a Rust-backed serializer that
        does NOT call the Python model_dump override, so schema-level Field(exclude=True)
        is the primary defense for this path.
        """
        import json

        excl = Exclusion(
            id="fp-json-test",
            created="2026-04-14T10:00:00Z",
            agent="sqli",
            finding=ExclusionFinding(
                file="a.py", line=1, code_pattern="*", cwe="CWE-89"
            ),
            reason="test",
            scope=ExclusionScope(type="pattern", pattern="*"),
        )

        # Default
        data = json.loads(excl.model_dump_json())
        assert "quarantined" not in data

        # Explicitly True
        excl.quarantined = True
        data = json.loads(excl.model_dump_json())
        assert "quarantined" not in data

    def test_exclusion_include_does_not_leak_quarantined(self):
        """Even if a caller explicitly passes include={"quarantined"}, the field
        must NOT appear in serialized output. This verifies Layer 2 (the custom
        model_dump override) catches the include edge case that schema-level
        Field(exclude=True) may not."""
        excl = Exclusion(
            id="fp-include-test",
            created="2026-04-14T10:00:00Z",
            agent="sqli",
            finding=ExclusionFinding(
                file="a.py", line=1, code_pattern="*", cwe="CWE-89"
            ),
            reason="test",
            scope=ExclusionScope(type="pattern", pattern="*"),
        )
        excl.quarantined = True

        # If a caller explicitly tries to include quarantined, it must still be stripped.
        dumped = excl.model_dump(include={"id", "quarantined"})
        assert "quarantined" not in dumped
        assert "id" in dumped  # other included fields still present

    # ----- Task 11 — trust_state runtime-only field -----

    def test_exclusion_trust_state_default_is_trusted(self):
        """Fresh Exclusion has trust_state='trusted' (matches quarantined=False default)."""
        exc = Exclusion(
            id="fp-2026-04-14-001",
            created="2026-04-14T10:00:00Z",
            agent="sqli",
            finding=ExclusionFinding(
                file="src/a.py", line=10, code_pattern="*", cwe="CWE-89"
            ),
            reason="test",
            scope=ExclusionScope(type="file", path="src/a.py"),
        )
        assert exc.trust_state == "trusted"
        assert exc.quarantined is False

    def test_exclusion_trust_state_accepts_all_literal_values(self):
        """trust_state accepts the four literal values."""
        for state in ("trusted", "warned", "quarantined", "allowed"):
            exc = Exclusion(
                id="fp-2026-04-14-001",
                created="2026-04-14T10:00:00Z",
                agent="sqli",
                finding=ExclusionFinding(
                    file="src/a.py", line=10, code_pattern="*", cwe="CWE-89"
                ),
                reason="test",
                scope=ExclusionScope(type="file", path="src/a.py"),
                trust_state=state,
            )
            assert exc.trust_state == state

    def test_exclusion_trust_state_rejects_invalid_value(self):
        """trust_state rejects values outside the literal set."""
        with pytest.raises(ValidationError):
            Exclusion(
                id="fp-2026-04-14-001",
                created="2026-04-14T10:00:00Z",
                agent="sqli",
                finding=ExclusionFinding(
                    file="src/a.py", line=10, code_pattern="*", cwe="CWE-89"
                ),
                reason="test",
                scope=ExclusionScope(type="file", path="src/a.py"),
                trust_state="pending",  # not in literal
            )

    def test_exclusion_model_dump_excludes_trust_state(self):
        """trust_state is stripped from model_dump output (runtime-only flag)."""
        exc = Exclusion(
            id="fp-2026-04-14-001",
            created="2026-04-14T10:00:00Z",
            agent="sqli",
            finding=ExclusionFinding(
                file="src/a.py", line=10, code_pattern="*", cwe="CWE-89"
            ),
            reason="test",
            scope=ExclusionScope(type="file", path="src/a.py"),
            trust_state="warned",
        )
        dumped = exc.model_dump()
        assert "trust_state" not in dumped
        assert "quarantined" not in dumped  # regression guard from Task 2

    def test_exclusion_model_dump_json_excludes_trust_state(self):
        """trust_state is stripped from model_dump_json (schema-level exclude)."""
        import json

        exc = Exclusion(
            id="fp-2026-04-14-001",
            created="2026-04-14T10:00:00Z",
            agent="sqli",
            finding=ExclusionFinding(
                file="src/a.py", line=10, code_pattern="*", cwe="CWE-89"
            ),
            reason="test",
            scope=ExclusionScope(type="file", path="src/a.py"),
            trust_state="warned",
        )
        data = json.loads(exc.model_dump_json())
        assert "trust_state" not in data
        assert "quarantined" not in data  # regression guard

    def test_exclusion_include_does_not_leak_trust_state(self):
        """Even with include={'trust_state'}, the runtime flag is stripped
        (the model_dump override forces exclude)."""
        exc = Exclusion(
            id="fp-2026-04-14-001",
            created="2026-04-14T10:00:00Z",
            agent="sqli",
            finding=ExclusionFinding(
                file="src/a.py", line=10, code_pattern="*", cwe="CWE-89"
            ),
            reason="test",
            scope=ExclusionScope(type="file", path="src/a.py"),
            trust_state="quarantined",
        )
        dumped = exc.model_dump(include={"trust_state", "id"})
        assert "trust_state" not in dumped
        assert "id" in dumped  # T11-N2 — other included fields still present


class TestFindingTriageExclusionFields:
    def test_triage_default_not_excluded(self):
        t = FindingTriage()
        assert t.excluded is False
        assert t.exclusion_ref is None

    def test_triage_excluded(self):
        t = FindingTriage(excluded=True, exclusion_ref="fp-2026-04-11-001")
        assert t.excluded is True
        assert t.exclusion_ref == "fp-2026-04-11-001"


def test_reviewer_key_roundtrip():
    key = ReviewerKey(
        name="Marco",
        email="marco@example.com",
        key="ssh-ed25519 AAAAC3Nz... marco@arch",
    )
    assert key.name == "Marco"
    assert key.email == "marco@example.com"
    assert key.key.startswith("ssh-ed25519 ")


def test_screw_config_defaults():
    config = ScrewConfig()
    assert config.version == 1
    assert config.exclusion_reviewers == []
    assert config.script_reviewers == []
    assert config.adaptive is False
    assert config.legacy_unsigned_exclusions == "reject"
    assert config.trusted_reviewers_file is None


def test_screw_config_with_reviewers():
    config = ScrewConfig(
        exclusion_reviewers=[
            ReviewerKey(name="Marco", email="marco@example.com", key="ssh-ed25519 X marco@arch"),
        ],
        script_reviewers=[
            ReviewerKey(name="Marco", email="marco@example.com", key="ssh-ed25519 X marco@arch"),
        ],
        adaptive=True,
    )
    assert len(config.exclusion_reviewers) == 1
    assert config.adaptive is True


def test_screw_config_rejects_invalid_legacy_policy():
    with pytest.raises(ValidationError):
        ScrewConfig(legacy_unsigned_exclusions="nonsense")


def test_pattern_suggestion_model():
    sugg = PatternSuggestion(
        pattern="db.text_search(*)",
        agent="sqli",
        cwe="CWE-89",
        evidence={"exclusion_count": 12, "files_affected": ["a.py", "b.py"]},
        suggestion="Consider adding to project-wide safe patterns.",
        confidence="high",
    )
    assert sugg.pattern == "db.text_search(*)"
    assert sugg.confidence == "high"


def test_directory_suggestion_model():
    sugg = DirectorySuggestion(
        directory="test/",
        agent="sqli",
        evidence={"total_findings": 12, "all_fp": True},
        suggestion="Add test/** directory exclusion.",
        confidence="high",
    )
    assert sugg.directory == "test/"


def test_fp_pattern_and_fp_report():
    pattern = FPPattern(
        agent="sqli",
        cwe="CWE-89",
        pattern="execute\\(f\"",
        fp_count=47,
        example_reasons=["static query", "test fixture"],
        candidate_heuristic_refinement="lower confidence on bounded f-strings",
    )
    report = FPReport(
        generated_at="2026-04-14T10:00:00Z",
        scope="project",
        top_fp_patterns=[pattern],
    )
    assert report.top_fp_patterns[0].fp_count == 47


def test_aggregate_report_model():
    report = AggregateReport(
        pattern_confidence=[],
        directory_suggestions=[],
        fp_report=FPReport(generated_at="2026-04-14T10:00:00Z", scope="project", top_fp_patterns=[]),
    )
    assert report.pattern_confidence == []


def test_pattern_suggestion_rejects_invalid_confidence():
    """`confidence` accepts only low/medium/high — other values raise ValidationError."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        PatternSuggestion(
            pattern="x",
            agent="sqli",
            cwe="CWE-89",
            evidence={},
            suggestion="y",
            confidence="critical",  # not a valid Literal value
        )


def test_fp_report_rejects_invalid_scope():
    """`scope` accepts only project/global."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        FPReport(generated_at="2026-04-14T10:00:00Z", scope="team", top_fp_patterns=[])


def test_finding_analysis_impact_default_is_none():
    """FindingAnalysis.impact defaults to None (not empty string)."""
    fa = FindingAnalysis(description="test")
    assert fa.impact is None


def test_finding_analysis_impact_accepts_explicit_string():
    """FindingAnalysis.impact accepts an explicit string value."""
    fa = FindingAnalysis(description="test", impact="Data exfiltration")
    assert fa.impact == "Data exfiltration"


def test_aggregate_report_round_trip_model_dump_validate():
    """model_dump -> model_validate round-trips losslessly for MCP JSON serialization."""
    original = AggregateReport(
        pattern_confidence=[
            PatternSuggestion(
                pattern="p",
                agent="sqli",
                cwe="CWE-89",
                evidence={"exclusion_count": 3, "files_affected": ["a.py"]},
                suggestion="s",
                confidence="low",
            )
        ],
        directory_suggestions=[],
        fp_report=FPReport(generated_at="2026-04-14T10:00:00Z", scope="project", top_fp_patterns=[]),
    )
    roundtrip = AggregateReport.model_validate(original.model_dump())
    assert roundtrip == original


def test_agent_meta_short_description_populated():
    from screw_agents.models import OWASPMapping

    meta = AgentMeta(
        name="sqli",
        display_name="SQL Injection",
        domain="injection-input-handling",
        version="1.0.0",
        last_updated="2026-04-16",
        cwes=CWEs(primary="CWE-89", related=[]),
        owasp=OWASPMapping(top10="A03:2025"),
        short_description="Detects SQL injection vulnerabilities via tainted query construction.",
    )
    assert meta.short_description == "Detects SQL injection vulnerabilities via tainted query construction."


def test_agent_meta_short_description_defaults_to_none():
    from screw_agents.models import OWASPMapping

    meta = AgentMeta(
        name="sqli",
        display_name="SQL Injection",
        domain="injection-input-handling",
        version="1.0.0",
        last_updated="2026-04-16",
        cwes=CWEs(primary="CWE-89", related=[]),
        owasp=OWASPMapping(top10="A03:2025"),
    )
    assert meta.short_description is None

