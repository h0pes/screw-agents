"""Tests for screw_agents.cli.validate_script — Phase 3b Task 13.

Covers:
- Happy path: unsigned script + meta -> signed with local key, sha256 recomputed.
- Idempotency: second call on unchanged script returns ``already_validated``.
- Re-sign on source edit: sha256 differs -> new signature is written.
- Missing script file -> ``not_found``.
- Empty ``script_reviewers`` -> ``error`` with init-trust hint.
- Local key does not match any registered reviewer (Model A correctness).
- Atomic write: ``PermissionError`` during write leaves no partial .tmp file
  AND leaves the original meta file untouched.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml


def _write_script_and_meta(
    script_dir: Path,
    *,
    name: str = "test",
    source: str | None = None,
    meta_extra: dict | None = None,
) -> tuple[Path, Path]:
    """Helper: write a minimal valid script and meta pair. Returns (script_path, meta_path)."""
    if source is None:
        source = (
            "from screw_agents.adaptive import emit_finding\n"
            "def analyze(project):\n"
            "    pass\n"
        )
    script_dir.mkdir(parents=True, exist_ok=True)
    script_path = script_dir / f"{name}.py"
    script_path.write_text(source, encoding="utf-8")

    meta: dict = {
        "name": name,
        "created": "2026-04-19T10:00:00Z",
        "created_by": "marco@example.com",
        "domain": "injection-input-handling",
        "description": f"{name} script",
        "target_patterns": [],
        "sha256": "will-be-recomputed",
    }
    if meta_extra:
        meta.update(meta_extra)
    meta_path = script_dir / f"{name}.meta.yaml"
    meta_path.write_text(yaml.dump(meta, sort_keys=False), encoding="utf-8")
    return script_path, meta_path


class TestValidateScript:
    """Phase 3b Task 13 — screw-agents validate-script <name>."""

    def test_validate_script_signs_existing_script(self, tmp_path: Path) -> None:
        """Happy path: unsigned script + meta -> the meta now carries
        ``signed_by``, a base64 signature, ``signature_version=1``,
        ``validated=True``, and a recomputed ``sha256``."""
        from screw_agents.cli.init_trust import run_init_trust
        from screw_agents.cli.validate_script import run_validate_script

        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )
        script_dir = tmp_path / ".screw" / "custom-scripts"
        _script_path, meta_path = _write_script_and_meta(script_dir)

        result = run_validate_script(project_root=tmp_path, script_name="test")
        assert result["status"] == "validated"
        assert "marco@example.com" in result["message"]

        meta = yaml.safe_load(meta_path.read_text(encoding="utf-8"))
        assert meta["signed_by"] == "marco@example.com"
        assert meta["signature"] is not None
        assert isinstance(meta["signature"], str)
        assert len(meta["signature"]) > 0
        assert meta["signature_version"] == 1
        assert meta["validated"] is True
        assert meta["sha256"] != "will-be-recomputed"
        # sha256 is 64 hex chars
        assert len(meta["sha256"]) == 64

    def test_validate_script_is_idempotent(self, tmp_path: Path) -> None:
        """Second call on an unchanged script returns ``already_validated``
        and leaves the signature bytes unchanged (no re-signing)."""
        from screw_agents.cli.init_trust import run_init_trust
        from screw_agents.cli.validate_script import run_validate_script

        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )
        script_dir = tmp_path / ".screw" / "custom-scripts"
        _script_path, meta_path = _write_script_and_meta(script_dir)

        first = run_validate_script(project_root=tmp_path, script_name="test")
        assert first["status"] == "validated"
        first_meta = yaml.safe_load(meta_path.read_text(encoding="utf-8"))
        original_sig = first_meta["signature"]
        original_sha = first_meta["sha256"]

        second = run_validate_script(project_root=tmp_path, script_name="test")
        assert second["status"] == "already_validated"
        assert "already signed" in second["message"].lower()

        reloaded = yaml.safe_load(meta_path.read_text(encoding="utf-8"))
        assert reloaded["signature"] == original_sig
        assert reloaded["sha256"] == original_sha

    def test_validate_script_re_signs_after_source_edit(
        self, tmp_path: Path
    ) -> None:
        """Editing the source between calls MUST trigger re-signing — new
        sha256 and a new signature both land in the meta."""
        from screw_agents.cli.init_trust import run_init_trust
        from screw_agents.cli.validate_script import run_validate_script

        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )
        script_dir = tmp_path / ".screw" / "custom-scripts"
        script_path, meta_path = _write_script_and_meta(script_dir)

        first = run_validate_script(project_root=tmp_path, script_name="test")
        assert first["status"] == "validated"
        first_meta = yaml.safe_load(meta_path.read_text(encoding="utf-8"))
        first_sig = first_meta["signature"]
        first_sha = first_meta["sha256"]

        # User edits the source after signing. This is exactly the scenario
        # `validate-script` exists to recover from.
        edited_source = (
            "from screw_agents.adaptive import emit_finding\n"
            "def analyze(project):\n"
            "    # edited comment — source changed since last signing\n"
            "    pass\n"
        )
        script_path.write_text(edited_source, encoding="utf-8")

        second = run_validate_script(project_root=tmp_path, script_name="test")
        assert second["status"] == "validated"

        second_meta = yaml.safe_load(meta_path.read_text(encoding="utf-8"))
        assert second_meta["sha256"] != first_sha, "sha256 must change"
        assert second_meta["signature"] != first_sig, (
            "signature must change when source changes"
        )
        assert second_meta["signed_by"] == "marco@example.com"
        assert second_meta["signature_version"] == 1
        assert second_meta["validated"] is True

    def test_validate_script_not_found(self, tmp_path: Path) -> None:
        """Missing script file returns ``not_found``."""
        from screw_agents.cli.init_trust import run_init_trust
        from screw_agents.cli.validate_script import run_validate_script

        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )
        # Deliberately don't write any script/meta.

        result = run_validate_script(
            project_root=tmp_path, script_name="does-not-exist"
        )
        assert result["status"] == "not_found"
        assert "does-not-exist" in result["message"]

    def test_validate_script_not_found_missing_meta_only(
        self, tmp_path: Path
    ) -> None:
        """Script file exists but meta is missing: still ``not_found``
        (the command needs both files to do its work)."""
        from screw_agents.cli.init_trust import run_init_trust
        from screw_agents.cli.validate_script import run_validate_script

        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )
        script_dir = tmp_path / ".screw" / "custom-scripts"
        script_dir.mkdir(parents=True, exist_ok=True)
        (script_dir / "orphan.py").write_text(
            "def analyze(project): pass\n", encoding="utf-8"
        )
        # No orphan.meta.yaml

        result = run_validate_script(
            project_root=tmp_path, script_name="orphan"
        )
        assert result["status"] == "not_found"
        assert "meta" in result["message"].lower()

    def test_validate_script_no_reviewers_configured(
        self, tmp_path: Path
    ) -> None:
        """No script_reviewers in config -> ``error`` with init-trust hint."""
        from screw_agents.cli.validate_script import run_validate_script

        # Do NOT run init-trust, so script_reviewers remains empty.
        script_dir = tmp_path / ".screw" / "custom-scripts"
        _write_script_and_meta(script_dir)

        result = run_validate_script(project_root=tmp_path, script_name="test")
        assert result["status"] == "error"
        assert "init-trust" in result["message"]
        assert "script_reviewers" in result["message"]

    def test_validate_script_local_key_not_in_script_reviewers(
        self, tmp_path: Path
    ) -> None:
        """Model A correctness test: config has a script_reviewers entry
        but none of the registered keys match the LOCAL signing key's
        fingerprint. Must return ``error`` pointing the user at init-trust.

        Scenario: the project has a legacy/teammate reviewer in
        script_reviewers, but THIS machine never ran init-trust, so the
        local key generated on first validate-script attempt has a
        fingerprint that doesn't match anyone. The plan's
        `script_reviewers[0].email` heuristic would silently attribute
        the signature to the wrong person; Model A catches this.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        from screw_agents.cli.validate_script import run_validate_script
        from screw_agents.trust import _public_key_to_openssh_line

        # Write a config with a reviewer that is NOT this machine's key.
        stranger_key = Ed25519PrivateKey.generate()
        stranger_pub_line = _public_key_to_openssh_line(
            stranger_key.public_key(), comment="stranger@example.com"
        )
        screw_dir = tmp_path / ".screw"
        screw_dir.mkdir(parents=True, exist_ok=True)
        (screw_dir / "config.yaml").write_text(
            yaml.dump(
                {
                    "version": 1,
                    "exclusion_reviewers": [],
                    "script_reviewers": [
                        {
                            "name": "Stranger",
                            "email": "stranger@example.com",
                            "key": stranger_pub_line,
                        }
                    ],
                    "adaptive": False,
                    "legacy_unsigned_exclusions": "reject",
                    "trusted_reviewers_file": None,
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )

        script_dir = screw_dir / "custom-scripts"
        _write_script_and_meta(script_dir)

        # Now run validate-script — it'll auto-generate a LOCAL key under
        # .screw/local/keys/ via _get_or_create_local_private_key, which
        # will NOT match `stranger@example.com`'s key.
        result = run_validate_script(project_root=tmp_path, script_name="test")
        assert result["status"] == "error"
        assert "does not match any registered reviewer" in result["message"]
        assert "init-trust" in result["message"]

    def test_validate_script_atomic_write_on_permission_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Simulate a PermissionError mid-write. The atomic write contract
        says: no partial `.tmp` file left behind AND the original meta file
        is untouched."""
        from screw_agents.cli import validate_script as validate_script_module
        from screw_agents.cli.init_trust import run_init_trust
        from screw_agents.cli.validate_script import run_validate_script

        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )
        script_dir = tmp_path / ".screw" / "custom-scripts"
        _script_path, meta_path = _write_script_and_meta(script_dir)

        # Capture the pristine meta bytes so we can assert the original is
        # untouched after the failed write.
        original_bytes = meta_path.read_bytes()

        # Monkeypatch os.replace inside the validate_script module so the
        # tmp file exists on disk at the moment we raise — giving us
        # something to assert gets cleaned up. Simulate the filesystem
        # rejecting the final rename.
        replace_calls: list[tuple[str, str]] = []

        def boom(src: str, dst: str) -> None:
            replace_calls.append((str(src), str(dst)))
            raise PermissionError("simulated EACCES during rename")

        monkeypatch.setattr(validate_script_module.os, "replace", boom)

        with pytest.raises(ValueError, match="permission denied"):
            run_validate_script(project_root=tmp_path, script_name="test")

        # The atomic write path MUST have gone through os.replace — guards
        # against a future switch to pathlib.Path.replace silently
        # weakening the test (we'd still clean up the tmp file but never
        # exercise the rename failure branch).
        assert len(replace_calls) == 1, (
            f"expected exactly one os.replace call; got {replace_calls}"
        )

        # The original meta file must be untouched.
        assert meta_path.read_bytes() == original_bytes

        # No stray .tmp file must be left behind.
        tmp_candidate = meta_path.parent / f"{meta_path.name}.tmp"
        assert not tmp_candidate.exists(), (
            f"atomic-write cleanup leaked {tmp_candidate}"
        )


class TestValidateScriptDispatcher:
    """Dispatcher-level smoke tests for `screw-agents validate-script`."""

    def test_dispatcher_returns_zero_on_validated(self, tmp_path: Path) -> None:
        from screw_agents.cli import main
        from screw_agents.cli.init_trust import run_init_trust

        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )
        script_dir = tmp_path / ".screw" / "custom-scripts"
        _write_script_and_meta(script_dir)

        exit_code = main(
            [
                "validate-script",
                "test",
                "--project-root",
                str(tmp_path),
            ]
        )
        assert exit_code == 0

    def test_dispatcher_returns_one_on_not_found(self, tmp_path: Path) -> None:
        from screw_agents.cli import main
        from screw_agents.cli.init_trust import run_init_trust

        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )
        # No script seeded.

        exit_code = main(
            [
                "validate-script",
                "missing",
                "--project-root",
                str(tmp_path),
            ]
        )
        assert exit_code == 1


class TestValidateScriptEndToEnd:
    """End-to-end signature round-trip tests.

    Locks in the invariant that a script signed by ``validate-script``
    verifies under the executor's Layer 3 without ``skip_trust_checks=True``.
    """

    def test_validate_script_output_passes_executor_signature_verification(
        self, tmp_path: Path
    ) -> None:
        """Regression for C1: a script signed by validate-script MUST verify
        under ``execute_script(skip_trust_checks=False)``.

        Guards against sign-side vs verify-side canonicalization drift. The
        executor parses persisted YAML via ``AdaptiveScriptMeta(**meta_raw)``
        which injects defaults (``last_used=None``, ``findings_produced=0``,
        ``false_positive_rate=None``) for omitted fields. If validate-script
        canonicalized the raw user dict (missing those fields), the verify-
        side canonical bytes would differ and every signed script would fail
        Layer 3 — a silent failure at the trust boundary.

        This test MUST NOT use ``skip_trust_checks=True``.
        """
        import shutil

        if (
            shutil.which("bwrap") is None
            and shutil.which("sandbox-exec") is None
        ):
            pytest.skip("no sandbox backend available")

        from screw_agents.adaptive.executor import execute_script
        from screw_agents.cli.init_trust import run_init_trust
        from screw_agents.cli.validate_script import run_validate_script
        from screw_agents.models import Finding

        # Seed the project: init-trust, then a minimal unsigned script+meta
        # containing ONLY the required schema fields (no last_used /
        # findings_produced / false_positive_rate) — this is the exact shape
        # a human would hand-write, and the shape the C1 bug fails on.
        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )
        script_dir = tmp_path / ".screw" / "custom-scripts"
        script_dir.mkdir(parents=True, exist_ok=True)

        source = (
            "from screw_agents.adaptive import emit_finding\n"
            "def analyze(project):\n"
            "    emit_finding(cwe='CWE-89', file='x.py', line=1,"
            " message='round-trip ok', severity='high')\n"
        )
        script_path = script_dir / "roundtrip.py"
        script_path.write_text(source, encoding="utf-8")

        meta_path = script_dir / "roundtrip.meta.yaml"
        meta_path.write_text(
            yaml.dump(
                {
                    "name": "roundtrip",
                    "created": "2026-04-19T10:00:00Z",
                    "created_by": "marco@example.com",
                    "domain": "injection-input-handling",
                    "description": "C1 regression",
                    "target_patterns": [],
                    "sha256": "placeholder-will-be-recomputed",
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )

        # Sign the script via the CLI command under test.
        validate_result = run_validate_script(
            project_root=tmp_path, script_name="roundtrip"
        )
        assert validate_result["status"] == "validated", (
            f"validate-script must succeed; got {validate_result!r}"
        )

        # Now the executor must accept the signed script end-to-end.
        # If C1 is not fixed, SignatureFailure is raised here.
        result = execute_script(
            script_path=script_path,
            meta_path=meta_path,
            project_root=tmp_path,
            skip_trust_checks=False,  # engage Layer 2 + Layer 3
            wall_clock_s=30,
        )

        assert result.stale is False
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert isinstance(finding, Finding)
        assert finding.classification.cwe == "CWE-89"
        assert finding.analysis.description == "round-trip ok"


class TestValidateScriptErrorBranches:
    """Coverage for the six error-wrap sites in run_validate_script.

    Each raise site must (a) raise the documented ValueError/RuntimeError
    with an actionable message, and (b) include the offending path + a
    remediation hint. These branches were previously untested.
    """

    def test_validate_script_malformed_meta_yaml_raises(
        self, tmp_path: Path
    ) -> None:
        """Covers validate_script.py's yaml.YAMLError wrap — the meta file
        contains invalid YAML syntax. The error must name the meta path and
        hint at manual fix."""
        from screw_agents.cli.init_trust import run_init_trust
        from screw_agents.cli.validate_script import run_validate_script

        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )
        script_dir = tmp_path / ".screw" / "custom-scripts"
        script_dir.mkdir(parents=True, exist_ok=True)
        script_path = script_dir / "broken.py"
        script_path.write_text("def analyze(project): pass\n", encoding="utf-8")
        meta_path = script_dir / "broken.meta.yaml"
        # Unclosed bracket → yaml.YAMLError on parse.
        meta_path.write_text(
            "name: broken\ntarget_patterns: [oops\n", encoding="utf-8"
        )

        with pytest.raises(ValueError) as excinfo:
            run_validate_script(project_root=tmp_path, script_name="broken")

        msg = str(excinfo.value)
        assert "Malformed script metadata YAML" in msg
        assert str(meta_path) in msg
        assert "manually" in msg, (
            "error should hint at manual YAML fix; got: " + msg
        )

    def test_validate_script_meta_not_a_mapping_raises(
        self, tmp_path: Path
    ) -> None:
        """Covers the `meta_raw` is not a mapping branch — a valid YAML
        top-level list or scalar. Error must name the actual type."""
        from screw_agents.cli.init_trust import run_init_trust
        from screw_agents.cli.validate_script import run_validate_script

        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )
        script_dir = tmp_path / ".screw" / "custom-scripts"
        script_dir.mkdir(parents=True, exist_ok=True)
        (script_dir / "listy.py").write_text(
            "def analyze(project): pass\n", encoding="utf-8"
        )
        # A YAML list is valid YAML but not a mapping.
        (script_dir / "listy.meta.yaml").write_text(
            "- name: listy\n- created: '2026-04-19T10:00:00Z'\n",
            encoding="utf-8",
        )

        with pytest.raises(ValueError) as excinfo:
            run_validate_script(project_root=tmp_path, script_name="listy")

        msg = str(excinfo.value)
        assert "must be a YAML mapping" in msg
        assert "list" in msg, (
            "error should name the offending type; got: " + msg
        )

    def test_validate_script_load_config_permission_error_is_wrapped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Covers the PermissionError wrap around `load_config`. The raw
        OSError must be re-raised as ValueError with an actionable message."""
        from screw_agents.cli import validate_script as validate_script_module
        from screw_agents.cli.init_trust import run_init_trust
        from screw_agents.cli.validate_script import run_validate_script

        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )
        script_dir = tmp_path / ".screw" / "custom-scripts"
        _write_script_and_meta(script_dir)

        def boom_load_config(_project_root):
            raise PermissionError("simulated EACCES on .screw/config.yaml")

        monkeypatch.setattr(
            validate_script_module, "load_config", boom_load_config
        )

        with pytest.raises(ValueError) as excinfo:
            run_validate_script(project_root=tmp_path, script_name="test")

        msg = str(excinfo.value)
        assert "permission denied" in msg
        assert "config.yaml" in msg
        assert "Check directory permissions" in msg, (
            "error should give a remediation hint; got: " + msg
        )

    def test_validate_script_key_gen_os_error_is_wrapped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Covers the OSError wrap around `_get_or_create_local_private_key`.
        Simulate disk-full / filesystem failure; must surface as RuntimeError
        with the project `.screw/local/keys` path + disk/filesystem hint."""
        from screw_agents.cli import validate_script as validate_script_module
        from screw_agents.cli.init_trust import run_init_trust
        from screw_agents.cli.validate_script import run_validate_script

        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )
        script_dir = tmp_path / ".screw" / "custom-scripts"
        _write_script_and_meta(script_dir)

        def boom_keygen(_project_root):
            raise OSError("simulated ENOSPC: no space left on device")

        monkeypatch.setattr(
            validate_script_module,
            "_get_or_create_local_private_key",
            boom_keygen,
        )

        with pytest.raises(RuntimeError) as excinfo:
            run_validate_script(project_root=tmp_path, script_name="test")

        msg = str(excinfo.value)
        assert "Failed to create local signing key" in msg
        assert ".screw" in msg and "keys" in msg
        assert "disk space" in msg or "filesystem" in msg, (
            "error should hint at disk/filesystem remediation; got: " + msg
        )
