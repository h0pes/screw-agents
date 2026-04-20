"""Tests for ``ScanEngine.sign_adaptive_script`` — Phase 3b T18a.

Covers:
- Happy path: fresh script + meta → signed, files written, sha256 matches.
- Name collisions (.py exists, .meta.yaml exists) → ``status="error"``.
- Name validation — invalid regex inputs rejected at the entry point.
- Empty ``script_reviewers`` → ``status="error"`` pointing at init-trust.
- Local key not registered (Model A mismatch) → ``status="error"``.
- C1 REGRESSION (mandatory): signed output passes ``execute_script`` Layer 3
  verification. Locks `build_signed_script_meta` against canonical-bytes
  drift across its three consumers.
- Atomic write rollback: meta-write failure unlinks the just-written script
  to avoid the partial-state "script exists, meta missing" Layer 2 failure.
- Meta schema failure (missing required field) → ``status="error"``.
- Dispatcher smoke test: invoke via ``server._dispatch_tool``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml


def _minimal_meta(name: str = "test-script") -> dict[str, Any]:
    """Build a minimal valid partial-meta dict for sign_adaptive_script."""
    return {
        "name": name,
        "created": "2026-04-19T10:00:00Z",
        "created_by": "marco@example.com",
        "domain": "injection-input-handling",
        "description": "test adaptive script",
        "target_patterns": [],
    }


_MINIMAL_SOURCE = (
    "from screw_agents.adaptive import emit_finding\n"
    "def analyze(project):\n"
    "    pass\n"
)


class TestSignAdaptiveScript:
    """Phase 3b T18a: sign_adaptive_script approve-path MCP tool."""

    def test_sign_happy_path(self, tmp_path: Path) -> None:
        """Valid name + meta + source produces signed .py + .meta.yaml."""
        from screw_agents.cli.init_trust import run_init_trust
        from screw_agents.engine import ScanEngine

        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )

        engine = ScanEngine.from_defaults()
        result = engine.sign_adaptive_script(
            project_root=tmp_path,
            script_name="fresh-test",
            source=_MINIMAL_SOURCE,
            meta=_minimal_meta("fresh-test"),
            session_id="session-abc123",
        )

        assert result["status"] == "signed"
        assert result["signed_by"] == "marco@example.com"
        assert len(result["sha256"]) == 64
        assert result["session_id"] == "session-abc123"
        assert "fresh-test" in result["message"]

        # Files landed on disk.
        script_path = Path(result["script_path"])
        meta_path = Path(result["meta_path"])
        assert script_path.exists()
        assert meta_path.exists()
        assert script_path.read_text(encoding="utf-8") == _MINIMAL_SOURCE

        # Meta YAML has the complete signed state.
        meta = yaml.safe_load(meta_path.read_text(encoding="utf-8"))
        assert meta["signed_by"] == "marco@example.com"
        assert meta["signature"] is not None
        assert isinstance(meta["signature"], str)
        assert meta["signature_version"] == 1
        assert meta["validated"] is True
        assert meta["sha256"] == result["sha256"]

    def test_sign_rejects_collision_on_py(self, tmp_path: Path) -> None:
        """Existing .py at the target path returns status=error."""
        from screw_agents.cli.init_trust import run_init_trust
        from screw_agents.engine import ScanEngine

        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )
        script_dir = tmp_path / ".screw" / "custom-scripts"
        script_dir.mkdir(parents=True, exist_ok=True)
        (script_dir / "collide-py.py").write_text(
            "existing script\n", encoding="utf-8"
        )

        engine = ScanEngine.from_defaults()
        result = engine.sign_adaptive_script(
            project_root=tmp_path,
            script_name="collide-py",
            source=_MINIMAL_SOURCE,
            meta=_minimal_meta("collide-py"),
            session_id="s",
        )

        assert result["status"] == "error"
        assert "already exists" in result["message"]
        assert "validate-script" in result["message"]

    def test_sign_rejects_collision_on_meta(self, tmp_path: Path) -> None:
        """Existing .meta.yaml (without .py) still counts as a collision."""
        from screw_agents.cli.init_trust import run_init_trust
        from screw_agents.engine import ScanEngine

        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )
        script_dir = tmp_path / ".screw" / "custom-scripts"
        script_dir.mkdir(parents=True, exist_ok=True)
        (script_dir / "collide-meta.meta.yaml").write_text(
            "name: collide-meta\n", encoding="utf-8"
        )

        engine = ScanEngine.from_defaults()
        result = engine.sign_adaptive_script(
            project_root=tmp_path,
            script_name="collide-meta",
            source=_MINIMAL_SOURCE,
            meta=_minimal_meta("collide-meta"),
            session_id="s",
        )

        assert result["status"] == "error"
        assert "already exists" in result["message"]

    @pytest.mark.parametrize(
        "bad_name",
        [
            "UPPERCASE",  # uppercase rejected
            "-leading-dash",  # must start alphanumeric
            "ab",  # too short (< 3 chars)
            "a" * 64,  # too long (> 63 chars)
            "dots.allowed",  # dots not in regex
            "has space",  # spaces not in regex
            "has/slash",  # path traversal probe
            "",  # empty
        ],
    )
    def test_sign_rejects_invalid_names(
        self, tmp_path: Path, bad_name: str
    ) -> None:
        """Name regex catches uppercase, leading dash, size out-of-range,
        and path-unsafe characters before any filesystem touch."""
        from screw_agents.cli.init_trust import run_init_trust
        from screw_agents.engine import ScanEngine

        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )

        engine = ScanEngine.from_defaults()
        result = engine.sign_adaptive_script(
            project_root=tmp_path,
            script_name=bad_name,
            source=_MINIMAL_SOURCE,
            meta=_minimal_meta("valid-name"),
            session_id="s",
        )

        assert result["status"] == "error"
        assert "Invalid script name" in result["message"]

    def test_sign_rejects_no_reviewers_configured(
        self, tmp_path: Path
    ) -> None:
        """No script_reviewers in config → status=error with init-trust hint."""
        from screw_agents.engine import ScanEngine

        # DO NOT run init-trust — config file won't exist, script_reviewers
        # defaults to empty list via load_config's stub.
        engine = ScanEngine.from_defaults()
        result = engine.sign_adaptive_script(
            project_root=tmp_path,
            script_name="no-reviewers",
            source=_MINIMAL_SOURCE,
            meta=_minimal_meta("no-reviewers"),
            session_id="s",
        )

        assert result["status"] == "error"
        assert "script_reviewers" in result["message"]
        assert "init-trust" in result["message"]

    def test_sign_rejects_local_key_not_in_reviewers(
        self, tmp_path: Path
    ) -> None:
        """Model A: config has a stranger's public key but local key has a
        different fingerprint — must return error, not misattribute the
        signature to the stranger."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        from screw_agents.engine import ScanEngine
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

        engine = ScanEngine.from_defaults()
        result = engine.sign_adaptive_script(
            project_root=tmp_path,
            script_name="mismatch",
            source=_MINIMAL_SOURCE,
            meta=_minimal_meta("mismatch"),
            session_id="s",
        )

        assert result["status"] == "error"
        assert "does not match any registered reviewer" in result["message"]
        assert "init-trust" in result["message"]

    def test_sign_output_passes_executor_verification(
        self, tmp_path: Path
    ) -> None:
        """C1 REGRESSION (mandatory): a script signed via sign_adaptive_script
        MUST pass Layer 3 verification in execute_script.

        Locks the shared `build_signed_script_meta` helper against drift:
        sign-side canonicalization (approve-path) and verify-side
        canonicalization (executor) must produce byte-identical inputs.
        The T11-N1 regression test in test_adaptive_executor covers the
        validate-script CLI consumer; this test covers the MCP-tool
        consumer at the same boundary.
        """
        import shutil

        if (
            shutil.which("bwrap") is None
            and shutil.which("sandbox-exec") is None
        ):
            pytest.skip("no sandbox backend available on this platform")

        from screw_agents.adaptive.executor import execute_script
        from screw_agents.cli.init_trust import run_init_trust
        from screw_agents.engine import ScanEngine

        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )

        # Emit a single valid finding so the sandbox returns a non-empty
        # findings_json that the executor's JSON-schema check approves.
        analyze_source = (
            "from screw_agents.adaptive import emit_finding\n"
            "def analyze(project):\n"
            "    emit_finding(\n"
            "        cwe='CWE-89',\n"
            "        file='app.py',\n"
            "        line=1,\n"
            "        message='regression test finding',\n"
            "        severity='low',\n"
            "    )\n"
        )

        engine = ScanEngine.from_defaults()
        sign_result = engine.sign_adaptive_script(
            project_root=tmp_path,
            script_name="c1-regression",
            source=analyze_source,
            meta=_minimal_meta("c1-regression"),
            session_id="s",
        )
        assert sign_result["status"] == "signed", sign_result

        script_path = Path(sign_result["script_path"])
        meta_path = Path(sign_result["meta_path"])

        # Real end-to-end execute with skip_trust_checks=False. If the
        # canonical bytes drift, this call raises SignatureFailure.
        result = execute_script(
            script_path=script_path,
            meta_path=meta_path,
            project_root=tmp_path,
            wall_clock_s=15,
            skip_trust_checks=False,
        )
        # Executor returns an AdaptiveScriptResult; sandbox returncode 0
        # and >= 1 finding proves Layers 1-3 all passed.
        assert result.sandbox_result.returncode == 0, (
            f"sandbox failed: stderr={result.sandbox_result.stderr!r}"
        )
        assert len(result.findings) >= 1

    def test_sign_atomic_write_rollback_on_meta_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Monkeypatch os.replace to raise on the meta write. Contract:
        the just-written .py file must be rolled back (unlinked) so the
        filesystem is not left in the partial-state that Layer 2 would
        fail on."""
        from screw_agents.cli.init_trust import run_init_trust
        from screw_agents.engine import ScanEngine
        import screw_agents.engine as engine_module

        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )

        script_dir = tmp_path / ".screw" / "custom-scripts"
        # Intercept: allow the FIRST os.replace (script write) to succeed,
        # FAIL on the SECOND (meta write). Simulates disk-full / EACCES
        # striking precisely between the two atomic swaps.
        real_replace = engine_module.os.replace
        call_count = {"n": 0}

        def flaky_replace(src: Any, dst: Any) -> None:
            call_count["n"] += 1
            if call_count["n"] == 1:
                real_replace(src, dst)
                return
            raise PermissionError("simulated EACCES on meta rename")

        monkeypatch.setattr(engine_module.os, "replace", flaky_replace)

        engine = ScanEngine.from_defaults()
        with pytest.raises(ValueError) as excinfo:
            engine.sign_adaptive_script(
                project_root=tmp_path,
                script_name="rollback-test",
                source=_MINIMAL_SOURCE,
                meta=_minimal_meta("rollback-test"),
                session_id="s",
            )

        msg = str(excinfo.value)
        assert "rolled back" in msg
        # Rollback: .py file must NOT be present.
        assert not (script_dir / "rollback-test.py").exists()
        # Meta tmp should have been cleaned up too.
        assert not (script_dir / "rollback-test.meta.yaml.tmp").exists()
        assert not (script_dir / "rollback-test.meta.yaml").exists()

    def test_sign_rejects_meta_schema_failure(self, tmp_path: Path) -> None:
        """Missing required `name` in meta → status=error from
        build_signed_script_meta ValueError wrap."""
        from screw_agents.cli.init_trust import run_init_trust
        from screw_agents.engine import ScanEngine

        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )

        # Omit the required `name` field.
        bad_meta = {
            "created": "2026-04-19T10:00:00Z",
            "created_by": "marco@example.com",
            "domain": "injection-input-handling",
        }
        engine = ScanEngine.from_defaults()
        result = engine.sign_adaptive_script(
            project_root=tmp_path,
            script_name="schema-bad",
            source=_MINIMAL_SOURCE,
            meta=bad_meta,
            session_id="s",
        )

        assert result["status"] == "error"
        assert "AdaptiveScriptMeta schema" in result["message"]
        # Files must NOT have landed when schema check failed.
        script_dir = tmp_path / ".screw" / "custom-scripts"
        assert not (script_dir / "schema-bad.py").exists()
        assert not (script_dir / "schema-bad.meta.yaml").exists()

    def test_sign_source_write_failure_raises_friendly_value_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """I1 regression: non-PermissionError OSError during source-file
        write (e.g., IsADirectoryError if a directory races into the tmp
        path, ENOSPC on a full disk, EROFS on read-only mount) must
        produce a friendly ValueError with rollback, not a bare
        traceback.

        Same class of gap as T13 I1 residual — narrow catch tuples miss
        OSError siblings that aren't PermissionError subclasses. This
        test locks the broadened ``(PermissionError, OSError)`` catch
        so a future refactor can't silently narrow it back.
        """
        from screw_agents.cli.init_trust import run_init_trust
        from screw_agents.engine import ScanEngine

        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@test"
        )
        engine = ScanEngine.from_defaults()

        # Monkeypatch Path.write_text to raise IsADirectoryError on the
        # source write. IsADirectoryError is an OSError subclass but
        # NOT a PermissionError subclass — the pre-fix narrow catch
        # would have let this propagate bare.
        orig_write_text = Path.write_text
        source_writes_seen: list[str] = []

        def failing_write_text(self: Path, *args: Any, **kwargs: Any) -> int:
            if str(self).endswith(".py.tmp"):
                source_writes_seen.append(str(self))
                raise IsADirectoryError(
                    21, "Is a directory", str(self)
                )
            return orig_write_text(self, *args, **kwargs)

        monkeypatch.setattr(Path, "write_text", failing_write_text)

        with pytest.raises(ValueError, match="script source"):
            engine.sign_adaptive_script(
                project_root=tmp_path,
                script_name="smoke-i1",
                source=(
                    "from screw_agents.adaptive import emit_finding\n"
                    "def analyze(project):\n"
                    "    pass\n"
                ),
                meta={
                    "name": "smoke-i1",
                    "created": "2026-04-19T12:00:00Z",
                    "created_by": "marco@test",
                    "domain": "injection-input-handling",
                    "description": "smoke test",
                    "target_patterns": [],
                },
                session_id="test-session",
            )

        # Verify source .py file was NOT created on disk (rollback or
        # never-persisted).
        script_path = (
            tmp_path / ".screw" / "custom-scripts" / "smoke-i1.py"
        )
        assert not script_path.exists(), (
            "Failed source write must not leave the script file on disk"
        )
        # Sanity — verify the monkeypatch actually fired (test would
        # false-pass if the code path didn't reach script write).
        assert len(source_writes_seen) == 1, (
            "Expected exactly one source-write attempt; got "
            f"{source_writes_seen}"
        )

    def test_sign_via_dispatcher_smoke(self, tmp_path: Path) -> None:
        """End-to-end: invoke through server._dispatch_tool. Proves the
        tool registration + schema wiring is intact."""
        from screw_agents.cli.init_trust import run_init_trust
        from screw_agents.engine import ScanEngine
        from screw_agents.server import _dispatch_tool

        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )

        engine = ScanEngine.from_defaults()
        result = _dispatch_tool(
            engine,
            "sign_adaptive_script",
            {
                "project_root": str(tmp_path),
                "script_name": "dispatcher-smoke",
                "source": _MINIMAL_SOURCE,
                "meta": _minimal_meta("dispatcher-smoke"),
                "session_id": "s-dispatch",
            },
        )

        assert result["status"] == "signed"
        assert result["session_id"] == "s-dispatch"
        # Confirm the tool was registered in list_tool_definitions too.
        tool_names = {t["name"] for t in engine.list_tool_definitions()}
        assert "sign_adaptive_script" in tool_names
