"""Tests for screw_agents.cli.init_trust — the init-trust CLI subcommand."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from screw_agents.cli.init_trust import run_init_trust


class TestInitTrust:
    """Task 12 — screw-agents init-trust CLI subcommand."""

    def test_creates_config_with_local_key_on_first_run(self, tmp_path: Path):
        """First run: generates an Ed25519 key under .screw/local/keys/, writes
        the public key into both exclusion_reviewers and script_reviewers in
        .screw/config.yaml, returns status='created'."""
        result = run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )
        assert result["status"] == "created"
        assert "marco@example.com" in result["message"]

        config_path = tmp_path / ".screw" / "config.yaml"
        assert config_path.exists()
        config_data = yaml.safe_load(config_path.read_text())

        assert len(config_data["exclusion_reviewers"]) == 1
        assert config_data["exclusion_reviewers"][0]["email"] == "marco@example.com"
        assert config_data["exclusion_reviewers"][0]["name"] == "Marco"
        # OpenSSH format starts with "ssh-ed25519 "
        assert config_data["exclusion_reviewers"][0]["key"].startswith("ssh-ed25519 ")

        assert len(config_data["script_reviewers"]) == 1
        assert config_data["script_reviewers"][0]["email"] == "marco@example.com"

        # Local key file exists
        key_file = tmp_path / ".screw" / "local" / "keys" / "screw-local.ed25519"
        assert key_file.exists()

    def test_is_idempotent_on_second_run_with_same_email(self, tmp_path: Path):
        """Running init-trust twice with the same email returns
        'already_registered' on the second run and does not duplicate entries."""
        run_init_trust(project_root=tmp_path, name="Marco", email="marco@example.com")
        result = run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )
        assert result["status"] == "already_registered"
        assert "already registered" in result["message"].lower()

        config_data = yaml.safe_load(
            (tmp_path / ".screw" / "config.yaml").read_text()
        )
        assert len(config_data["exclusion_reviewers"]) == 1
        assert len(config_data["script_reviewers"]) == 1

    def test_different_email_appends_without_clobbering(self, tmp_path: Path):
        """Running init-trust with a different email appends to both lists
        (preserves existing reviewers in multi-reviewer workflows)."""
        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )
        result = run_init_trust(
            project_root=tmp_path, name="Alice", email="alice@example.com"
        )
        assert result["status"] == "created"

        config_data = yaml.safe_load(
            (tmp_path / ".screw" / "config.yaml").read_text()
        )
        assert len(config_data["exclusion_reviewers"]) == 2
        assert len(config_data["script_reviewers"]) == 2
        emails_excl = {r["email"] for r in config_data["exclusion_reviewers"]}
        emails_scr = {r["email"] for r in config_data["script_reviewers"]}
        assert emails_excl == {"marco@example.com", "alice@example.com"}
        assert emails_scr == {"marco@example.com", "alice@example.com"}

    def test_partial_registration_completes_missing_list(self, tmp_path: Path):
        """If an email is registered in only one list (manual edit scenario),
        init-trust adds it to the missing list without duplicating in the
        other."""
        # First, run normally to generate the key + config
        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )

        # Manually edit config to remove from script_reviewers only
        config_path = tmp_path / ".screw" / "config.yaml"
        data = yaml.safe_load(config_path.read_text())
        data["script_reviewers"] = []
        config_path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))

        # Re-run init-trust — it should add to script_reviewers but not
        # duplicate in exclusion_reviewers.
        result = run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )
        assert result["status"] == "created"

        reloaded = yaml.safe_load(config_path.read_text())
        assert len(reloaded["exclusion_reviewers"]) == 1
        assert len(reloaded["script_reviewers"]) == 1
        assert reloaded["exclusion_reviewers"][0]["email"] == "marco@example.com"
        assert reloaded["script_reviewers"][0]["email"] == "marco@example.com"

    def test_friendly_error_when_dot_screw_is_file(self, tmp_path: Path):
        """When .screw exists as a file (not directory), init-trust raises
        ValueError with an actionable message. T6-I1 friendly error wrapping."""
        (tmp_path / ".screw").write_text("i am not a directory")

        with pytest.raises(ValueError, match="not a directory"):
            run_init_trust(
                project_root=tmp_path, name="Marco", email="marco@example.com"
            )

    def test_generated_key_matches_reviewer_fingerprint(self, tmp_path: Path):
        """The written public key line matches the fingerprint of the local
        private key — end-to-end sanity check of the registration flow."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        from screw_agents.models import ScrewConfig
        from screw_agents.trust import (
            _fingerprint_public_key,
            _load_public_keys_with_reviewers,
        )

        run_init_trust(
            project_root=tmp_path, name="Marco", email="marco@example.com"
        )

        # Load the written config and extract the reviewer's public key
        config_data = yaml.safe_load(
            (tmp_path / ".screw" / "config.yaml").read_text()
        )
        config = ScrewConfig.model_validate(config_data)
        pairs, dropped = _load_public_keys_with_reviewers(config.exclusion_reviewers)
        assert not dropped
        assert len(pairs) == 1

        # Load the local private key and compare fingerprints
        key_path = tmp_path / ".screw" / "local" / "keys" / "screw-local.ed25519"
        priv_bytes = key_path.read_bytes()
        priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)
        local_pub_fp = _fingerprint_public_key(priv.public_key())

        reviewer_pub, reviewer_entry = pairs[0]
        reviewer_fp = _fingerprint_public_key(reviewer_pub)

        assert local_pub_fp == reviewer_fp, (
            "Reviewer public key in config does not match local private key "
            "fingerprint — init-trust registration is broken."
        )
        assert reviewer_entry.email == "marco@example.com"


class TestCLIDispatcher:
    """Task 12 — screw-agents CLI dispatcher (cli.__init__.main)."""

    def test_build_parser_recognizes_all_subcommands(self):
        """The argparse dispatcher recognizes serve, init-trust,
        migrate-exclusions, and validate-exclusion."""
        from screw_agents.cli import build_parser

        parser = build_parser()
        # Each subcommand should parse without error for its happy-path args
        assert parser.parse_args(["serve", "--transport", "stdio"]).command == "serve"
        assert (
            parser.parse_args(
                ["init-trust", "--name", "Marco", "--email", "marco@example.com"]
            ).command
            == "init-trust"
        )
        assert (
            parser.parse_args(["migrate-exclusions", "--yes"]).command
            == "migrate-exclusions"
        )
        assert (
            parser.parse_args(["validate-exclusion", "fp-2026-04-14-001"]).command
            == "validate-exclusion"
        )

    def test_serve_subcommand_requires_valid_transport(self):
        """serve --transport foo is rejected by argparse."""
        from screw_agents.cli import build_parser

        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["serve", "--transport", "foo"])

    def test_init_trust_via_cli_main_happy_path(self, tmp_path: Path, capsys):
        """Invoking main() with init-trust args routes to run_init_trust and
        returns exit code 0."""
        from screw_agents.cli import main

        exit_code = main([
            "init-trust",
            "--name", "Marco",
            "--email", "marco@example.com",
            "--project-root", str(tmp_path),
        ])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "marco@example.com" in captured.out
        assert (tmp_path / ".screw" / "config.yaml").exists()

    def test_init_trust_via_cli_main_friendly_error_exit_code_1(
        self, tmp_path: Path, capsys
    ):
        """When run_init_trust raises ValueError (e.g., .screw is a file),
        main() catches it and returns exit code 1 with the error on stderr."""
        from screw_agents.cli import main

        (tmp_path / ".screw").write_text("blocked")

        exit_code = main([
            "init-trust",
            "--name", "Marco",
            "--email", "marco@example.com",
            "--project-root", str(tmp_path),
        ])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "screw-agents init-trust:" in captured.err
        assert "not a directory" in captured.err
