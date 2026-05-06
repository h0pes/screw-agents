from __future__ import annotations

import json
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "screw"


def test_codex_plugin_manifest_exposes_shared_plugin_assets() -> None:
    manifest_path = PLUGIN_ROOT / ".codex-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest["name"] == "screw"
    assert manifest["version"] == "0.1.5"
    assert manifest["skills"] == "./codex-skills/"
    assert manifest["mcpServers"] == "./codex-mcp.json"
    assert manifest["interface"]["displayName"] == "screw-agents"
    assert "Provider-neutral" in manifest["description"]

    for command in ["scan.md", "learn-report.md", "adaptive-cleanup.md"]:
        assert (PLUGIN_ROOT / "commands" / command).is_file()


def test_claude_command_names_are_explicit_for_shared_commands() -> None:
    expected_names = {
        "scan.md": "screw:scan",
        "learn-report.md": "screw:learn-report",
        "adaptive-cleanup.md": "screw:adaptive-cleanup",
    }
    for command, expected_name in expected_names.items():
        command_text = (PLUGIN_ROOT / "commands" / command).read_text(encoding="utf-8")
        assert f"\nname: {expected_name}\n" in command_text


def test_codex_skills_cover_command_workflows() -> None:
    for skill in [
        "screw-scan",
        "screw-learn-report",
        "screw-adaptive-cleanup",
    ]:
        skill_path = PLUGIN_ROOT / "codex-skills" / skill / "SKILL.md"
        assert skill_path.is_file()
        skill_text = skill_path.read_text(encoding="utf-8")
        assert f"name: {skill}" in skill_text
        assert "screw-agents" in skill_text


def test_codex_plugin_mcp_config_points_to_repo_local_server() -> None:
    config = json.loads((PLUGIN_ROOT / "codex-mcp.json").read_text(encoding="utf-8"))
    server = config["mcpServers"]["screw-agents"]

    assert server["command"] == "uv"
    assert server["args"] == [
        "run",
        "--directory",
        "../..",
        "screw-agents",
        "serve",
        "--transport",
        "stdio",
    ]


def test_claude_plugin_exposes_only_claude_skills_without_command_duplicates() -> None:
    skill_names = {
        path.name
        for path in (PLUGIN_ROOT / "skills").iterdir()
        if path.is_dir()
    }

    assert skill_names == {"screw-review", "screw-research"}
    assert (PLUGIN_ROOT / "codex-skills").is_dir()
    for duplicate in (
        "screw-scan",
        "screw-learn-report",
        "screw-adaptive-cleanup",
    ):
        assert duplicate not in skill_names


def test_claude_plugin_does_not_auto_load_codex_mcp_config() -> None:
    assert not (PLUGIN_ROOT / ".mcp.json").exists()
    assert (PLUGIN_ROOT / "codex-mcp.json").is_file()


def test_codex_marketplace_entry_points_to_shared_screw_plugin() -> None:
    marketplace = json.loads(
        (REPO_ROOT / ".agents" / "plugins" / "marketplace.json").read_text(
            encoding="utf-8"
        )
    )

    [entry] = marketplace["plugins"]
    assert entry["name"] == "screw"
    assert entry["source"] == {"source": "local", "path": "./plugins/screw"}
    assert entry["policy"] == {
        "installation": "AVAILABLE",
        "authentication": "ON_INSTALL",
    }
    assert entry["category"] == "Engineering"


def test_codex_openai_interface_metadata_exists() -> None:
    metadata = yaml.safe_load(
        (PLUGIN_ROOT / "agents" / "openai.yaml").read_text(encoding="utf-8")
    )

    assert metadata["interface"]["display_name"] == "screw-agents"
    assert "secure code review" in metadata["interface"]["short_description"]
