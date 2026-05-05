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
    assert manifest["skills"] == "./skills/"
    assert manifest["mcpServers"] == "./.mcp.json"
    assert manifest["interface"]["displayName"] == "screw-agents"
    assert "Provider-neutral" in manifest["description"]

    for command in ["scan.md", "learn-report.md", "adaptive-cleanup.md"]:
        assert (PLUGIN_ROOT / "commands" / command).is_file()


def test_codex_plugin_mcp_config_points_to_repo_local_server() -> None:
    config = json.loads((PLUGIN_ROOT / ".mcp.json").read_text(encoding="utf-8"))
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
