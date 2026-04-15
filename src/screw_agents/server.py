"""MCP server skeleton with stdio transport.

Wires the AgentRegistry and ScanEngine into the MCP protocol using
the low-level Server API.  Exposes scan tools via list_tools/call_tool
handlers.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import Server, NotificationOptions
from mcp.server.models import InitializationOptions

from screw_agents.engine import ScanEngine
from screw_agents.learning import load_exclusions, record_exclusion
from screw_agents.models import ExclusionInput, Finding
from screw_agents.results import write_scan_results
from screw_agents.registry import AgentRegistry

logger = logging.getLogger(__name__)

_DEFAULT_DOMAINS_DIR = Path(__file__).resolve().parent.parent.parent / "domains"


def create_server(domains_dir: Path | None = None) -> tuple[Server, ScanEngine]:
    """Create and configure the MCP server with tool handlers.

    Args:
        domains_dir: Path to the domains directory containing agent YAML
            definitions.  Falls back to the repo-root ``domains/`` directory.

    Returns:
        A tuple of ``(Server, ScanEngine)``.
    """
    if domains_dir is None:
        domains_dir = _DEFAULT_DOMAINS_DIR

    registry = AgentRegistry(domains_dir)
    engine = ScanEngine(registry)
    server = Server("screw-agents")

    @server.list_tools()
    async def handle_list_tools() -> list[types.Tool]:
        tool_defs = engine.list_tool_definitions()
        return [
            types.Tool(
                name=td["name"],
                description=td.get("description"),
                inputSchema=td.get("input_schema", {"type": "object"}),
            )
            for td in tool_defs
        ]

    @server.call_tool()
    async def handle_call_tool(
        name: str, arguments: dict | None
    ) -> list[types.TextContent]:
        result = _dispatch_tool(engine, name, arguments or {})
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    return server, engine


# ------------------------------------------------------------------
# Tool dispatch
# ------------------------------------------------------------------


def _dispatch_tool(
    engine: ScanEngine, name: str, args: dict[str, Any]
) -> Any:
    """Synchronous dispatcher — routes MCP tool calls to engine methods.

    Args:
        engine: The ScanEngine instance.
        name: Tool name (e.g. ``"list_domains"``, ``"scan_sqli"``).
        args: Tool arguments dict.

    Returns:
        A JSON-serialisable result.

    Raises:
        ValueError: If the tool name is unknown.
    """
    if name == "list_domains":
        return engine.list_domains()

    if name == "list_agents":
        return engine.list_agents(domain=args.get("domain"))

    # --- Phase 2: new tools ---

    if name == "format_output":
        findings_raw = args.get("findings", [])
        output_format = args.get("format", "json")
        scan_metadata = args.get("scan_metadata")
        findings = [Finding(**f) for f in findings_raw]
        formatted = engine.format_output(findings, output_format, scan_metadata)
        return {"formatted": formatted}

    if name == "record_exclusion":
        project_root = Path(args["project_root"])
        exc_data = args["exclusion"]
        exc_input = ExclusionInput(**exc_data)
        saved = record_exclusion(project_root, exc_input)
        return {"exclusion": saved.model_dump()}

    if name == "check_exclusions":
        project_root = Path(args["project_root"])
        agent_filter = args.get("agent")
        all_exc = load_exclusions(project_root)
        if agent_filter:
            all_exc = [e for e in all_exc if e.agent == agent_filter]
        return {"exclusions": [e.model_dump() for e in all_exc]}

    # --- Phase 3a: trust tools ---

    if name == "verify_trust":
        project_root = Path(args["project_root"])
        return engine.verify_trust(project_root=project_root)

    if name == "write_scan_results":
        return write_scan_results(
            project_root=Path(args["project_root"]),
            findings_raw=args.get("findings", []),
            agent_names=args.get("agent_names", []),
            scan_metadata=args.get("scan_metadata"),
        )

    # --- Scan tools (Phase 1 + Phase 2 project_root) ---

    project_root = Path(args["project_root"]) if args.get("project_root") else None

    if name == "scan_domain":
        return engine.assemble_domain_scan(
            domain=args["domain"],
            target=args["target"],
            thoroughness=args.get("thoroughness", "standard"),
            project_root=project_root,
        )

    if name == "scan_full":
        return engine.assemble_full_scan(
            target=args["target"],
            thoroughness=args.get("thoroughness", "standard"),
            project_root=project_root,
        )

    # Per-agent scan tools: scan_{agent_name}
    if name.startswith("scan_"):
        agent_name = name[len("scan_"):]
        return engine.assemble_scan(
            agent_name=agent_name,
            target=args["target"],
            thoroughness=args.get("thoroughness", "standard"),
            project_root=project_root,
        )

    raise ValueError(f"Unknown tool: {name!r}")


# ------------------------------------------------------------------
# Transport: stdio
# ------------------------------------------------------------------


async def run_stdio(domains_dir: Path | None = None) -> None:
    """Run the MCP server over stdio transport.

    Args:
        domains_dir: Optional override for the domains directory.
    """
    from mcp.server.stdio import stdio_server

    server, _ = create_server(domains_dir)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="screw-agents",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


# ------------------------------------------------------------------
# Transport: Streamable HTTP
# ------------------------------------------------------------------


def create_http_app(
    domains_dir: Path | None = None, path: str = "/mcp"
) -> "Starlette":
    """Create a Starlette app serving the MCP server over Streamable HTTP.

    Args:
        domains_dir: Optional override for the domains directory.
        path: URL path for the MCP endpoint (default ``"/mcp"``).

    Returns:
        A :class:`starlette.applications.Starlette` application instance.
    """
    from starlette.applications import Starlette
    from starlette.routing import Route

    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

    server, _ = create_server(domains_dir)

    session_manager = StreamableHTTPSessionManager(
        app=server,
        stateless=True,
    )

    async def handle_mcp(scope, receive, send):  # type: ignore[no-untyped-def]
        await session_manager.handle_request(scope, receive, send)

    app = Starlette(
        routes=[Route(path, endpoint=handle_mcp)],
        lifespan=lambda _app: session_manager.run(),
    )
    return app


async def run_http(domains_dir: Path | None = None, port: int = 8080) -> None:
    """Run the MCP server over Streamable HTTP transport.

    Args:
        domains_dir: Optional override for the domains directory.
        port: TCP port to listen on (default ``8080``).
    """
    import uvicorn

    app = create_http_app(domains_dir)
    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info")
    uvi_server = uvicorn.Server(config)
    await uvi_server.serve()


# ------------------------------------------------------------------
# CLI entry point
# ------------------------------------------------------------------


def main() -> None:
    """CLI entry point for ``screw-agents``."""
    parser = argparse.ArgumentParser(
        prog="screw-agents",
        description="screw-agents MCP server — vulnerability-specific code review agents",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="Transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port for HTTP transport (default: 8080)",
    )
    parser.add_argument(
        "--domains-dir",
        type=Path,
        default=None,
        help="Path to domains directory (default: auto-detect from repo root)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.transport == "stdio":
        asyncio.run(run_stdio(args.domains_dir))
    elif args.transport == "http":
        asyncio.run(run_http(args.domains_dir, args.port))


if __name__ == "__main__":
    main()
