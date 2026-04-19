"""screw-agents command-line interface.

Unified dispatcher for user-facing CLI commands. Subcommands:

- ``screw-agents serve`` — run the MCP server (stdio or HTTP transport)
- ``screw-agents init-trust`` — register the local SSH key as a trusted reviewer
- ``screw-agents migrate-exclusions`` — bulk-sign legacy unsigned exclusions
- ``screw-agents validate-exclusion <id>`` — sign a single quarantined exclusion
- ``screw-agents validate-script <name>`` — re-sign a quarantined adaptive
  script after manual review (Phase 3b Task 13)

The four trust-plane subcommands (init-trust, migrate-exclusions,
validate-exclusion, validate-script) share the same Ed25519 signing
plumbing via ``screw_agents.trust``. Each subcommand module is imported
on-demand inside ``main()`` to avoid import-time side effects and keep the
CLI startup lightweight.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argparse dispatcher for ``screw-agents``.

    Extracted for testability — unit tests parse args without invoking main().
    """
    parser = argparse.ArgumentParser(
        prog="screw-agents",
        description=(
            "screw-agents — vulnerability-specific code review with a shared "
            "MCP server backbone."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- serve ---
    serve_p = subparsers.add_parser(
        "serve",
        help="Run the screw-agents MCP server (stdio or HTTP transport)",
    )
    serve_p.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="Transport protocol (default: stdio)",
    )
    serve_p.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port for HTTP transport (default: 8080)",
    )
    serve_p.add_argument(
        "--domains-dir",
        type=Path,
        default=None,
        help="Path to domains directory (default: auto-detect from repo root)",
    )
    serve_p.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)",
    )

    # --- init-trust ---
    init_p = subparsers.add_parser(
        "init-trust",
        help="Register the local SSH key as a trusted reviewer",
    )
    init_p.add_argument("--name", required=True, help="Reviewer display name")
    init_p.add_argument("--email", required=True, help="Reviewer email address")
    init_p.add_argument(
        "--project-root",
        type=Path,
        default=Path("."),
        help="Project root directory (default: current working directory)",
    )

    # --- migrate-exclusions (Task 13 stub) ---
    migrate_p = subparsers.add_parser(
        "migrate-exclusions",
        help="Sign legacy unsigned exclusions with the local key (Task 13)",
    )
    migrate_p.add_argument(
        "--project-root",
        type=Path,
        default=Path("."),
        help="Project root directory (default: current working directory)",
    )
    migrate_p.add_argument(
        "--yes",
        action="store_true",
        help="Skip per-entry confirmation",
    )

    # --- validate-exclusion (Task 14 stub) ---
    validate_p = subparsers.add_parser(
        "validate-exclusion",
        help="Re-sign a quarantined exclusion after manual review (Task 14)",
    )
    validate_p.add_argument("exclusion_id", help="The exclusion ID to validate")
    validate_p.add_argument(
        "--project-root",
        type=Path,
        default=Path("."),
        help="Project root directory (default: current working directory)",
    )

    # --- validate-script (Phase 3b Task 13) ---
    validate_script_p = subparsers.add_parser(
        "validate-script",
        help="Re-sign a quarantined adaptive script after manual review",
    )
    validate_script_p.add_argument(
        "script_name",
        help="The adaptive script name without .py suffix (e.g. 'sqli_a')",
    )
    validate_script_p.add_argument(
        "--project-root",
        type=Path,
        default=Path("."),
        help="Project root directory (default: current working directory)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """screw-agents CLI entry point.

    Args:
        argv: Argument list (for testing). Defaults to sys.argv[1:].

    Returns:
        Process exit code: 0 for success, 1 for expected failures, 2 for
        argparse errors (handled internally by argparse).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "serve":
        return _run_serve(args)

    if args.command == "init-trust":
        return _run_init_trust_command(args)

    if args.command == "migrate-exclusions":
        from screw_agents.cli.migrate_exclusions import run_migrate_exclusions

        project_root = args.project_root.resolve()
        result = run_migrate_exclusions(
            project_root=project_root, skip_confirm=args.yes
        )
        print(result["message"])
        # T13-N1 fix: status space is success/no_exclusions/error.
        # no_exclusions is a graceful no-op (nothing to migrate), only
        # "error" is a genuine failure.
        return 1 if result["status"] == "error" else 0

    if args.command == "validate-exclusion":
        from screw_agents.cli.validate_exclusion import run_validate_exclusion

        project_root = args.project_root.resolve()
        result = run_validate_exclusion(
            project_root=project_root, exclusion_id=args.exclusion_id
        )
        print(result["message"])
        # T13-N1 fix: status space is validated/already_validated/
        # not_found/error. validated and already_validated are successful
        # outcomes. not_found is a user input error (wrong ID) that
        # scriptable CI should detect via exit 1.
        return 1 if result["status"] in ("error", "not_found") else 0

    if args.command == "validate-script":
        from screw_agents.cli.validate_script import run_validate_script

        project_root = args.project_root.resolve()
        result = run_validate_script(
            project_root=project_root, script_name=args.script_name
        )
        print(result["message"])
        # Status space parallels validate-exclusion: validated and
        # already_validated are successful outcomes; not_found (missing
        # script or meta) and error (misconfiguration) are failures for
        # scriptable CI.
        return 1 if result["status"] in ("error", "not_found") else 0

    return 0  # unreachable — argparse enforces required=True


def _run_serve(args: argparse.Namespace) -> int:
    """Run the screw-agents MCP server with the selected transport."""
    from screw_agents.server import run_http, run_stdio

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.transport == "stdio":
        asyncio.run(run_stdio(args.domains_dir))
    else:
        asyncio.run(run_http(args.domains_dir, args.port))
    return 0


def _run_init_trust_command(args: argparse.Namespace) -> int:
    """Handle the ``screw-agents init-trust`` subcommand.

    Wraps friendly error reporting around the underlying ``run_init_trust``
    implementation. Returns 0 on success (created or already_registered),
    1 on failure.
    """
    from screw_agents.cli.init_trust import run_init_trust

    project_root = args.project_root.resolve()
    try:
        result = run_init_trust(
            project_root=project_root, name=args.name, email=args.email
        )
    except (ValueError, RuntimeError) as exc:
        print(f"screw-agents init-trust: {exc}", file=sys.stderr)
        return 1

    print(result["message"])
    return 0 if result["status"] in ("created", "already_registered") else 1


if __name__ == "__main__":
    sys.exit(main())
