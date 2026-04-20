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
from collections.abc import Callable
from pathlib import Path
from typing import Any


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

    project_root = args.project_root.resolve()

    if args.command == "init-trust":
        from screw_agents.cli.init_trust import run_init_trust

        # run_init_trust raises ValueError/RuntimeError on all failure modes
        # and returns only successful statuses (created, already_registered).
        # No failure_statuses membership check needed — exceptions ARE the
        # failure path.
        return _run_trust_command(
            "init-trust",
            run_init_trust,
            failure_statuses=(),
            project_root=project_root,
            name=args.name,
            email=args.email,
        )

    if args.command == "migrate-exclusions":
        from screw_agents.cli.migrate_exclusions import run_migrate_exclusions

        # Status space: success / no_exclusions / error. no_exclusions is a
        # graceful no-op.
        return _run_trust_command(
            "migrate-exclusions",
            run_migrate_exclusions,
            failure_statuses=("error",),
            project_root=project_root,
            skip_confirm=args.yes,
        )

    if args.command == "validate-exclusion":
        from screw_agents.cli.validate_exclusion import run_validate_exclusion

        # Status space: validated / already_validated / not_found / error.
        # not_found is user input error (wrong ID) — scriptable CI should
        # detect via exit 1.
        return _run_trust_command(
            "validate-exclusion",
            run_validate_exclusion,
            failure_statuses=("error", "not_found"),
            project_root=project_root,
            exclusion_id=args.exclusion_id,
        )

    if args.command == "validate-script":
        from screw_agents.cli.validate_script import run_validate_script

        # Status space parallels validate-exclusion.
        return _run_trust_command(
            "validate-script",
            run_validate_script,
            failure_statuses=("error", "not_found"),
            project_root=project_root,
            script_name=args.script_name,
        )

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


def _run_trust_command(
    command_label: str,
    runner: Callable[..., dict[str, Any]],
    *,
    failure_statuses: tuple[str, ...] = ("error",),
    **kwargs: Any,
) -> int:
    """Run a trust-path CLI command with friendly error surfacing.

    All four trust-path commands (init-trust, migrate-exclusions,
    validate-exclusion, validate-script) raise ``ValueError`` or
    ``RuntimeError`` for actionable misconfigurations (bad permissions,
    malformed config, missing .screw directory). Without wrapping, users
    see a raw traceback. This helper prints a one-line message to stderr
    with the command label so the failure looks like::

        screw-agents validate-script: permission denied at ...

    Then returns exit code 1.

    On success, prints ``result["message"]`` to stdout and returns 0 iff
    ``result["status"]`` is NOT in ``failure_statuses``. init-trust passes
    an empty tuple here because ``run_init_trust`` raises on every failure
    path already; the other three commands have statuses like
    ``"not_found"`` or ``"error"`` that encode user-facing failure without
    raising.

    Args:
        command_label: Human-visible command name (e.g., ``"validate-script"``)
            used in stderr output.
        runner: The underlying ``run_*`` function to invoke.
        failure_statuses: Statuses that count as failure → exit 1.
        **kwargs: Forwarded to ``runner``.

    Returns:
        Process exit code: 0 on success, 1 on failure.
    """
    try:
        result = runner(**kwargs)
    except (ValueError, RuntimeError) as exc:
        print(f"screw-agents {command_label}: {exc}", file=sys.stderr)
        return 1
    print(result["message"])
    return 1 if result["status"] in failure_statuses else 0


if __name__ == "__main__":
    sys.exit(main())
