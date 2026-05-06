"""Execution surfaces for provider-neutral primary scans."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from screw_agents.challenger.models import (
    ChallengerConfig,
    ChallengerReconciliation,
    ChallengerTransportConfig,
)
from screw_agents.engine import ScanEngine
from screw_agents.primary_scan.models import PrimaryScanParticipant, PrimaryScanResult
from screw_agents.primary_scan.providers import (
    ClaudeCliPrimaryScanRunner,
    CliPrimaryScanCommandRunner,
    CliPrimaryScanRunner,
    CodexCliPrimaryScanRunner,
    FixturePrimaryScanRunner,
)
from screw_agents.trust import load_config

_PARALLEL_LINE_MATCH_WINDOW = 20


def run_provider_scan(
    *,
    engine: ScanEngine,
    project_root: Path,
    provider: str,
    transport: str,
    execution: str,
    run_id: str,
    session_id: str,
    agents: list[str],
    target: dict[str, Any],
    thoroughness: str = "standard",
    timeout_seconds: int = 120,
    fixture_findings: list[dict[str, Any]] | None = None,
    command_runner: CliPrimaryScanCommandRunner | None = None,
    env: Mapping[str, str] | None = None,
) -> PrimaryScanResult:
    """Run one provider-neutral primary scan through an exposed execution path."""
    if execution not in {"fixture", "cli"}:
        raise ValueError("execution must be one of: 'fixture', 'cli'")

    config = load_config(project_root).challenger
    transport_config = _enabled_transport(config, provider, transport)
    if transport_config.kind != execution:
        raise ValueError(
            f"execution {execution!r} requires a {execution!r} transport; "
            f"{provider!r}/{transport!r} is {transport_config.kind!r}"
        )

    participant = PrimaryScanParticipant(provider=provider, transport=transport)
    scan_input = engine.assemble_primary_scan_input(
        run_id=run_id,
        session_id=session_id,
        participant=participant,
        agents=agents,
        target=target,
        thoroughness=thoroughness,
        project_root=project_root,
    )

    if execution == "fixture":
        runner = FixturePrimaryScanRunner(
            participant=participant,
            findings=fixture_findings,
            provider_metadata={
                provider: {
                    "transport": transport,
                    "execution": "fixture",
                }
            },
        )
        return runner.run(scan_input)

    _require_cli_consent(config, provider, transport, transport_config)
    runner = _cli_runner_for(
        participant=participant,
        transport=transport_config,
        command_runner=command_runner,
        timeout_seconds=timeout_seconds,
        env=env,
    )
    return runner.run(scan_input)


def run_provider_scan_workflow(
    *,
    engine: ScanEngine,
    project_root: Path,
    provider: str,
    transport: str,
    execution: str,
    run_id: str,
    session_id: str,
    agents: list[str],
    target: dict[str, Any],
    thoroughness: str = "standard",
    timeout_seconds: int = 120,
    fixture_findings: list[dict[str, Any]] | None = None,
    command_runner: CliPrimaryScanCommandRunner | None = None,
    env: Mapping[str, str] | None = None,
    finalize: bool = False,
    formats: list[str] | None = None,
) -> dict[str, Any]:
    """Run provider scan and optionally finalize findings into reports."""
    scan_result = run_provider_scan(
        engine=engine,
        project_root=project_root,
        provider=provider,
        transport=transport,
        execution=execution,
        run_id=run_id,
        session_id=session_id,
        agents=agents,
        target=target,
        thoroughness=thoroughness,
        timeout_seconds=timeout_seconds,
        fixture_findings=fixture_findings,
        command_runner=command_runner,
        env=env,
    )
    result = scan_result.model_dump(mode="json")
    if not finalize:
        return result

    findings = [finding.model_dump(mode="json") for finding in scan_result.findings]
    accumulate_result = engine.accumulate_findings(
        project_root=project_root,
        findings_chunk=findings,
        session_id=session_id,
    )
    finalize_result = engine.finalize_scan_results(
        project_root=project_root,
        session_id=accumulate_result["session_id"],
        agent_names=agents,
        scan_metadata=_provider_scan_metadata(
            target=target,
            provider=provider,
            transport=transport,
            execution=execution,
            run_id=run_id,
        ),
        formats=formats,
    )
    return {
        "primary_scan_result": result,
        "accumulate_result": accumulate_result,
        "finalize_result": finalize_result,
    }


def run_composed_provider_scan_workflow(
    *,
    engine: ScanEngine,
    project_root: Path,
    primary_provider: str,
    primary_transport: str,
    primary_execution: str,
    challenger_mode: str,
    challenger_execution: str,
    run_id: str,
    session_id: str,
    agents: list[str],
    target: dict[str, Any],
    thoroughness: str = "standard",
    primary_timeout_seconds: int = 120,
    challenger_timeout_seconds: int = 120,
    fixture_findings: list[dict[str, Any]] | None = None,
    primary_command_runner: CliPrimaryScanCommandRunner | None = None,
    env: Mapping[str, str] | None = None,
    formats: list[str] | None = None,
    challenger_prompt: str | None = None,
) -> dict[str, Any]:
    """Run provider-neutral primary scanning and configured challenger review.

    This is the backend composition for Phase 5 primary/challenger modes:
    one configured provider acts as first-pass scanner from YAML agent
    knowledge, the findings are accumulated/finalized through the normal
    reporting path, and finalization attaches a configured challenger mode.
    """
    scan_result = run_provider_scan(
        engine=engine,
        project_root=project_root,
        provider=primary_provider,
        transport=primary_transport,
        execution=primary_execution,
        run_id=run_id,
        session_id=session_id,
        agents=agents,
        target=target,
        thoroughness=thoroughness,
        timeout_seconds=primary_timeout_seconds,
        fixture_findings=fixture_findings,
        command_runner=primary_command_runner,
        env=env,
    )
    findings = [finding.model_dump(mode="json") for finding in scan_result.findings]
    challenger_provider = _challenger_provider(
        project_root=project_root,
        mode_name=challenger_mode,
    )
    accumulate_result = engine.accumulate_findings(
        project_root=project_root,
        findings_chunk=findings,
        session_id=session_id,
    )
    finalize_result = engine.finalize_scan_results(
        project_root=project_root,
        session_id=accumulate_result["session_id"],
        agent_names=agents,
        scan_metadata=_composed_scan_metadata(
            target=target,
            primary_provider=primary_provider,
            primary_transport=primary_transport,
            primary_execution=primary_execution,
            challenger_provider=challenger_provider,
            challenger_mode=challenger_mode,
            challenger_execution=challenger_execution,
            run_id=run_id,
        ),
        formats=formats,
        challenger_mode=challenger_mode,
        challenger_execution=challenger_execution,
        challenger_prompt=challenger_prompt,
        challenger_target=target,
        challenger_timeout_seconds=challenger_timeout_seconds,
    )
    return {
        "mode": {
            "type": "primary_challenger",
            "primary": {
                "provider": primary_provider,
                "transport": primary_transport,
                "execution": primary_execution,
            },
            "challenger": {
                "mode": challenger_mode,
                "execution": challenger_execution,
            },
        },
        "primary_scan_result": scan_result.model_dump(mode="json"),
        "accumulate_result": accumulate_result,
        "finalize_result": finalize_result,
        "challenger_results": _challenger_results_from_finalize_result(
            finalize_result
        ),
    }


def run_parallel_provider_scan_workflow(
    *,
    engine: ScanEngine,
    project_root: Path,
    participants: list[dict[str, str]],
    run_id: str,
    session_id: str,
    agents: list[str],
    target: dict[str, Any],
    thoroughness: str = "standard",
    timeout_seconds: int = 120,
    fixture_findings_by_provider: Mapping[str, list[dict[str, Any]]] | None = None,
    command_runners_by_provider: Mapping[str, CliPrimaryScanCommandRunner] | None = None,
    env: Mapping[str, str] | None = None,
    finalize: bool = False,
    formats: list[str] | None = None,
) -> dict[str, Any]:
    """Run independent provider primary scans and reconcile their findings."""
    if len(participants) < 2:
        raise ValueError("parallel provider scans require at least two participants")

    scan_results: list[PrimaryScanResult] = []
    for participant in participants:
        provider = _participant_field(participant, "provider")
        transport = _participant_field(participant, "transport")
        execution = _participant_field(participant, "execution")
        scan_results.append(
            run_provider_scan(
                engine=engine,
                project_root=project_root,
                provider=provider,
                transport=transport,
                execution=execution,
                run_id=f"{run_id}-{provider}",
                session_id=f"{session_id}-{provider}",
                agents=agents,
                target=target,
                thoroughness=thoroughness,
                timeout_seconds=timeout_seconds,
                fixture_findings=(fixture_findings_by_provider or {}).get(provider),
                command_runner=(command_runners_by_provider or {}).get(provider),
                env=env,
            )
        )

    provider_findings = {
        result.provider: [
            finding.model_dump(mode="json") for finding in result.findings
        ]
        for result in scan_results
    }
    reconciliations = [
        reconciliation.model_dump(mode="json")
        for reconciliation in _reconcile_parallel_findings(provider_findings)
    ]
    result: dict[str, Any] = {
        "mode": {
            "type": "parallel",
            "participants": [
                {
                    "provider": result.provider,
                    "transport": result.transport,
                    "execution": result.transport_kind,
                }
                for result in scan_results
            ],
        },
        "primary_scan_results": [
            result.model_dump(mode="json") for result in scan_results
        ],
        "provider_findings": provider_findings,
        "findings": [
            finding
            for findings in provider_findings.values()
            for finding in findings
        ],
        "reconciliations": reconciliations,
    }
    if not finalize:
        return result

    accumulate_result = engine.accumulate_findings(
        project_root=project_root,
        findings_chunk=result["findings"],
        session_id=session_id,
    )
    finalize_result = engine.finalize_scan_results(
        project_root=project_root,
        session_id=accumulate_result["session_id"],
        agent_names=agents,
        scan_metadata=_parallel_scan_metadata(
            target=target,
            participants=participants,
            run_id=run_id,
            reconciliations=reconciliations,
        ),
        formats=formats,
    )
    result["accumulate_result"] = accumulate_result
    result["finalize_result"] = finalize_result
    return result


def _enabled_transport(
    config: ChallengerConfig,
    provider: str,
    transport: str,
) -> ChallengerTransportConfig:
    if provider not in config.providers:
        raise ValueError(f"unknown provider {provider!r}")
    return config.providers[provider].enabled_transport(transport)


def _require_cli_consent(
    config: ChallengerConfig,
    provider: str,
    transport: str,
    transport_config: ChallengerTransportConfig,
) -> None:
    consent = config.consent
    if transport_config.sends_source_externally:
        if not consent.privacy_acknowledged:
            raise ValueError("CLI provider execution requires privacy_acknowledged=true")
        if not consent.source_sharing_allowed:
            raise ValueError(
                "CLI provider execution requires source_sharing_allowed=true"
            )
    if transport_config.may_bill_api_credits():
        if not consent.cost_acknowledged:
            raise ValueError("API-billing transports require cost_acknowledged=true")
        if not consent.api_billing_allowed:
            raise ValueError("API-billing transports require api_billing_allowed=true")
    if transport_config.kind != "cli":
        raise ValueError(
            "provider primary scan live execution only supports cli transports; "
            f"{provider!r}/{transport!r} uses {transport_config.kind!r}. "
            "Fixture, API, and local execution are separate surfaces."
        )


def _cli_runner_for(
    *,
    participant: PrimaryScanParticipant,
    transport: ChallengerTransportConfig,
    command_runner: CliPrimaryScanCommandRunner | None,
    timeout_seconds: int,
    env: Mapping[str, str] | None,
) -> CliPrimaryScanRunner:
    if participant.provider == "claude":
        return ClaudeCliPrimaryScanRunner(
            participant=participant,
            transport=transport,
            command_runner=command_runner,
            timeout_seconds=timeout_seconds,
            env=env,
        )
    if participant.provider == "codex":
        return CodexCliPrimaryScanRunner(
            participant=participant,
            transport=transport,
            command_runner=command_runner,
            timeout_seconds=timeout_seconds,
            env=env,
        )
    return CliPrimaryScanRunner(
        participant=participant,
        transport=transport,
        command_runner=command_runner,
        timeout_seconds=timeout_seconds,
        env=env,
    )


def _challenger_results_from_finalize_result(
    finalize_result: dict[str, Any],
) -> list[dict[str, Any]]:
    json_path = finalize_result.get("files_written", {}).get("json")
    if not json_path:
        return []
    try:
        payload = json.loads(Path(json_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(payload, dict):
        return []
    challenger_results = payload.get("challenger_results", [])
    if isinstance(challenger_results, list):
        return [
            item for item in challenger_results
            if isinstance(item, dict)
        ]
    return []


def _participant_field(participant: dict[str, str], field_name: str) -> str:
    value = participant.get(field_name)
    if not value:
        raise ValueError(f"parallel participant requires {field_name!r}")
    return value


def _provider_scan_metadata(
    *,
    target: dict[str, Any],
    provider: str,
    transport: str,
    execution: str,
    run_id: str,
) -> dict[str, Any]:
    return {
        "target": target,
        "report": {
            "label": f"{provider}-primary",
            "mode": "provider_primary",
            "providers": [provider],
        },
        "provider_scan": {
            "provider": provider,
            "transport": transport,
            "execution": execution,
            "run_id": run_id,
        },
    }


def _composed_scan_metadata(
    *,
    target: dict[str, Any],
    primary_provider: str,
    primary_transport: str,
    primary_execution: str,
    challenger_provider: str | None,
    challenger_mode: str,
    challenger_execution: str,
    run_id: str,
) -> dict[str, Any]:
    label_parts = [primary_provider, "primary"]
    providers = [primary_provider]
    if challenger_provider:
        label_parts.extend([challenger_provider, "challenger"])
        providers.append(challenger_provider)
    else:
        label_parts.append(challenger_mode)
    return {
        "target": target,
        "report": {
            "label": "-".join(label_parts),
            "mode": "primary_challenger",
            "providers": providers,
        },
        "provider_scan": {
            "provider": primary_provider,
            "transport": primary_transport,
            "execution": primary_execution,
            "run_id": run_id,
        },
        "phase5_mode": {
            "type": "primary_challenger",
            "primary_provider": primary_provider,
            "challenger_provider": challenger_provider,
            "challenger_mode": challenger_mode,
            "challenger_execution": challenger_execution,
        },
    }


def _parallel_scan_metadata(
    *,
    target: dict[str, Any],
    participants: list[dict[str, str]],
    run_id: str,
    reconciliations: list[dict[str, Any]],
) -> dict[str, Any]:
    providers = [_participant_field(participant, "provider") for participant in participants]
    return {
        "target": target,
        "report": {
            "label": "parallel-" + "-".join(providers),
            "mode": "parallel",
            "providers": providers,
        },
        "phase5_mode": {
            "type": "parallel",
            "participants": participants,
            "run_id": run_id,
        },
        "parallel_reconciliations": reconciliations,
    }


def _challenger_provider(*, project_root: Path, mode_name: str) -> str | None:
    mode = load_config(project_root).challenger.modes.get(mode_name)
    if mode is None:
        return None
    for participant in mode.participants:
        if participant.role == "challenger":
            return participant.provider
    return None


def _reconcile_parallel_findings(
    provider_findings: Mapping[str, list[dict[str, Any]]],
) -> list[ChallengerReconciliation]:
    buckets: list[tuple[str, list[tuple[str, dict[str, Any]]]]] = []
    for provider, findings in provider_findings.items():
        for finding in findings:
            key = _parallel_finding_key(finding)
            bucket = _matching_parallel_bucket(buckets, provider, finding)
            if bucket is None:
                bucket = (key, [])
                buckets.append(bucket)
            bucket[1].append((provider, finding))

    reconciliations: list[ChallengerReconciliation] = []
    for key, entries in buckets:
        providers = _ordered_unique([provider for provider, _finding in entries])
        status = "agreed" if len(providers) > 1 else "unique"
        severity_values = [
            str((finding.get("classification") or {}).get("severity"))
            for _provider, finding in entries
            if (finding.get("classification") or {}).get("severity") is not None
        ]
        severities = _ordered_unique(severity_values)
        normalized_severities = _ordered_unique(
            [severity.casefold() for severity in severity_values]
        )
        if status == "agreed" and len(normalized_severities) > 1:
            status = "disputed"
        reconciliations.append(
            ChallengerReconciliation(
                finding_ids=[
                    _finding_id(finding, fallback_key=key)
                    for _provider, finding in entries
                ],
                status=status,
                participant_providers=providers,
                agreed_severity=severities[0] if status == "agreed" and severities else None,
                rationale=_parallel_rationale(status, providers),
            )
        )
    return reconciliations


def _matching_parallel_bucket(
    buckets: list[tuple[str, list[tuple[str, dict[str, Any]]]]],
    provider: str,
    finding: dict[str, Any],
) -> tuple[str, list[tuple[str, dict[str, Any]]]] | None:
    candidate_key = _parallel_finding_key(finding)
    for bucket in buckets:
        _bucket_key, entries = bucket
        providers = {entry_provider for entry_provider, _entry_finding in entries}
        for _entry_provider, entry_finding in entries:
            if candidate_key == _parallel_finding_key(entry_finding):
                return bucket
            if provider in providers:
                continue
            if _parallel_findings_match(entry_finding, finding):
                return bucket
    return None


def _parallel_findings_match(
    left: dict[str, Any],
    right: dict[str, Any],
) -> bool:
    left_location = left.get("location") or {}
    right_location = right.get("location") or {}
    left_classification = left.get("classification") or {}
    right_classification = right.get("classification") or {}
    if left_classification.get("cwe") != right_classification.get("cwe"):
        return False
    if not _parallel_same_file(left_location.get("file"), right_location.get("file")):
        return False
    return _parallel_lines_near(left_location, right_location)


def _parallel_finding_key(finding: dict[str, Any]) -> str:
    location = finding.get("location") or {}
    classification = finding.get("classification") or {}
    file_path = location.get("file")
    line_start = location.get("line_start")
    cwe = classification.get("cwe")
    if file_path is not None and line_start is not None and cwe is not None:
        return f"{file_path}:{line_start}:{cwe}"
    return _finding_id(finding, fallback_key="unknown")


def _parallel_same_file(left_file: Any, right_file: Any) -> bool:
    if left_file is None or right_file is None:
        return False
    left = str(left_file).replace("\\", "/").strip("/")
    right = str(right_file).replace("\\", "/").strip("/")
    return left == right or left.endswith(f"/{right}") or right.endswith(f"/{left}")


def _parallel_lines_near(
    left_location: dict[str, Any],
    right_location: dict[str, Any],
) -> bool:
    left_start = _line_number(left_location.get("line_start"))
    right_start = _line_number(right_location.get("line_start"))
    if left_start is None or right_start is None:
        return False
    left_end = _line_number(left_location.get("line_end")) or left_start
    right_end = _line_number(right_location.get("line_end")) or right_start
    return (
        left_start <= right_end + _PARALLEL_LINE_MATCH_WINDOW
        and right_start <= left_end + _PARALLEL_LINE_MATCH_WINDOW
    )


def _line_number(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _finding_id(finding: dict[str, Any], *, fallback_key: str) -> str:
    finding_id = finding.get("id")
    return finding_id if isinstance(finding_id, str) and finding_id else fallback_key


def _ordered_unique(values: list[str]) -> list[str]:
    seen: list[str] = []
    for value in values:
        if value not in seen:
            seen.append(value)
    return seen


def _parallel_rationale(status: str, providers: list[str]) -> str:
    provider_list = ", ".join(providers)
    if status == "agreed":
        return f"Multiple primary providers reported the same finding: {provider_list}."
    if status == "disputed":
        return (
            "Multiple primary providers reported the same finding with "
            f"different severities: {provider_list}."
        )
    return f"Only one primary provider reported this finding: {provider_list}."
