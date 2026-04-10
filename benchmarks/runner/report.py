"""Markdown report rendering for benchmark runs."""
from __future__ import annotations

from io import StringIO

from benchmarks.runner.models import MetricSet, Summary


def render_markdown(summary: Summary) -> str:
    """Render a Summary as a Markdown report."""
    out = StringIO()

    _write_header(out, summary)
    _write_overall(out, summary)
    _write_per_cwe(out, summary)
    _write_per_language(out, summary)
    _write_methodology(out, summary)

    return out.getvalue()


def _write_header(out: StringIO, summary: Summary) -> None:
    out.write(f"# Benchmark Run `{summary.run_id}`\n\n")
    out.write(f"- **Agent:** `{summary.agent_name}`\n")
    out.write(f"- **Dataset:** `{summary.dataset}`\n")
    out.write(f"- **Generated:** {summary.generated_at}\n\n")


def _write_overall(out: StringIO, summary: Summary) -> None:
    overall = next(
        (m for m in summary.metrics if m.cwe_id is None and m.language is None),
        None,
    )
    if overall is None:
        out.write("## Overall\n\n_(no overall metric)_\n\n")
        return
    out.write("## Overall\n\n")
    out.write("| Metric | Value |\n|---|---|\n")
    out.write(f"| TPR (recall) | {_pct(overall.tpr)} |\n")
    out.write(f"| FPR | {_pct(overall.fpr)} |\n")
    out.write(f"| Precision | {_pct(overall.precision)} |\n")
    out.write(f"| F1 | {_pct(overall.f1)} |\n")
    out.write(f"| Accuracy (TPR - FPR) | {_pct(overall.accuracy)} |\n")
    out.write(f"| TP / FP / TN / FN | "
              f"{overall.true_positives} / {overall.false_positives} / "
              f"{overall.true_negatives} / {overall.false_negatives} |\n\n")


def _write_per_cwe(out: StringIO, summary: Summary) -> None:
    per_cwe = [m for m in summary.metrics if m.cwe_id is not None and m.language is None]
    if not per_cwe:
        return
    out.write("## Per CWE\n\n")
    out.write("| CWE | TPR | FPR | Precision | F1 | TP | FP | FN |\n")
    out.write("|---|---|---|---|---|---|---|---|\n")
    for m in sorted(per_cwe, key=lambda x: x.cwe_id or ""):
        out.write(f"| {m.cwe_id} | {_pct(m.tpr)} | {_pct(m.fpr)} | "
                  f"{_pct(m.precision)} | {_pct(m.f1)} | "
                  f"{m.true_positives} | {m.false_positives} | {m.false_negatives} |\n")
    out.write("\n")


def _write_per_language(out: StringIO, summary: Summary) -> None:
    per_lang = [m for m in summary.metrics if m.language is not None and m.cwe_id is None]
    if not per_lang:
        return
    out.write("## Per Language\n\n")
    out.write("| Language | TPR | FPR | Precision | F1 | TP | FP | FN |\n")
    out.write("|---|---|---|---|---|---|---|---|\n")
    for m in sorted(per_lang, key=lambda x: x.language.value if x.language else ""):
        name = m.language.value.capitalize() if m.language else "—"
        out.write(f"| {name} | {_pct(m.tpr)} | {_pct(m.fpr)} | "
                  f"{_pct(m.precision)} | {_pct(m.f1)} | "
                  f"{m.true_positives} | {m.false_positives} | {m.false_negatives} |\n")
    out.write("\n")


def _write_methodology(out: StringIO, summary: Summary) -> None:
    out.write("## Methodology\n\n")
    for key, value in sorted(summary.methodology.items()):
        out.write(f"- **{key}**: `{value}`\n")
    out.write("\n")


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"
