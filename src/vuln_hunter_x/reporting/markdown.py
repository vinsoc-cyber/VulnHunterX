"""Markdown report generation from verification results."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from vuln_hunter_x.core.types import (
    Finding,
    Verdict,
    VerdictType,
    VerificationResult,
)


# Severity sort order (highest first)
_SEVERITY_ORDER = {"error": 0, "warning": 1, "recommendation": 2, "note": 3, "": 4}


class MarkdownReportGenerator:
    """Generates markdown reports from verification results."""

    def generate(
        self,
        result: VerificationResult,
        output_path: Path,
        repo_name: str | None = None,
        lang: str | None = None,
    ) -> Path:
        """Generate a markdown report from a VerificationResult.

        Args:
            result: The verification result to report on.
            output_path: Path to write the .md file.
            repo_name: Repository name (auto-detected from verdicts if omitted).
            lang: Language (auto-detected from verdicts if omitted).

        Returns:
            Path to the generated report.
        """
        # Auto-detect repo/lang from verdicts
        if not repo_name and result.verdicts:
            repo_names = sorted(set(v.finding.repo_name for v in result.verdicts))
            repo_name = ", ".join(repo_names)
        if not lang and result.verdicts:
            langs = sorted(set(v.finding.lang for v in result.verdicts))
            lang = ", ".join(langs)

        sections = [
            self._header(result, repo_name or "unknown", lang or "unknown"),
            self._executive_summary(result),
            self._severity_breakdown(result),
            self._cwe_distribution(result),
            self._findings_detail(result),
        ]

        content = "\n".join(sections)
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        return output_path

    @staticmethod
    def from_verdict_files(verdict_dir: Path) -> VerificationResult:
        """Reconstruct a VerificationResult from saved JSON verdict files.

        Reads all .json files in the directory (excluding summary files).

        Args:
            verdict_dir: Directory containing individual verdict JSON files.

        Returns:
            Reconstructed VerificationResult.
        """
        verdicts: list[Verdict] = []
        model = ""
        provider = ""

        for json_file in sorted(verdict_dir.glob("*.json")):
            if json_file.name.startswith("summary_"):
                # Try to extract provider from summary
                try:
                    summary_data = json.loads(json_file.read_text(encoding="utf-8"))
                    provider = summary_data.get("provider", provider)
                    model = summary_data.get("model", model)
                except Exception:
                    pass
                continue
            if json_file.name == "report.md":
                continue

            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
                verdict = Verdict.from_dict(data)
                verdicts.append(verdict)
                if not model:
                    model = verdict.model
            except Exception:
                continue

        # Build stats
        stats: dict[str, int] = {}
        for v in verdicts:
            stats[v.verdict] = stats.get(v.verdict, 0) + 1

        total_time = sum(v.elapsed_seconds for v in verdicts)

        return VerificationResult(
            verdicts=verdicts,
            stats=stats,
            model=model,
            provider=provider,
            total_time_seconds=total_time,
        )

    # ── Section generators ────────────────────────────────────────

    def _header(
        self,
        result: VerificationResult,
        repo_name: str,
        lang: str,
    ) -> str:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return (
            f"# VulnHunterX Verification Report\n\n"
            f"**Generated**: {now}  \n"
            f"**Repository**: {repo_name}  \n"
            f"**Language**: {lang}  \n"
            f"**Model**: {result.model}  \n"
            f"**Provider**: {result.provider}  \n"
        )

    def _executive_summary(self, result: VerificationResult) -> str:
        total = result.total_findings
        if total == 0:
            return "---\n\n## Executive Summary\n\nNo findings to report.\n"

        tp = result.stats.get(VerdictType.TRUE_POSITIVE.value, 0)
        fp = result.stats.get(VerdictType.FALSE_POSITIVE.value, 0)
        nmd = result.stats.get(VerdictType.NEEDS_MORE_DATA.value, 0)
        err = result.stats.get(VerdictType.ERROR.value, 0)
        total_cost = sum(v.cost_usd for v in result.verdicts)
        total_tokens = sum(v.tokens_used for v in result.verdicts)

        def pct(n: int) -> str:
            return f"{n / total * 100:.1f}%" if total else "0.0%"

        lines = [
            "---\n",
            "## Executive Summary\n",
            "| Metric | Count | Percentage |",
            "|--------|------:|-----------:|",
            f"| Total Findings | {total} | 100% |",
            f"| True Positive | {tp} | {pct(tp)} |",
            f"| False Positive | {fp} | {pct(fp)} |",
            f"| Needs More Data | {nmd} | {pct(nmd)} |",
        ]
        if err:
            lines.append(f"| Error | {err} | {pct(err)} |")

        lines.extend([
            "",
            f"**False Positive Rate**: {pct(fp)}  ",
            f"**Total Verification Time**: {result.total_time_seconds:.1f}s  ",
            f"**Total Tokens**: {total_tokens:,}  ",
            f"**Total Cost**: ${total_cost:.4f}  ",
            "",
        ])
        return "\n".join(lines)

    def _severity_breakdown(self, result: VerificationResult) -> str:
        if not result.verdicts:
            return ""

        # Collect severity -> verdict counts
        severities: dict[str, dict[str, int]] = {}
        for v in result.verdicts:
            sev = v.finding.severity or "unknown"
            if sev not in severities:
                severities[sev] = {}
            severities[sev][v.verdict] = severities[sev].get(v.verdict, 0) + 1

        if not severities:
            return ""

        verdict_types = [
            VerdictType.TRUE_POSITIVE.value,
            VerdictType.FALSE_POSITIVE.value,
            VerdictType.NEEDS_MORE_DATA.value,
        ]

        lines = [
            "---\n",
            "## Severity Breakdown\n",
            "| Severity | TP | FP | NMD | Total |",
            "|----------|---:|---:|----:|------:|",
        ]

        sorted_sevs = sorted(severities.keys(), key=lambda s: _SEVERITY_ORDER.get(s, 99))
        for sev in sorted_sevs:
            counts = severities[sev]
            tp = counts.get(verdict_types[0], 0)
            fp = counts.get(verdict_types[1], 0)
            nmd = counts.get(verdict_types[2], 0)
            total = sum(counts.values())
            lines.append(f"| {sev} | {tp} | {fp} | {nmd} | {total} |")

        lines.append("")
        return "\n".join(lines)

    def _cwe_distribution(self, result: VerificationResult) -> str:
        if not result.verdicts:
            return ""

        cwe_counts: Counter[str] = Counter()
        cwe_tp: Counter[str] = Counter()
        for v in result.verdicts:
            for cwe in v.finding.cwe_ids:
                cwe_counts[cwe] += 1
                if v.is_true_positive:
                    cwe_tp[cwe] += 1

        if not cwe_counts:
            return ""

        lines = [
            "---\n",
            "## CWE Distribution\n",
            "| CWE | Count | True Positives |",
            "|-----|------:|---------------:|",
        ]

        for cwe, count in cwe_counts.most_common():
            tp = cwe_tp.get(cwe, 0)
            lines.append(f"| {cwe} | {count} | {tp} |")

        lines.append("")
        return "\n".join(lines)

    def _findings_detail(self, result: VerificationResult) -> str:
        if not result.verdicts:
            return ""

        # Group by verdict type: TP first, then NMD, then FP
        groups = [
            (VerdictType.TRUE_POSITIVE.value, "True Positives"),
            (VerdictType.NEEDS_MORE_DATA.value, "Needs More Data"),
            (VerdictType.FALSE_POSITIVE.value, "False Positives"),
            (VerdictType.ERROR.value, "Errors"),
        ]

        lines = ["---\n", "## Findings Detail\n"]

        for verdict_val, group_title in groups:
            verdicts = [
                v for v in result.verdicts if v.verdict == verdict_val
            ]
            if not verdicts:
                continue

            # Sort by severity then confidence_score descending
            verdicts.sort(
                key=lambda v: (
                    _SEVERITY_ORDER.get(v.finding.severity, 99),
                    -v.confidence_score,
                )
            )

            lines.append(f"### {group_title} ({len(verdicts)})\n")

            for i, v in enumerate(verdicts, 1):
                f = v.finding
                lines.append(
                    f"#### {i}. {f.rule_id} @ {f.file}:{f.start_line}"
                )
                lines.append("")

                # Metadata table
                lines.append("| Field | Value |")
                lines.append("|-------|-------|")
                if f.severity:
                    lines.append(f"| **Severity** | {f.severity} |")
                if f.cwe_ids:
                    lines.append(f"| **CWE** | {', '.join(f.cwe_ids)} |")
                if f.tool:
                    lines.append(f"| **Tool** | {f.tool} |")
                lines.append(f"| **Confidence** | {v.confidence} ({v.confidence_score:.2f}) |")
                lines.append(f"| **Iterations** | {v.iterations} |")
                if v.elapsed_seconds:
                    lines.append(f"| **Time** | {v.elapsed_seconds:.1f}s |")
                lines.append("")

                # Message
                lines.append(f"**Message**: {f.message}")
                lines.append("")

                # Reasoning
                lines.append(f"**Reasoning**: {v.reasoning}")
                lines.append("")

                # Dataflow path
                if f.dataflow_path:
                    lines.append("**Dataflow Path**:")
                    for step in f.dataflow_path:
                        lines.append(f"- {step}")
                    lines.append("")

                lines.append("---\n")

        return "\n".join(lines)
