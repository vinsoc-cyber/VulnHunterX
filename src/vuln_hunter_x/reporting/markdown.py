# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Markdown report generation from verification results with i18n support."""

from __future__ import annotations

import json
import logging
import os
from collections import Counter
from datetime import datetime
from pathlib import Path

from vuln_hunter_x.core.types import (
    Finding,
    Verdict,
    VerdictType,
    VerificationResult,
)

logger = logging.getLogger(__name__)

# Severity sort order (highest first)
_SEVERITY_ORDER = {"error": 0, "warning": 1, "recommendation": 2, "note": 3, "": 4}

# ── Translations ─────────────────────────────────────────────────────

_VI: dict[str, str] = {
    # Report title / headers
    "VulnHunterX Verification Report": "Báo cáo Xác minh VulnHunterX",
    "Generated": "Ngày tạo",
    "Repository": "Kho mã nguồn",
    "Language": "Ngôn ngữ",
    "Model": "Mô hình",
    "Provider": "Nhà cung cấp",
    # Sections
    "Executive Summary": "Tóm tắt",
    "Severity Breakdown": "Phân bố theo mức độ nghiêm trọng",
    "CWE Distribution": "Phân bố CWE",
    "Findings Detail": "Chi tiết phát hiện",
    # Verdict types
    "True Positives": "Lỗ hổng thực (True Positive)",
    "False Positives": "Cảnh báo sai (False Positive)",
    "Needs More Data": "Cần thêm dữ liệu",
    "Errors": "Lỗi",
    # Table headers
    "Metric": "Chỉ số",
    "Count": "Số lượng",
    "Percentage": "Tỷ lệ",
    "Total Findings": "Tổng số phát hiện",
    "True Positive": "Lỗ hổng thực",
    "False Positive": "Cảnh báo sai",
    "False Positive Rate": "Tỷ lệ cảnh báo sai",
    "Total Verification Time": "Tổng thời gian xác minh",
    "Total Tokens": "Tổng số token",
    "Total Cost": "Tổng chi phí",
    "Severity": "Mức độ",
    "Total": "Tổng",
    "True Positives Count": "Số TP",
    # Per-finding fields
    "Field": "Trường",
    "Value": "Giá trị",
    "CWE": "CWE",
    "OWASP": "OWASP",
    "Tool": "Công cụ",
    "Precision": "Độ chính xác",
    "Confidence": "Độ tin cậy",
    "Iterations": "Số vòng",
    "Time": "Thời gian",
    "Tokens": "Token",
    "Cost": "Chi phí",
    # Content labels
    "Vulnerable Code": "Mã nguồn lỗ hổng",
    "Message": "Mô tả lỗ hổng",
    "Data Flow": "Luồng dữ liệu",
    "Reasoning": "Phân tích",
    "Guided Question Answers": "Trả lời câu hỏi hướng dẫn",
    "Dataflow Path": "Đường dẫn luồng dữ liệu",
    "Related Locations": "Vị trí liên quan",
    "No findings to report.": "Không có phát hiện nào.",
    "Report sections": "Nội dung báo cáo",
    # Findings Overview section (before/after verdicting table)
    "Findings Overview": "Tổng quan phát hiện",
    "Rule": "Quy tắc",
    "File:Line": "Tệp:Dòng",
    "Severity (before)": "Mức độ (trước)",
    "Verdict (after)": "Kết luận (sau)",
}


def _extract_code_snippet(
    file_path: str,
    start_line: int,
    end_line: int,
    context: int = 5,
) -> tuple[str, str] | None:
    """Extract a code snippet from source file with line numbers.

    Returns (language_hint, snippet_text) or None if the file can't be read.
    The vulnerable line range is marked with '►' prefix.
    Context lines above/below are included for readability.
    """
    # Handle absolute paths directly
    path = Path(file_path)
    if not path.is_file():
        return None

    try:
        source_lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return None

    total = len(source_lines)
    if total == 0:
        return None

    # Window: context lines before/after the finding range
    win_start = max(0, start_line - context - 1)
    win_end = min(total, end_line + context)

    # Detect language from extension for the code fence
    suffix = path.suffix.lower()
    lang_hint = {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".java": "java", ".c": "c", ".cpp": "c++", ".cc": "c++",
        ".go": "go", ".php": "php", ".rb": "ruby", ".rs": "rust",
        ".html": "html", ".xml": "xml",
    }.get(suffix, "")

    # Build numbered snippet; mark vulnerable lines with ►
    snippet_lines: list[str] = []
    for idx in range(win_start, win_end):
        lineno = idx + 1
        is_vuln = start_line <= lineno <= end_line
        marker = "►" if is_vuln else " "
        snippet_lines.append(f"{marker} {lineno:4d} │ {source_lines[idx]}")

    return lang_hint, "\n".join(snippet_lines)


def _t(text: str, lang: str) -> str:
    """Translate static text. Returns original if lang='en' or not found."""
    if lang == "en":
        return text
    return _VI.get(text, text)


def _translate_dynamic_text(texts: list[str], lang: str) -> list[str]:
    """Translate dynamic text (reasoning, answers) via LLM.

    Falls back to original text on any failure.
    """
    if lang == "en" or not texts:
        return texts

    # Collect non-empty texts
    to_translate = [t for t in texts if t.strip()]
    if not to_translate:
        return texts

    try:
        import litellm
    except ImportError:
        logger.warning("litellm not available for translation, falling back to English")
        return texts

    # Build a single batch prompt
    numbered = "\n".join(f"[{i+1}] {t}" for i, t in enumerate(to_translate))
    prompt = (
        "Translate the following security analysis texts from English to Vietnamese. "
        "Keep technical terms (CWE, OWASP, variable names, file names, line numbers) unchanged. "
        "Return ONLY the translations in the same numbered format [1], [2], etc. "
        "Do not add explanations.\n\n"
        f"{numbered}"
    )

    # Use same LLM config as the verification engine
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    model = os.environ.get("LLM_MODEL", "")
    provider = os.environ.get("LLM_PROVIDER", "openai").lower()

    api_base: str | None = None

    if provider == "anthropic" and anthropic_key:
        llm_model = model or "claude-sonnet-4-20250514"
    elif provider == "ollama":
        ollama_model = os.environ.get("OLLAMA_MODEL", "ollama/llama3.2")
        raw = model or ollama_model
        # LiteLLM requires "ollama/<name>" prefix
        llm_model = raw if raw.startswith("ollama/") else f"ollama/{raw}"
        api_base = (os.environ.get("OLLAMA_API_BASE", "").strip() or None)
        if api_base:
            api_base = api_base.rstrip("/")
    elif api_key:
        raw = model or "gpt-4o-mini"
        # OpenAI-compatible custom endpoint (e.g. DashScope, Azure)
        openai_base = (
            os.environ.get("OPENAI_BASE_URL") or os.environ.get("OPENAI_API_BASE") or ""
        ).strip().rstrip("/")
        if openai_base:
            api_base = openai_base
            # LiteLLM needs "openai/<model>" when using a custom base URL
            llm_model = raw if raw.startswith("openai/") else f"openai/{raw}"
        else:
            llm_model = raw
    else:
        logger.warning("No LLM configured for translation, falling back to English")
        return texts

    try:
        from concurrent.futures import ThreadPoolExecutor
        from concurrent.futures import TimeoutError as FuturesTimeoutError

        kwargs: dict = {
            "model": llm_model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": min(8000, len(numbered) * 3),
        }
        if api_base:
            kwargs["api_base"] = api_base
        if api_key and provider != "ollama":
            kwargs["api_key"] = api_key

        # Use a thread with wall-clock timeout so SSL read hangs don't block forever
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(litellm.completion, **kwargs)
            try:
                resp = future.result(timeout=120)
            except FuturesTimeoutError:
                logger.warning("Translation timed out after 120s, falling back to English")
                return texts

        translated_text = (resp.choices[0].message.content or "").strip()

        # Parse numbered responses
        translated: dict[int, str] = {}
        for line in translated_text.split("\n"):
            line = line.strip()
            if line.startswith("[") and "]" in line:
                bracket_end = line.index("]")
                try:
                    num = int(line[1:bracket_end])
                    translated[num] = line[bracket_end + 1:].strip()
                except ValueError:
                    continue

        # Map back
        result = list(texts)
        translate_idx = 0
        for i, t in enumerate(texts):
            if t.strip():
                translate_idx += 1
                if translate_idx in translated:
                    result[i] = translated[translate_idx]

        return result

    except Exception:
        logger.warning("Translation failed, falling back to English", exc_info=True)
        return texts


class MarkdownReportGenerator:
    """Generates enriched markdown reports from verification results."""

    def generate(
        self,
        result: VerificationResult,
        output_path: Path,
        repo_name: str | None = None,
        lang: str | None = None,
        report_lang: str = "en",
    ) -> Path:
        """Generate a markdown report.

        Args:
            result: The verification result to report on.
            output_path: Path to write the .md file.
            repo_name: Repository name (auto-detected from verdicts if omitted).
            lang: Programming language (auto-detected from verdicts if omitted).
            report_lang: Report language — "en" (English) or "vi" (Vietnamese).

        Returns:
            Path to the generated report.
        """
        if not repo_name and result.verdicts:
            repo_names = sorted(set(v.finding.repo_name for v in result.verdicts))
            repo_name = ", ".join(repo_names)
        if not lang and result.verdicts:
            langs = sorted(set(v.finding.lang for v in result.verdicts))
            lang = ", ".join(langs)

        # Pre-translate dynamic texts if Vietnamese — ONE batched LLM call for all texts
        translated_reasoning: dict[int, str] = {}
        translated_answers: dict[int, list[str]] = {}
        if report_lang == "vi" and result.verdicts:
            all_texts: list[str] = []
            reasoning_indices: list[int] = []
            answer_indices: list[tuple[int, int, int]] = []  # (verdict_i, answer_j, flat_idx)

            for i, v in enumerate(result.verdicts):
                reasoning_indices.append(len(all_texts))
                all_texts.append(v.reasoning)
                for j, ans in enumerate(v.answers):
                    answer_indices.append((i, j, len(all_texts)))
                    all_texts.append(ans)

            translated_all = _translate_dynamic_text(all_texts, report_lang)

            for i, flat_idx in enumerate(reasoning_indices):
                translated_reasoning[i] = translated_all[flat_idx]
            for verdict_i, answer_j, flat_idx in answer_indices:
                if verdict_i not in translated_answers:
                    translated_answers[verdict_i] = list(result.verdicts[verdict_i].answers)
                translated_answers[verdict_i][answer_j] = translated_all[flat_idx]

        sections = [
            self._header(result, repo_name or "unknown", lang or "unknown", report_lang),
            self._executive_summary(result, report_lang),
            self._findings_overview(result, report_lang),
            self._severity_breakdown(result, report_lang),
            self._cwe_distribution(result, report_lang),
            self._findings_detail(result, report_lang, translated_reasoning, translated_answers),
        ]

        content = "\n".join(sections)
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        return output_path

    @staticmethod
    def from_verdict_files(verdict_dir: Path) -> VerificationResult:
        """Reconstruct a VerificationResult from saved JSON verdict files."""
        verdicts: list[Verdict] = []
        model = ""
        provider = ""

        for json_file in sorted(verdict_dir.glob("*.json")):
            if json_file.name.startswith("summary_"):
                try:
                    summary_data = json.loads(json_file.read_text(encoding="utf-8"))
                    provider = summary_data.get("provider", provider)
                    model = summary_data.get("model", model)
                except Exception:
                    pass
                continue
            if json_file.name.endswith(".md"):
                continue

            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
                verdict = Verdict.from_dict(data)
                verdicts.append(verdict)
                if not model:
                    model = verdict.model
            except Exception:
                continue

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
        self, result: VerificationResult, repo_name: str, lang: str, rl: str,
    ) -> str:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        title = _t("VulnHunterX Verification Report", rl)
        return (
            f"# {title}\n\n"
            f"**{_t('Generated', rl)}**: {now}  \n"
            f"**{_t('Repository', rl)}**: {repo_name}  \n"
            f"**{_t('Language', rl)}**: {lang}  \n"
            f"**{_t('Model', rl)}**: {result.model}  \n"
            f"**{_t('Provider', rl)}**: {result.provider}  \n"
        )

    def _executive_summary(self, result: VerificationResult, rl: str) -> str:
        total = result.total_findings
        if total == 0:
            return f"---\n\n## {_t('Executive Summary', rl)}\n\n{_t('No findings to report.', rl)}\n"

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
            f"## {_t('Executive Summary', rl)}\n",
            f"| {_t('Metric', rl)} | {_t('Count', rl)} | {_t('Percentage', rl)} |",
            "|--------|------:|-----------:|",
            f"| {_t('Total Findings', rl)} | {total} | 100% |",
            f"| {_t('True Positive', rl)} | {tp} | {pct(tp)} |",
            f"| {_t('False Positive', rl)} | {fp} | {pct(fp)} |",
            f"| {_t('Needs More Data', rl)} | {nmd} | {pct(nmd)} |",
        ]
        if err:
            lines.append(f"| {_t('Errors', rl)} | {err} | {pct(err)} |")

        lines.extend([
            "",
            f"**{_t('False Positive Rate', rl)}**: {pct(fp)}  ",
            f"**{_t('Total Verification Time', rl)}**: {result.total_time_seconds:.1f}s  ",
            f"**{_t('Total Tokens', rl)}**: {total_tokens:,}  ",
            f"**{_t('Total Cost', rl)}**: ${total_cost:.4f}  ",
            "",
        ])
        return "\n".join(lines)

    def _findings_overview(self, result: VerificationResult, rl: str) -> str:
        """Per-finding before/after table: analyzer state vs. LLM verdict.

        Rows are sorted by severity (highest first), then by verdict
        (TP → NMD → FP → Error), then by file:line — so the most actionable
        items sit at the top.
        """
        if not result.verdicts:
            return ""

        verdict_rank = {
            VerdictType.TRUE_POSITIVE.value: 0,
            VerdictType.NEEDS_MORE_DATA.value: 1,
            VerdictType.FALSE_POSITIVE.value: 2,
            VerdictType.ERROR.value: 3,
        }

        ordered = sorted(
            result.verdicts,
            key=lambda v: (
                _SEVERITY_ORDER.get(v.finding.severity, 99),
                verdict_rank.get(v.verdict, 99),
                v.finding.file,
                v.finding.start_line,
            ),
        )

        lines = [
            "---\n",
            f"## {_t('Findings Overview', rl)}\n",
            f"| # | {_t('Rule', rl)} | {_t('File:Line', rl)} | "
            f"{_t('Severity (before)', rl)} | {_t('Verdict (after)', rl)} | "
            f"{_t('Confidence', rl)} |",
            "|---:|------|-----------|----------|---------|------|",
        ]

        for i, v in enumerate(ordered, 1):
            f = v.finding
            sev = f.severity or "unknown"
            lines.append(
                f"| {i} | {f.rule_id} | {f.location} | {sev} | {v.verdict} | {v.confidence} |"
            )

        lines.append("")
        return "\n".join(lines)

    def _severity_breakdown(self, result: VerificationResult, rl: str) -> str:
        if not result.verdicts:
            return ""

        severities: dict[str, dict[str, int]] = {}
        for v in result.verdicts:
            sev = v.finding.severity or "unknown"
            if sev not in severities:
                severities[sev] = {}
            severities[sev][v.verdict] = severities[sev].get(v.verdict, 0) + 1

        if not severities:
            return ""

        lines = [
            "---\n",
            f"## {_t('Severity Breakdown', rl)}\n",
            f"| {_t('Severity', rl)} | TP | FP | NMD | {_t('Total', rl)} |",
            "|----------|---:|---:|----:|------:|",
        ]

        vt = [VerdictType.TRUE_POSITIVE.value, VerdictType.FALSE_POSITIVE.value, VerdictType.NEEDS_MORE_DATA.value]
        for sev in sorted(severities, key=lambda s: _SEVERITY_ORDER.get(s, 99)):
            counts = severities[sev]
            tp_c = counts.get(vt[0], 0)
            fp_c = counts.get(vt[1], 0)
            nmd_c = counts.get(vt[2], 0)
            total = sum(counts.values())
            lines.append(f"| {sev} | {tp_c} | {fp_c} | {nmd_c} | {total} |")

        lines.append("")
        return "\n".join(lines)

    def _cwe_distribution(self, result: VerificationResult, rl: str) -> str:
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
            f"## {_t('CWE Distribution', rl)}\n",
            f"| CWE | {_t('Count', rl)} | {_t('True Positives Count', rl)} |",
            "|-----|------:|---------------:|",
        ]

        for cwe, count in cwe_counts.most_common():
            tp = cwe_tp.get(cwe, 0)
            lines.append(f"| {cwe} | {count} | {tp} |")

        lines.append("")
        return "\n".join(lines)

    def _findings_detail(
        self,
        result: VerificationResult,
        rl: str,
        translated_reasoning: dict[int, str],
        translated_answers: dict[int, list[str]],
    ) -> str:
        if not result.verdicts:
            return ""

        groups = [
            (VerdictType.TRUE_POSITIVE.value, _t("True Positives", rl)),
            (VerdictType.NEEDS_MORE_DATA.value, _t("Needs More Data", rl)),
            (VerdictType.FALSE_POSITIVE.value, _t("False Positives", rl)),
            (VerdictType.ERROR.value, _t("Errors", rl)),
        ]

        # Build global index for translation lookup
        verdict_index = {id(v): i for i, v in enumerate(result.verdicts)}

        lines = ["---\n", f"## {_t('Findings Detail', rl)}\n"]

        for verdict_val, group_title in groups:
            verdicts = [v for v in result.verdicts if v.verdict == verdict_val]
            if not verdicts:
                continue

            verdicts.sort(key=lambda v: (_SEVERITY_ORDER.get(v.finding.severity, 99), -v.confidence_score))

            lines.append(f"### {group_title} ({len(verdicts)})\n")

            for i, v in enumerate(verdicts, 1):
                f = v.finding
                global_idx = verdict_index.get(id(v), -1)

                # Header
                lines.append(f"#### {i}. {f.rule_id} @ {f.file}:{f.start_line}")
                lines.append("")

                # Metadata table
                lines.append(f"| {_t('Field', rl)} | {_t('Value', rl)} |")
                lines.append("|-------|-------|")
                if f.severity:
                    lines.append(f"| **{_t('Severity', rl)}** | {f.severity} |")
                if f.cwe_ids:
                    lines.append(f"| **{_t('CWE', rl)}** | {', '.join(f.cwe_ids)} |")
                # OWASP / tags
                owasp_tags = [t for t in f.tags if "OWASP" in t.upper()]
                other_tags = [t for t in f.tags if "OWASP" not in t.upper() and t not in ("security",)]
                if owasp_tags:
                    lines.append(f"| **OWASP** | {', '.join(owasp_tags)} |")
                if other_tags:
                    lines.append(f"| **Tags** | {', '.join(other_tags)} |")
                if f.tool:
                    lines.append(f"| **{_t('Tool', rl)}** | {f.tool} |")
                if f.precision:
                    lines.append(f"| **{_t('Precision', rl)}** | {f.precision} |")
                lines.append(f"| **{_t('Confidence', rl)}** | {v.confidence} ({v.confidence_score:.2f}) |")
                lines.append(f"| **{_t('Iterations', rl)}** | {v.iterations} |")
                if v.elapsed_seconds:
                    lines.append(f"| **{_t('Time', rl)}** | {v.elapsed_seconds:.1f}s |")
                if v.tokens_used:
                    lines.append(f"| **{_t('Tokens', rl)}** | {v.tokens_used:,} |")
                if v.cost_usd > 0:
                    lines.append(f"| **{_t('Cost', rl)}** | ${v.cost_usd:.4f} |")
                lines.append("")

                # Code snippet
                snippet = _extract_code_snippet(f.file, f.start_line, f.end_line)
                if snippet:
                    lang_hint, snippet_text = snippet
                    lines.append(f"**{_t('Vulnerable Code', rl)}** (`{Path(f.file).name}`):\n")
                    lines.append(f"```{lang_hint}")
                    lines.append(snippet_text)
                    lines.append("```")
                    lines.append("")

                # Message
                lines.append(f"**{_t('Message', rl)}**: {f.message}")
                lines.append("")

                # Data flow (LLM-annotated)
                data_flow = v.data_flow if hasattr(v, "data_flow") else ""
                if data_flow:
                    lines.append(f"**{_t('Data Flow', rl)}**: {data_flow}")
                    lines.append("")

                # Reasoning
                reasoning = translated_reasoning.get(global_idx, v.reasoning) if rl == "vi" else v.reasoning
                lines.append(f"**{_t('Reasoning', rl)}**: {reasoning}")
                lines.append("")

                # Guided question answers
                answers = translated_answers.get(global_idx, v.answers) if rl == "vi" else v.answers
                if answers:
                    lines.append(f"**{_t('Guided Question Answers', rl)}**:\n")
                    for j, ans in enumerate(answers, 1):
                        lines.append(f"{j}. {ans}")
                    lines.append("")

                # Dataflow path (SARIF-extracted)
                if f.dataflow_path:
                    lines.append(f"**{_t('Dataflow Path', rl)}**:")
                    for step in f.dataflow_path:
                        lines.append(f"- {step}")
                    lines.append("")

                # Related locations
                if f.related_locations:
                    lines.append(f"**{_t('Related Locations', rl)}**:")
                    for loc in f.related_locations:
                        lines.append(f"- {loc}")
                    lines.append("")

                lines.append("---\n")

        return "\n".join(lines)
