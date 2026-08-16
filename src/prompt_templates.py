"""Lightweight prompt builders shared by the public inference paths."""

from __future__ import annotations

from typing import Any, Mapping, Sequence


def build_simple_prompt(
    query_code: str,
    query_desc: str,
    topk_samples: Sequence[Mapping[str, Any]],
    *,
    slim: bool = False,
    trunc_chars: int = 0,
) -> str:
    """Build the No-CoT prompt with exactly one target block."""

    def maybe_truncate(value: Any) -> str:
        text = str(value or "")
        if trunc_chars > 0 and len(text) > trunc_chars:
            return text[:trunc_chars]
        return text

    if slim:
        parts = [
            "Below are a few code snippets. Infer the severity of the target "
            "code as one of: LOW, MEDIUM, HIGH, CRITICAL.\n\n"
        ]
        for index, item in enumerate(topk_samples, start=1):
            parts.append(
                f"Sample {index}:\n"
                f"- Code:\n{maybe_truncate(item.get('code', ''))}\n"
                f"- Severity: {item.get('base_severity', '')}\n\n"
            )
        parts.extend(
            [
                "Target:\n",
                f"- Code:\n{maybe_truncate(query_code)}\n\n",
                "Output only one token among: LOW, MEDIUM, HIGH, CRITICAL.",
            ]
        )
        return "".join(parts)

    parts = [
        "Below are several similar vulnerability samples with their code, "
        "description, and corresponding severity levels. Based on these "
        "samples, you will determine the severity of the target vulnerability "
        "example. Please only output the severity level of the target "
        "vulnerability example without providing any explanations or severity "
        "levels of the similar samples.\n\n"
    ]
    for index, item in enumerate(topk_samples, start=1):
        parts.append(
            f"Sample {index}:\n"
            f"- CVE ID: {item.get('cve_id', '')}\n"
            f"- CWE IDs: {item.get('cwe_ids', '')}\n"
            f"- Base Score: {item.get('base_score', '')}\n"
            f"- Base Severity: {item.get('base_severity', '')}\n"
            f"- Code: {item.get('code', '')}\n"
            f"- Description: {item.get('description', '')}\n"
            f"- NVD Info: {item.get('nvd_info', '')}\n"
            f"- CWE Info: {item.get('cwe_info', '')}\n\n"
        )
    parts.extend(
        [
            "Target Vulnerability:\n",
            f"- Code: {query_code}\n",
            f"- Description: {query_desc}\n\n",
        ]
    )
    return "".join(parts)
