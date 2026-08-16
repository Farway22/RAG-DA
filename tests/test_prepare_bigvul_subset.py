from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from prepare_bigvul_subset import attach_descriptions, build_subset  # noqa: E402


def test_build_subset_matches_counts_and_removes_overlap() -> None:
    mega = pd.DataFrame(
        {
            "cve_id": ["M1", "M2", "M3", "M4"],
            "Base Severity": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        }
    )
    big = pd.DataFrame(
        {
            "cve_id": ["M1", "B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8"],
            "Base Severity": [
                "LOW", "LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL"
            ],
        }
    )

    result = build_subset(mega, big, seed=42)

    assert len(result) == 4
    assert set(result["cve_id"]).isdisjoint(set(mega["cve_id"]))
    assert result["Base Severity"].value_counts().to_dict() == {
        "LOW": 1,
        "MEDIUM": 1,
        "HIGH": 1,
        "CRITICAL": 1,
    }


def test_attach_descriptions_uses_first_record_without_changing_rows() -> None:
    subset = pd.DataFrame({"cve_id": ["B1", "B2"], "Base Severity": ["LOW", "HIGH"]})
    descriptions = pd.DataFrame(
        {"cve_id": ["B1", "B1"], "description": ["first", "second"]}
    )

    result = attach_descriptions(subset, descriptions)

    assert result["cve_id"].tolist() == ["B1", "B2"]
    assert result["description"].tolist() == ["first", ""]
