"""Build the severity-matched BigVul zero-transfer subset used in the paper.

The script removes CVEs present in the MegaVul test split, then samples each
severity stratum with the retained random seed. It does not redistribute either
third-party dataset.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


SEVERITY_COLUMN = "Base Severity"
ID_COLUMN = "cve_id"


def _read_table(path: Path) -> pd.DataFrame:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return pd.read_csv(path)
    if suffix in {".xlsx", ".xls"}:
        return pd.read_excel(path)
    raise ValueError(f"unsupported table format: {path}")


def build_subset(mega_test: pd.DataFrame, bigvul_test: pd.DataFrame, seed: int) -> pd.DataFrame:
    for name, frame in (("MegaVul", mega_test), ("BigVul", bigvul_test)):
        missing = {ID_COLUMN, SEVERITY_COLUMN} - set(frame.columns)
        if missing:
            raise ValueError(f"{name} input is missing columns: {sorted(missing)}")

    mega_ids = set(mega_test[ID_COLUMN].dropna().astype(str))
    available = bigvul_test[
        ~bigvul_test[ID_COLUMN].astype(str).isin(mega_ids)
    ].copy()
    target_counts = mega_test[SEVERITY_COLUMN].value_counts().sort_index()

    sampled = []
    for severity, target_count in target_counts.items():
        stratum = available[available[SEVERITY_COLUMN] == severity]
        if len(stratum) < target_count:
            raise ValueError(
                f"insufficient BigVul rows for {severity}: "
                f"need {target_count}, found {len(stratum)}"
            )
        sampled.append(stratum.sample(n=int(target_count), random_state=seed))

    result = pd.concat(sampled, ignore_index=True)
    if set(result[ID_COLUMN].astype(str)) & mega_ids:
        raise AssertionError("CVE overlap remains after filtering")
    if result[SEVERITY_COLUMN].value_counts().sort_index().to_dict() != target_counts.to_dict():
        raise AssertionError("severity distribution does not match MegaVul test")
    return result


def attach_descriptions(subset: pd.DataFrame, descriptions: pd.DataFrame) -> pd.DataFrame:
    missing = {ID_COLUMN, "description"} - set(descriptions.columns)
    if missing:
        raise ValueError(f"description table is missing columns: {sorted(missing)}")
    lookup = descriptions[[ID_COLUMN, "description"]].drop_duplicates(ID_COLUMN, keep="first")
    result = subset.drop(columns=["description"], errors="ignore").merge(
        lookup, on=ID_COLUMN, how="left", validate="many_to_one"
    )
    result["description"] = result["description"].fillna("")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mega-test", type=Path, required=True)
    parser.add_argument("--bigvul-test", type=Path, required=True)
    parser.add_argument(
        "--description-source",
        type=Path,
        default=None,
        help="optional cve_id/description table joined after sampling",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    result = build_subset(_read_table(args.mega_test), _read_table(args.bigvul_test), args.seed)
    if args.description_source is not None:
        result = attach_descriptions(result, _read_table(args.description_source))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.suffix.lower() == ".csv":
        result.to_csv(args.output, index=False)
    elif args.output.suffix.lower() == ".xlsx":
        result.to_excel(args.output, index=False)
    else:
        parser.error("--output must end in .csv or .xlsx")
    print(f"wrote {len(result)} rows to {args.output}")


if __name__ == "__main__":
    main()
