"""Create license-safe split identifiers and checksums from external tables.

The emitted CSV contains no source code or descriptions. A row digest binds the
public identifier to the complete retained record without redistributing it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pandas as pd


def _read_table(path: Path) -> pd.DataFrame:
    if path.suffix.lower() == ".csv":
        return pd.read_csv(path, keep_default_na=False)
    if path.suffix.lower() in {".xlsx", ".xls"}:
        return pd.read_excel(path, keep_default_na=False)
    raise ValueError(f"unsupported table format: {path}")


def _canonical_row(row: pd.Series) -> bytes:
    payload = {str(key): str(value) for key, value in row.items()}
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", required=True, help="stable split name")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    frame = _read_table(args.input)
    if "cve_id" not in frame or "Base Severity" not in frame:
        parser.error("input must contain cve_id and Base Severity columns")

    rows = []
    for index, row in frame.iterrows():
        digest = hashlib.sha256(_canonical_row(row)).hexdigest()
        rows.append(
            {
                "split": args.split,
                "row_index": int(index),
                "query_id": f"{args.split}:{index}:{digest[:12]}",
                "cve_id": str(row["cve_id"]),
                "severity": str(row["Base Severity"]).upper(),
                "row_sha256": digest,
            }
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(args.output, index=False, encoding="utf-8")
    metadata = {
        "split": args.split,
        "rows": len(frame),
        "source_filename": args.input.name,
        "source_file_sha256": hashlib.sha256(args.input.read_bytes()).hexdigest(),
        "manifest_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
        "row_digest": "SHA-256 of canonical JSON containing every retained source column",
    }
    args.output.with_suffix(".json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(metadata, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
