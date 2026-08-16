"""Build identifier and subtoken frequency summaries for family curation."""

from __future__ import annotations

import argparse
from collections import Counter
import json
import pathlib
import sys
from typing import Iterable

import pandas as pd


ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from rag_da import _extract_variables, _parse_c_or_cpp, _split_identifier_subtokens  # noqa: E402


CODE_COLUMNS = ("code", "func", "function", "source", "snippet")


def load_table(path: pathlib.Path) -> pd.DataFrame:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return pd.read_csv(path)
    if suffix in {".xlsx", ".xls"}:
        return pd.read_excel(path)
    if suffix in {".json", ".jsonl"}:
        return pd.read_json(path, lines=suffix == ".jsonl")
    raise ValueError(f"unsupported dataset format: {path}")


def resolve_code_column(frame: pd.DataFrame, requested: str | None) -> str:
    if requested:
        if requested not in frame.columns:
            raise KeyError(f"code column not found: {requested}")
        return requested
    lowered = {str(column).lower(): str(column) for column in frame.columns}
    for candidate in CODE_COLUMNS:
        if candidate in lowered:
            return lowered[candidate]
    raise KeyError(f"no code column found; tried {', '.join(CODE_COLUMNS)}")


def iter_code(paths: Iterable[pathlib.Path], code_column: str | None):
    for path in paths:
        frame = load_table(path)
        column = resolve_code_column(frame, code_column)
        for value in frame[column].dropna():
            code = str(value)
            if code.strip():
                yield path, code


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="+", type=pathlib.Path)
    parser.add_argument("--code-column")
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--top", type=int, default=500)
    args = parser.parse_args()

    name_counts: Counter[str] = Counter()
    subtoken_counts: Counter[str] = Counter()
    rows = parsed_rows = 0
    for _path, code in iter_code(args.inputs, args.code_column):
        rows += 1
        _language, tree = _parse_c_or_cpp(code)
        if tree is None:
            continue
        parsed_rows += 1
        for variable in _extract_variables(tree.root_node):
            name_counts[variable.name] += 1
            subtoken_counts.update(_split_identifier_subtokens(variable.name))

    payload = {
        "inputs": [str(path) for path in args.inputs],
        "rows": rows,
        "parsed_rows": parsed_rows,
        "identifier_frequencies": name_counts.most_common(args.top),
        "subtoken_frequencies": subtoken_counts.most_common(args.top),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
