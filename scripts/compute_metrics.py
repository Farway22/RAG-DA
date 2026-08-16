# -*- coding: utf-8 -*-
"""Compute standard classification metrics from a prediction workbook."""

from __future__ import annotations

import argparse
import numbers
import re
import sys
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score, matthews_corrcoef, precision_recall_fscore_support

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from rag_da_metrics import calculate_cmr_adv, calculate_dsr, calculate_true_asr  # noqa: E402


VALID_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def normalize_label(label: str) -> str:
    if not isinstance(label, str):
        return ""
    match = re.search(r"(LOW|MEDIUM|HIGH|CRITICAL)", label.upper())
    return match.group(1) if match else ""


def normalize_query_id(value) -> str:
    if pd.isna(value):
        return ""
    if isinstance(value, numbers.Integral):
        return str(int(value))
    if isinstance(value, numbers.Real) and float(value).is_integer():
        return str(int(value))
    return str(value).strip()


def load_predictions(path: Path, predicted_col: str, truth_col: str, id_col: str) -> pd.DataFrame:
    df = pd.read_excel(path)
    missing = [column for column in (id_col, predicted_col, truth_col) if column not in df.columns]
    if missing:
        raise ValueError(f"missing columns {missing!r} in {path}")

    rows = df[[id_col, truth_col, predicted_col]].copy()
    rows["query_id"] = rows[id_col].map(normalize_query_id)
    rows["y_true"] = rows[truth_col].astype(str).str.upper().str.strip()
    rows["y_pred"] = rows[predicted_col].map(normalize_label)
    rows = rows[
        (rows["query_id"] != "")
        & rows["y_true"].isin(VALID_LEVELS)
    ][["query_id", "y_true", "y_pred"]]
    if rows.empty:
        raise ValueError(f"no rows with a valid query ID and ground-truth label found in {path}")
    duplicates = rows.loc[rows["query_id"].duplicated(keep=False), "query_id"].unique().tolist()
    if duplicates:
        preview = duplicates[:5]
        raise ValueError(f"duplicate {id_col!r} values in {path}: {preview!r}")
    return rows.reset_index(drop=True)


def pair_predictions(clean: pd.DataFrame, attack: pd.DataFrame) -> pd.DataFrame:
    clean_ids = set(clean["query_id"])
    attack_ids = set(attack["query_id"])
    if clean_ids != attack_ids:
        missing_attack = sorted(clean_ids - attack_ids)[:5]
        missing_clean = sorted(attack_ids - clean_ids)[:5]
        raise ValueError(
            "clean/attack query IDs do not match; "
            f"missing from attack={missing_attack!r}, missing from clean={missing_clean!r}"
        )

    paired = clean.merge(attack, on="query_id", how="inner", suffixes=("_clean", "_adv"), validate="one_to_one")
    truth_mismatch = paired[paired["y_true_clean"] != paired["y_true_adv"]]
    if not truth_mismatch.empty:
        preview = truth_mismatch["query_id"].head(5).tolist()
        raise ValueError(f"ground-truth labels disagree for paired query IDs: {preview!r}")
    return paired


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compute CMR, DSR, true ASR, and related metrics from prediction files."
    )
    parser.add_argument("--predictions", required=True, help="Attack or evaluation workbook (.xlsx)")
    parser.add_argument("--clean", default="", help="Optional clean baseline workbook for DSR/ASR")
    parser.add_argument("--predicted-col", default="Predicted")
    parser.add_argument("--truth-col", default="Base Severity")
    parser.add_argument("--clean-col", default="Predicted")
    parser.add_argument(
        "--id-col",
        default="Original_Index",
        help="Stable query identifier used to pair clean and attack predictions",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    pred_path = Path(args.predictions)
    attack = load_predictions(pred_path, args.predicted_col, args.truth_col, args.id_col)
    y_true = attack["y_true"].tolist()
    y_adv = attack["y_pred"].tolist()
    n = len(attack)
    invalid_predictions = int((~attack["y_pred"].isin(VALID_LEVELS)).sum())

    acc = accuracy_score(y_true, y_adv)
    precision_ma, recall_ma, f1_ma, _ = precision_recall_fscore_support(
        y_true,
        y_adv,
        labels=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        average="macro",
        zero_division=0,
    )
    mcc = matthews_corrcoef(y_true, y_adv)
    cmr_adv, _, _ = calculate_cmr_adv(y_true, y_adv)

    print(f"file={pred_path}")
    print(f"labeled_rows={n}")
    print(f"invalid_predictions={invalid_predictions}")
    print(f"accuracy={acc:.4f}")
    print(f"precision_macro={precision_ma:.4f}")
    print(f"recall_macro={recall_ma:.4f}")
    print(f"f1_macro={f1_ma:.4f}")
    print(f"mcc={mcc:.4f}")
    if cmr_adv is not None:
        print(f"cmr_adv={cmr_adv:.2f}")

    if args.clean:
        clean_path = Path(args.clean)
        clean = load_predictions(clean_path, args.clean_col, args.truth_col, args.id_col)
        paired = pair_predictions(clean, attack)
        y_true = paired["y_true_clean"].tolist()
        y_clean = paired["y_pred_clean"].tolist()
        y_adv = paired["y_pred_adv"].tolist()
        dsr, dsr_num, dsr_den = calculate_dsr(y_true, y_adv)
        true_asr, asr_num, asr_den = calculate_true_asr(y_true, y_clean, y_adv)
        print(f"paired_rows={len(paired)}")
        if dsr is not None:
            print(f"dsr={dsr:.2f}")
            print(f"dsr_count={dsr_num}/{dsr_den}")
        if true_asr is not None:
            print(f"true_asr={true_asr:.2f}")
            print(f"true_asr_count={asr_num}/{asr_den}")


if __name__ == "__main__":
    main()
