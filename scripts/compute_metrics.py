# -*- coding: utf-8 -*-
"""Compute standard classification metrics from a prediction workbook."""

from __future__ import annotations

import argparse
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


def load_labels(path: Path, predicted_col: str, truth_col: str):
    df = pd.read_excel(path)
    if predicted_col not in df.columns:
        raise ValueError(f"missing column {predicted_col!r} in {path}")
    if truth_col not in df.columns:
        raise ValueError(f"missing column {truth_col!r} in {path}")

    rows = df[df[predicted_col].notna() & (df[predicted_col].astype(str).str.strip() != "")].copy()
    rows[predicted_col] = rows[predicted_col].map(normalize_label)
    rows[truth_col] = rows[truth_col].astype(str).str.upper().str.strip()
    rows = rows[rows[predicted_col].isin(VALID_LEVELS) & rows[truth_col].isin(VALID_LEVELS)]
    if rows.empty:
        raise ValueError(f"no valid labeled rows found in {path}")
    y_true = rows[truth_col].tolist()
    y_pred = rows[predicted_col].tolist()
    return y_true, y_pred, len(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compute CMR, DSR, true ASR, and related metrics from prediction files."
    )
    parser.add_argument("--predictions", required=True, help="Attack or evaluation workbook (.xlsx)")
    parser.add_argument("--clean", default="", help="Optional clean baseline workbook for DSR/ASR")
    parser.add_argument("--predicted-col", default="Predicted")
    parser.add_argument("--truth-col", default="Base Severity")
    parser.add_argument("--clean-col", default="Predicted")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    pred_path = Path(args.predictions)
    y_true, y_adv, n = load_labels(pred_path, args.predicted_col, args.truth_col)

    acc = accuracy_score(y_true, y_adv)
    precision_ma, recall_ma, f1_ma, _ = precision_recall_fscore_support(
        y_true, y_adv, average="macro", zero_division=0
    )
    mcc = matthews_corrcoef(y_true, y_adv)
    cmr_adv, _, _ = calculate_cmr_adv(y_true, y_adv)

    print(f"file={pred_path}")
    print(f"valid_rows={n}")
    print(f"accuracy={acc:.4f}")
    print(f"precision_macro={precision_ma:.4f}")
    print(f"recall_macro={recall_ma:.4f}")
    print(f"f1_macro={f1_ma:.4f}")
    print(f"mcc={mcc:.4f}")
    if cmr_adv is not None:
        print(f"cmr_adv={cmr_adv:.2f}")

    if args.clean:
        clean_path = Path(args.clean)
        y_true_c, y_clean, _ = load_labels(clean_path, args.clean_col, args.truth_col)
        if len(y_true_c) != len(y_true):
            print("[WARN] clean and attack files have different valid row counts; aligning by min length")
            n_align = min(len(y_true_c), len(y_true), len(y_adv), len(y_clean))
            y_true = y_true[:n_align]
            y_adv = y_adv[:n_align]
            y_clean = y_clean[:n_align]
        dsr, _, _ = calculate_dsr(y_true, y_clean, y_adv)
        true_asr, _, _ = calculate_true_asr(y_true, y_clean, y_adv)
        if dsr is not None:
            print(f"dsr={dsr:.2f}")
        if true_asr is not None:
            print(f"true_asr={true_asr:.2f}")


if __name__ == "__main__":
    main()
