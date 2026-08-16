from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

import pandas as pd
from sklearn.metrics import accuracy_score


ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
SCRIPTS = ROOT / "scripts"
for path in (str(SRC), str(SCRIPTS)):
    if path not in sys.path:
        sys.path.insert(0, path)

from compute_metrics import load_predictions, pair_predictions  # noqa: E402
from rag_da_metrics import calculate_cmr_adv, calculate_dsr, calculate_true_asr  # noqa: E402


class TestPairedMetrics(unittest.TestCase):
    def test_dsr_compares_attack_with_ground_truth(self):
        y_true = ["HIGH", "HIGH", "CRITICAL", "MEDIUM"]
        y_adv = ["MEDIUM", "CRITICAL", "HIGH", "LOW"]

        rate, numerator, denominator = calculate_dsr(y_true, y_adv)

        self.assertEqual((numerator, denominator), (2, 3))
        self.assertAlmostEqual(rate, 200 / 3)

    def test_true_asr_uses_only_clean_correct_queries(self):
        y_true = ["HIGH", "CRITICAL", "MEDIUM", "LOW"]
        y_clean = ["HIGH", "CRITICAL", "LOW", "LOW"]
        y_adv = ["MEDIUM", "CRITICAL", "LOW", "LOW"]

        rate, numerator, denominator = calculate_true_asr(y_true, y_clean, y_adv)

        self.assertEqual((numerator, denominator), (1, 3))
        self.assertAlmostEqual(rate, 100 / 3)

    def test_prediction_files_are_paired_by_original_index(self):
        clean_df = pd.DataFrame(
            {
                "Original_Index": [1, 2, 3],
                "Base Severity": ["HIGH", "CRITICAL", "MEDIUM"],
                "Predicted": ["HIGH", "CRITICAL", "MEDIUM"],
            }
        )
        attack_df = pd.DataFrame(
            {
                "Original_Index": [3, 1, 2],
                "Base Severity": ["MEDIUM", "HIGH", "CRITICAL"],
                "Predicted": ["LOW", "MEDIUM", "HIGH"],
            }
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            clean_path = pathlib.Path(temp_dir) / "clean.xlsx"
            attack_path = pathlib.Path(temp_dir) / "attack.xlsx"
            clean_df.to_excel(clean_path, index=False)
            attack_df.to_excel(attack_path, index=False)

            clean = load_predictions(clean_path, "Predicted", "Base Severity", "Original_Index")
            attack = load_predictions(attack_path, "Predicted", "Base Severity", "Original_Index")
            paired = pair_predictions(clean, attack)

        by_id = paired.set_index("query_id")
        self.assertEqual(by_id.loc["1", "y_pred_adv"], "MEDIUM")
        self.assertEqual(by_id.loc["2", "y_pred_adv"], "HIGH")
        self.assertEqual(by_id.loc["3", "y_pred_adv"], "LOW")

    def test_pairing_rejects_missing_query_ids(self):
        clean = pd.DataFrame(
            {"query_id": ["1", "2"], "y_true": ["HIGH", "HIGH"], "y_pred": ["HIGH", "HIGH"]}
        )
        attack = pd.DataFrame(
            {"query_id": ["1"], "y_true": ["HIGH"], "y_pred": ["LOW"]}
        )

        with self.assertRaisesRegex(ValueError, "query IDs do not match"):
            pair_predictions(clean, attack)

    def test_invalid_prediction_is_retained_but_not_an_attack_success(self):
        attack_df = pd.DataFrame(
            {
                "Original_Index": [1, 2],
                "Base Severity": ["HIGH", "CRITICAL"],
                "Predicted": ["unparseable response", ""],
            }
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            attack_path = pathlib.Path(temp_dir) / "attack.xlsx"
            attack_df.to_excel(attack_path, index=False)
            attack = load_predictions(attack_path, "Predicted", "Base Severity", "Original_Index")

        self.assertEqual(len(attack), 2)
        self.assertEqual(attack["y_pred"].tolist(), ["", ""])
        self.assertEqual(accuracy_score(attack["y_true"], attack["y_pred"]), 0.0)
        self.assertEqual(calculate_dsr(attack["y_true"].tolist(), attack["y_pred"].tolist())[1:], (0, 2))
        self.assertEqual(calculate_cmr_adv(attack["y_true"].tolist(), attack["y_pred"].tolist())[1:], (0, 1))

    def test_invalid_attack_prediction_is_not_true_asr_success(self):
        rate, numerator, denominator = calculate_true_asr(
            ["HIGH", "CRITICAL"], ["HIGH", "CRITICAL"], ["", "HIGH"]
        )

        self.assertEqual((numerator, denominator), (1, 2))
        self.assertEqual(rate, 50.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
