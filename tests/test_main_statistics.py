from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

import numpy as np
import pandas as pd

ROOT = pathlib.Path(__file__).resolve().parents[1]
for path in (ROOT / "src", ROOT / "scripts"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from analyze_main_statistics import (  # noqa: E402
    analyze_model,
    apply_holm,
    load_compact_predictions,
    reconcile_targets,
)
from rag_da_statistics import exact_mcnemar, holm_adjust  # noqa: E402


class TestMainStatistics(unittest.TestCase):
    def test_point_estimates_use_defined_denominators(self):
        rows = pd.DataFrame({
            "model": ["M"] * 6,
            "query_id": [str(i) for i in range(6)],
            "y_true": ["LOW", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL"],
            "y_clean": ["LOW", "MEDIUM", "HIGH", "MEDIUM", "CRITICAL", "CRITICAL"],
            "y_adv": ["LOW", "LOW", "MEDIUM", "CRITICAL", "MEDIUM", ""],
        })
        result = analyze_model(rows, bootstrap_rounds=50, permutation_rounds=100, seed=7)
        self.assertEqual((result["dsr"]["numerator"], result["dsr"]["denominator"]), (2, 4))
        self.assertEqual((result["asr_true"]["numerator"], result["asr_true"]["denominator"]), (3, 5))
        self.assertEqual((result["critical_to_low_medium"]["numerator"], result["critical_to_low_medium"]["denominator"]), (1, 2))
        self.assertAlmostEqual(result["clean_accuracy"]["percent"], 500 / 6)
        self.assertAlmostEqual(result["attack_accuracy"]["percent"], 100 / 6)

    def test_exact_mcnemar_and_holm(self):
        test = exact_mcnemar([True, True, True, False], [False, False, True, True])
        self.assertEqual((test["b"], test["c"]), (2, 1))
        self.assertEqual(test["p_raw"], 1.0)
        adjusted = holm_adjust([("a", 0.01), ("b", 0.03), ("c", 0.5)])
        self.assertAlmostEqual(adjusted["a"], 0.03)
        self.assertAlmostEqual(adjusted["b"], 0.06)
        self.assertAlmostEqual(adjusted["c"], 0.5)

    def test_loader_rejects_duplicate_model_query_pairs(self):
        rows = pd.DataFrame({
            "model": ["M", "M"], "query_id": ["1", "1"],
            "y_true": ["HIGH", "HIGH"], "y_clean": ["HIGH", "HIGH"],
            "y_adv": ["LOW", "LOW"],
        })
        with tempfile.TemporaryDirectory() as temp_dir:
            path = pathlib.Path(temp_dir) / "compact.csv"
            rows.to_csv(path, index=False)
            with self.assertRaisesRegex(ValueError, "duplicate"):
                load_compact_predictions(path)

    def test_holm_is_applied_within_each_test_family(self):
        results = {
            "A": {"mcnemar_exact": {"p_raw": 0.01}, "q_hi_sign_flip": {"p_raw": 0.2}},
            "B": {"mcnemar_exact": {"p_raw": 0.04}, "q_hi_sign_flip": {"p_raw": 0.3}},
        }
        apply_holm(results)
        self.assertAlmostEqual(results["A"]["mcnemar_exact"]["p_holm"], 0.02)
        self.assertAlmostEqual(results["B"]["mcnemar_exact"]["p_holm"], 0.04)
        self.assertAlmostEqual(results["A"]["q_hi_sign_flip"]["p_holm"], 0.4)
        self.assertAlmostEqual(results["B"]["q_hi_sign_flip"]["p_holm"], 0.4)

    def test_reconciliation_uses_displayed_precision(self):
        results = {"M": {"dsr": {"percent": 12.318}}}
        rows = reconcile_targets(results, {"M": {"dsr": [12.30, 1]}})
        self.assertTrue(rows[0]["matches"])
        rows = reconcile_targets(results, {"M": {"dsr": [12.30, 2]}})
        self.assertFalse(rows[0]["matches"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
