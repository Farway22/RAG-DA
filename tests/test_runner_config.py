from __future__ import annotations

import os
import pathlib
import sys
import unittest
from types import SimpleNamespace
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
SCRIPTS = ROOT / "scripts"
for path in (str(SRC), str(SCRIPTS)):
    if path not in sys.path:
        sys.path.insert(0, path)

from rag_da_reproduce import parse_args, select_demos  # noqa: E402


def _pool(n: int) -> list[dict]:
    return [
        {
            "code": f"int f{i}(int value{i}) {{ return value{i}; }}",
            "description": f"sample {i}",
            "cve_id": f"CVE-TEST-{i:04d}",
            "base_severity": "HIGH",
            "score": 1.0 - i / 100.0,
        }
        for i in range(n)
    ]


class TestRunnerConfiguration(unittest.TestCase):
    def test_yaml_defaults_are_loaded(self):
        config_path = ROOT / "configs" / "vuln_beam_best.yaml"
        with mock.patch.dict(os.environ, {}, clear=True):
            args = parse_args(["--config", str(config_path)])

        self.assertEqual(args.pool_size, 30)
        self.assertEqual(args.topk, 5)
        self.assertEqual(args.beam_width, 8)
        self.assertEqual(args.variant_m, 3)
        self.assertFalse(args.infer_simple)
        self.assertTrue(args.recompute_variant_similarity)
        self.assertEqual(args.slot_freq_weight, 1.0)
        self.assertEqual(args.slot_prox_weight, 1.0)
        self.assertEqual(args.slot_role_weight, 2.0)
        self.assertEqual(args.family_mode, "family")
        self.assertEqual(args.family_lex_weight, 1.0)
        self.assertEqual(args.family_context_weight, 0.5)
        self.assertEqual(args.family_min_score, 0.5)

    def test_cli_overrides_yaml(self):
        config_path = ROOT / "configs" / "vuln_beam_best.yaml"
        with mock.patch.dict(os.environ, {}, clear=True):
            args = parse_args(
                [
                    "--config",
                    str(config_path),
                    "--pool-size",
                    "40",
                    "--topk",
                    "7",
                    "--beam-width",
                    "4",
                ]
            )

        self.assertEqual(args.pool_size, 40)
        self.assertEqual(args.topk, 7)
        self.assertEqual(args.beam_width, 4)

    def test_pool_is_reduced_to_ordered_topk_for_clean_and_attack(self):
        pool = _pool(30)
        args = SimpleNamespace(
            topk=5,
            recompute_variant_similarity=False,
            alpha=0.6,
            beta=0.4,
            beam_width=8,
            variant_m=3,
            rewrite_max_ids=3,
            variant_seed=42,
            w_sim=1.0,
            diversity_lambda=0.1,
            edit_lambda=0.0,
        )

        clean = select_demos("clean", "query", "description", pool, args)
        attack = select_demos("attack", "query", "description", pool, args)

        expected_ids = [item["cve_id"] for item in pool[:5]]
        self.assertEqual([item["cve_id"] for item in clean], expected_ids)
        self.assertEqual([item["cve_id"] for item in attack], expected_ids)
        self.assertEqual([int(item["_base_index"]) for item in attack], [0, 1, 2, 3, 4])


if __name__ == "__main__":
    unittest.main(verbosity=2)
