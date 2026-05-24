# -*- coding: utf-8 -*-
"""Deterministic checks for Algorithm 1 (variant-first beam on top-k demos).

These tests verify attack *logic*, not paper table numbers. End-to-end metrics
depend on datasets, FAISS indexes, and LLM backends that are intentionally
external to this repository.
"""

from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from rag_da import rag_da_attack  # noqa: E402


def _toy_demos(n: int, seed: int = 0) -> list:
    demos = []
    for i in range(n):
        demos.append(
            {
                "code": f"void f{i}(char* buf{i}, int len{i}) {{ strcpy(dst{i}, buf{i}); }}",
                "description": f"toy vulnerability {i}",
                "cve_id": f"CVE-TOY-{i:04d}",
                "base_severity": "HIGH",
                "score": 0.9 - i * 0.01,
                "cwe_ids": "CWE-120",
            }
        )
    return demos


class TestAlgorithm1Beam(unittest.TestCase):
    def test_five_demos_in_five_variants_out(self):
        demos = _toy_demos(5)
        out = rag_da_attack(
            fixed_demos=demos,
            k=5,
            beam_width=8,
            variant_m=3,
            max_ids=3,
            seed=42,
            w_sim=1.0,
            diversity_lambda=0.1,
            edit_lambda=0.0,
            variant_score_fn=lambda v, o: float(o["score"]) + 0.01 * int(v.get("_is_edited", 0)),
        )
        self.assertEqual(len(out), 5)

    def test_one_variant_per_retrieved_demo(self):
        demos = _toy_demos(5)
        out = rag_da_attack(
            fixed_demos=demos,
            k=5,
            beam_width=8,
            variant_m=3,
            max_ids=3,
            seed=42,
            variant_score_fn=lambda v, o: float(o["score"]),
        )
        base_indices = [int(d["_base_index"]) for d in out]
        self.assertEqual(len(base_indices), len(set(base_indices)), "duplicate demo index")
        self.assertEqual(sorted(base_indices), list(range(5)))

    def test_preserves_non_code_fields(self):
        demos = _toy_demos(3)
        out = rag_da_attack(fixed_demos=demos, k=3, seed=7, max_ids=2)
        for chosen, original in zip(out, demos):
            idx = int(chosen["_base_index"])
            self.assertEqual(chosen["cve_id"], original["cve_id"])
            self.assertEqual(chosen["description"], original["description"])
            self.assertEqual(chosen["base_severity"], original["base_severity"])
            self.assertEqual(idx, demos.index(original))

    def test_deterministic_under_fixed_seed(self):
        demos = _toy_demos(5)
        kwargs = dict(
            k=5,
            beam_width=8,
            variant_m=3,
            max_ids=3,
            seed=123,
            variant_score_fn=lambda v, o: float(o["score"]),
        )
        a = rag_da_attack(fixed_demos=demos, **kwargs)
        b = rag_da_attack(fixed_demos=demos, **kwargs)
        self.assertEqual([d["code"] for d in a], [d["code"] for d in b])
        self.assertEqual([d["_base_index"] for d in a], [d["_base_index"] for d in b])

    def test_k_less_than_pool_only_selects_k_demos(self):
        demos = _toy_demos(5)
        out = rag_da_attack(fixed_demos=demos, k=3, seed=99)
        self.assertEqual(len(out), 3)
        self.assertEqual(len({int(d["_base_index"]) for d in out}), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
