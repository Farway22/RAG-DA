from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class TestCanonicalBeamEntry(unittest.TestCase):
    def test_retrieval_module_has_no_second_beam_entry(self):
        retrieval_source = (ROOT / "src" / "retrieval.py").read_text(encoding="utf-8")
        runner_source = (ROOT / "scripts" / "rag_da_reproduce.py").read_text(encoding="utf-8")

        self.assertNotIn("predict_vuln_level_rag_llm_beam", retrieval_source)
        self.assertNotIn("REWRITE_TARGET", retrieval_source)
        self.assertNotIn("w_sev", retrieval_source)
        self.assertNotIn("true_severity", retrieval_source)
        self.assertIn("rag_da_attack(", runner_source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
