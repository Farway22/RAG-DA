from __future__ import annotations

import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from prompt_templates import build_simple_prompt


def sample_rows(count: int = 5):
    return [
        {
            "cve_id": f"CVE-TEST-{index}",
            "cwe_ids": f"CWE-{100 + index}",
            "base_score": 5.0 + index,
            "base_severity": "HIGH",
            "code": f"void demo_{index}(void) {{}}",
            "description": f"sample description {index}",
            "nvd_info": f"NVD field {index}",
            "cwe_info": f"CWE field {index}",
        }
        for index in range(1, count + 1)
    ]


class TestSimplePrompt(unittest.TestCase):
    def test_full_prompt_has_five_samples_and_one_target(self):
        query_code = "void unique_target_query(void) {}"
        prompt = build_simple_prompt(
            query_code,
            "unique target description",
            sample_rows(),
        )

        self.assertEqual(prompt.count("Sample "), 5)
        self.assertEqual(prompt.count("Target Vulnerability:"), 1)
        self.assertEqual(prompt.count(query_code), 1)

    def test_slim_prompt_omits_metadata_and_has_one_target(self):
        query_code = "void unique_slim_target(void) {}"
        prompt = build_simple_prompt(
            query_code,
            "description must not be included",
            sample_rows(),
            slim=True,
        )

        self.assertEqual(prompt.count("Sample "), 5)
        self.assertEqual(prompt.count("Target:"), 1)
        self.assertEqual(prompt.count(query_code), 1)
        self.assertNotIn("- Description:", prompt)
        self.assertNotIn("- NVD Info:", prompt)
        self.assertNotIn("- CWE Info:", prompt)


if __name__ == "__main__":
    unittest.main(verbosity=2)
