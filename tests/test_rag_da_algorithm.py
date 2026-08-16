# -*- coding: utf-8 -*-
"""Deterministic checks for Algorithm 1 (variant-first beam on top-k demos).

These tests verify attack *logic*, not paper table numbers. End-to-end metrics
depend on datasets, FAISS indexes, and LLM backends that are intentionally
external to this repository.
"""

from __future__ import annotations

import pathlib
import os
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from rag_da import (  # noqa: E402
    FAMILY_TEMPLATES,
    SemanticFamily,
    _assign_semantic_family,
    _compute_diversity_score,
    _generate_new_name_from_template,
    _load_packaged_parser,
    _make_variants_for_item,
    _extract_variables,
    _parse_c_or_cpp,
    _split_identifier_subtokens,
    _stable_name_seed,
    normalized_levenshtein,
    rag_da_attack,
    rename_identifiers_ast,
)
from rename_ast import generate_new_name as legacy_generate_new_name  # noqa: E402


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
    def test_packaged_parser_does_not_fall_back_to_a_raw_capsule(self):
        capsule = object()

        class IncompatibleLanguage:
            def __init__(self, value):
                raise TypeError("unsupported capsule API")

        grammar_module = SimpleNamespace(language=lambda: capsule)
        with mock.patch("rag_da.Language", IncompatibleLanguage), mock.patch(
            "builtins.__import__", return_value=grammar_module
        ):
            with self.assertRaisesRegex(RuntimeError, "tree-sitter>=0.23"):
                _load_packaged_parser("c")

    def test_identifier_seed_uses_stable_digest(self):
        self.assertEqual(_stable_name_seed(42, "buffer"), _stable_name_seed(42, "buffer"))
        self.assertNotEqual(_stable_name_seed(42, "buffer"), _stable_name_seed(42, "length"))

    def test_family_mode_can_disable_family_templates(self):
        with mock.patch.dict(os.environ, {"RAG_DA_FAMILY_MODE": "generic"}):
            self.assertEqual(_assign_semantic_family("buffer"), SemanticFamily.GENERIC)
        with mock.patch.dict(os.environ, {"RAG_DA_FAMILY_MODE": "family"}):
            self.assertEqual(_assign_semantic_family("buffer"), SemanticFamily.BUFFER)

    def test_snake_and_camel_identifiers_are_split_into_subtokens(self):
        self.assertEqual(_split_identifier_subtokens("input_buffer_len"), ["input", "buffer", "len"])
        self.assertEqual(_split_identifier_subtokens("inputBufferLen"), ["input", "buffer", "len"])
        self.assertEqual(_split_identifier_subtokens("HTTPBufferSize"), ["http", "buffer", "size"])

    def test_six_semantic_families_follow_subtoken_taxonomy(self):
        examples = {
            "safeBuffer": SemanticFamily.BUFFER,
            "payloadLength": SemanticFamily.LENGTH_SIZE,
            "byteOffset": SemanticFamily.INDEX_OFFSET,
            "nodePtr": SemanticFamily.POINTER,
            "isValid": SemanticFamily.FLAG_STATUS,
            "inputPayload": SemanticFamily.INPUT_DATA,
        }
        for name, expected in examples.items():
            self.assertEqual(_assign_semantic_family(name), expected)

    def test_context_score_can_assign_an_unseen_identifier(self):
        context = {SemanticFamily.POINTER: 2.0}
        self.assertEqual(_assign_semantic_family("opaqueThing", context), SemanticFamily.POINTER)

    def test_unmatched_other_family_is_left_unchanged(self):
        self.assertEqual(_assign_semantic_family("opaqueThing"), SemanticFamily.GENERIC)
        self.assertIsNone(
            _generate_new_name_from_template(
                "opaqueThing",
                SemanticFamily.GENERIC,
                {"opaqueThing"},
                _stable_name_seed(42, "opaqueThing"),
            )
        )

    def test_seed_explores_different_family_templates(self):
        names = {
            _generate_new_name_from_template(
                "buf", SemanticFamily.BUFFER, {"buf"}, _stable_name_seed(seed, "buf")
            )
            for seed in (42, 43, 44)
        }
        self.assertGreaterEqual(len(names), 2)

    def test_non_generic_family_does_not_use_generic_suffixes(self):
        names = {
            _generate_new_name_from_template(
                "buf", SemanticFamily.BUFFER, {"buf"}, _stable_name_seed(seed, "buf")
            )
            for seed in range(20)
        }
        self.assertTrue(names)
        self.assertTrue(
            names
            <= {
                "buf_buf", "tmp_buf", "buf_data", "buf_ptr",
                "data_buf", "safe_buf", "buf_buffer",
            }
        )

    def test_figure_three_candidates_are_reachable(self):
        expected = {
            SemanticFamily.INDEX_OFFSET: {"i_idx", "i_pos", "i_offset"},
            SemanticFamily.BUFFER: {"buf_buf", "buf_data", "buf_ptr"},
            SemanticFamily.LENGTH_SIZE: {"len_count", "len_total", "len_num"},
        }
        for family, names in expected.items():
            generated = {
                template.format(core={
                    SemanticFamily.INDEX_OFFSET: "i",
                    SemanticFamily.BUFFER: "buf",
                    SemanticFamily.LENGTH_SIZE: "len",
                }[family])
                for template in FAMILY_TEMPLATES[family]
            }
            self.assertTrue(names <= generated)

    def test_generated_names_reclassify_to_the_requested_family(self):
        examples = {
            SemanticFamily.BUFFER: "buf",
            SemanticFamily.LENGTH_SIZE: "len",
            SemanticFamily.INDEX_OFFSET: "offset",
            SemanticFamily.POINTER: "ptr",
            SemanticFamily.FLAG_STATUS: "err",
            SemanticFamily.INPUT_DATA: "input",
            SemanticFamily.GENERIC: "value",
        }
        for family, old_name in examples.items():
            for seed in range(20):
                candidate = _generate_new_name_from_template(
                    old_name,
                    family,
                    {old_name},
                    _stable_name_seed(seed, old_name),
                )
                if candidate is not None:
                    self.assertEqual(_assign_semantic_family(candidate), family)

    def test_parser_failure_is_strict_by_default(self):
        code = "int f(int count) { return count + 1; }"
        with mock.patch("rag_da._parse_c_or_cpp", return_value=(None, None)):
            self.assertEqual(rename_identifiers_ast(code, max_ids=1, seed=42), code)

    def test_lexical_fallback_requires_explicit_opt_in(self):
        code = "int f(int count) { return count + 1; }"
        with mock.patch("rag_da._parse_c_or_cpp", return_value=(None, None)):
            renamed = rename_identifiers_ast(
                code,
                max_ids=1,
                seed=42,
                allow_lexical_fallback=True,
            )
        self.assertNotEqual(renamed, code)

    def test_parse_errors_are_skipped_in_strict_mode(self):
        code = "int f(int count) { return count + 1; }"
        fake_tree = mock.Mock()
        fake_tree.root_node = mock.Mock()
        with mock.patch("rag_da._parse_c_or_cpp", return_value=("c", fake_tree)), mock.patch(
            "rag_da._tree_error_score", return_value=1
        ):
            self.assertEqual(rename_identifiers_ast(code, max_ids=1, seed=42), code)

    def test_legacy_generator_delegates_to_canonical_templates(self):
        seed = _stable_name_seed(42, "len")
        expected = _generate_new_name_from_template(
            "len", SemanticFamily.LENGTH_SIZE, {"len"}, seed
        )
        actual = legacy_generate_new_name(
            "len", SemanticFamily.LENGTH_SIZE, {"len"}, seed
        )
        self.assertEqual(actual, expected)
        self.assertTrue(actual.startswith("len_"))

    def test_variant_pool_contains_no_duplicate_code(self):
        item = {
            "code": "int copy(char *buf, int len) { return buf[len - 1]; }",
            "score": 1.0,
        }
        variants = _make_variants_for_item(
            item,
            base_index=0,
            variant_m=3,
            max_ids=2,
            seed=42,
            allow_lexical_fallback=True,
        )
        codes = [variant["code"] for variant in variants]
        self.assertEqual(len(codes), len(set(codes)))
        self.assertGreaterEqual(len(codes), 2)

    def test_diversity_is_incremental_candidate_to_path_average(self):
        candidate = {"code": "int value = 0;"}
        path = [
            {"code": "int value = 0;"},
            {"code": "return buffer[index];"},
        ]
        expected = sum(
            normalized_levenshtein(candidate["code"], prior["code"])
            for prior in path
        ) / len(path)
        self.assertAlmostEqual(_compute_diversity_score(path, candidate), expected)
        self.assertEqual(_compute_diversity_score([], candidate), 0.0)

    def test_cpp_grammar_is_selected_for_cpp_syntax(self):
        language, tree = _parse_c_or_cpp(
            "template <typename T> T pick(T value) { return value; }"
        )
        if tree is None:
            self.skipTest("tree-sitter C/C++ grammars are not installed")
        self.assertEqual(language, "cpp")

    def test_shadowed_bindings_have_disjoint_use_nodes(self):
        code = (
            "int f(int count) { int total = count; "
            "{ int count = 7; total += count; } return count + total; }"
        )
        _language, tree = _parse_c_or_cpp(code)
        if tree is None:
            self.skipTest("tree-sitter C/C++ grammars are not installed")
        bindings = [var for var in _extract_variables(tree.root_node) if var.name == "count"]
        self.assertEqual(len(bindings), 2)
        bindings.sort(key=lambda var: var.decl_node.start_byte)
        self.assertEqual(len(bindings[0].use_nodes), 2)
        self.assertEqual(len(bindings[1].use_nodes), 1)
        self.assertTrue(
            set(node.start_byte for node in bindings[0].use_nodes).isdisjoint(
                node.start_byte for node in bindings[1].use_nodes
            )
        )

    def test_renaming_outer_binding_does_not_capture_shadowed_name(self):
        code = (
            "int f(int count) { int total = count; "
            "{ int count = 7; total += count; } return count + total; }"
        )
        _language, tree = _parse_c_or_cpp(code)
        if tree is None:
            self.skipTest("tree-sitter C/C++ grammars are not installed")
        renamed = rename_identifiers_ast(code, max_ids=1, seed=42)
        self.assertIn("int count = 7", renamed)
        self.assertIn("total += count", renamed)
        self.assertNotEqual(renamed, code)

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
        self.assertEqual([int(d["_base_index"]) for d in out], [0, 1, 2])

    def test_beam_preserves_retrieval_order(self):
        demos = _toy_demos(5)
        out = rag_da_attack(
            fixed_demos=demos,
            k=5,
            seed=11,
            variant_score_fn=lambda variant, original: float(original["score"]),
        )
        self.assertEqual([int(d["_base_index"]) for d in out], [0, 1, 2, 3, 4])
        self.assertEqual([d["cve_id"] for d in out], [d["cve_id"] for d in demos])


if __name__ == "__main__":
    unittest.main(verbosity=2)
