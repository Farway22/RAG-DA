"""Build executable spot-check pairs with the released canonical generator."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SRC = ROOT / "src"
INPUT = HERE.parent / "validation_subset_review" / "validation_subset_candidates.jsonl"
OUTPUT = HERE / "canonical_generator_pairs.jsonl"

EXTRA_CLEAN_RECORD = {
    "sample_id": 33,
    "demo_index": 19,
    "clean_code": (
        "static inline int32_t unzigzag32(uint32_t v) "
        "{ return (int32_t)((v >> 1) ^ (~(v & 1) + 1)); }"
    ),
}

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from rag_da import (  # noqa: E402
    _assign_semantic_family,
    _extract_variables,
    _parse_c_or_cpp,
    rename_identifiers_ast,
)


IDENTIFIER = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


def changed_identifier(clean: str, adversarial: str) -> tuple[str, str]:
    clean_counts = Counter(IDENTIFIER.findall(clean))
    adversarial_counts = Counter(IDENTIFIER.findall(adversarial))
    removed = [name for name, count in clean_counts.items() if count > adversarial_counts[name]]
    added = [name for name, count in adversarial_counts.items() if count > clean_counts[name]]
    if len(removed) != 1 or len(added) != 1:
        raise RuntimeError(f"Expected one renamed binding, found {removed!r} -> {added!r}")
    return removed[0], added[0]


def contextual_family(code: str, identifier: str):
    _language, tree = _parse_c_or_cpp(code)
    if tree is None:
        return _assign_semantic_family(identifier)
    matches = [var.family for var in _extract_variables(tree.root_node) if var.name == identifier]
    return matches[0] if matches else _assign_semantic_family(identifier)


def main() -> None:
    records = []
    sources = [json.loads(line) for line in INPUT.read_text(encoding="utf-8").splitlines()]
    # The historical 124/6 snippet contains an undefined parser macro in its
    # raw form, so strict mode correctly declines to edit it. Replace that case
    # with a parser-clean snippet from the same frozen full artifact.
    sources = [
        source
        for source in sources
        if (int(source["sample_id"]), int(source["demo_index"])) != (124, 6)
    ]
    sources.append(EXTRA_CLEAN_RECORD)

    for source in sources:
        clean = source["clean_code"]
        adversarial = rename_identifiers_ast(
            clean,
            max_ids=1,
            seed=42,
            allow_lexical_fallback=False,
        )
        if adversarial == clean:
            raise RuntimeError(
                f"Canonical AST generator produced no edit for "
                f"{source['sample_id']}/{source['demo_index']}"
            )
        old_name, new_name = changed_identifier(clean, adversarial)
        records.append(
            {
                "sample_id": source["sample_id"],
                "demo_index": source["demo_index"],
                "old_identifier": old_name,
                "new_identifier": new_name,
                "old_family": contextual_family(clean, old_name).value,
                "new_family": _assign_semantic_family(new_name).value,
                "generator": "src/rag_da.py::rename_identifiers_ast",
                "generator_seed": 42,
                "max_ids": 1,
                "allow_lexical_fallback": False,
                "clean_code": clean,
                "adversarial_code": adversarial,
            }
        )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        "\n".join(json.dumps(record, ensure_ascii=False) for record in records) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(records)} canonical generator pairs to {OUTPUT}")


if __name__ == "__main__":
    main()
