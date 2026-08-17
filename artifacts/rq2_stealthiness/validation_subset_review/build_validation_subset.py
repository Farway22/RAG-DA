"""Build an independent behavior-check subset from historical pairs.

The filter intentionally favors precision over coverage.  It keeps only pairs
that can be represented as one collision-free, token-consistent identifier
substitution and whose source identifier has a parameter/local declaration.
Canonical-generator conformance is tested separately. This subset supports
manual review and executable behavior spot checks of historical pairs.
"""

from __future__ import annotations

import csv
import argparse
import json
import re
import sys
from pathlib import Path


OUT_DIR = Path(__file__).resolve().parent
OUT_JSONL = OUT_DIR / "validation_subset_candidates.jsonl"
OUT_CSV = OUT_DIR / "validation_subset_audit.csv"
OUT_MARKDOWN = OUT_DIR / "validation_subset_review.md"
TARGET_SIZE = 15

_assign_semantic_family = None
_split_identifier_subtokens = None
SemanticFamily = None
SEMANTIC_FAMILIES = None

# These transformations are mechanically consistent but less natural in an
# illustrative subset: `id -> res` disconnects the parameter from
# the function's `by_id` wording, and `len -> sum` shifts the lexical cue from
# length to accumulation.  They remain in the source artifact and are excluded
# only from this illustrative subset.
MANUAL_SEMANTIC_EXCLUSIONS = {
    (8, 7),
    (7, 0),
    (7, 25),
    # `write_cr4` executes a privileged instruction and is unsuitable for a
    # user-mode executable validation suite.
    (679, 3),
    # Uses a C99 static array-parameter qualifier unsupported by MSVC.
    (492, 3),
}

# The review subset requires an explicit lexical cue from the canonical
# Snake/Camel subtoken vocabulary.
FAMILY_LEXICONS = {}
EXACT_GENERIC_NAMES = set()

# Interpretable aliases are deliberately narrower than the algorithm's broad
# families and retain examples with an immediately clear lexical relationship.
INTERPRETABLE_ALIAS_GROUPS = [
    {"len", "length", "size"},
    {"count", "counter", "cnt", "num", "number", "total"},
    {"idx", "index"},
    {"offset", "pos", "position", "cursor", "iter", "iterator"},
    {"arr", "array", "vec", "vector"},
    {"buf", "buffer", "data", "mem", "memory", "ptr", "pointer"},
    {"error", "err"},
    {"success", "ok", "valid"},
    {"status", "state", "flag"},
    {"value", "val", "var"},
    {"result", "res", "ret", "return"},
    {"temp", "tmp"},
    {"object", "obj"},
    {"item", "entry", "node"},
]


TOKEN_RE = re.compile(
    r"(?P<comment>//[^\n]*|/\*.*?\*/)"
    r"|(?P<string>L?'(?:\\.|[^'\\])*'|L?\"(?:\\.|[^\"\\])*\")"
    r"|(?P<identifier>[A-Za-z_]\w*)"
    r"|(?P<number>(?:0[xX][0-9A-Fa-f]+)|(?:\d+(?:\.\d*)?))"
    r"|(?P<operator>::|->|==|!=|<=|>=|\+\+|--|&&|\|\||<<|>>|[-+*/%&|^~!<>=?:;,.(){}\[\]])",
    re.DOTALL,
)

KEYWORDS = {
    "alignas", "alignof", "asm", "auto", "bool", "break", "case", "catch",
    "char", "class", "const", "constexpr", "continue", "default", "delete",
    "do", "double", "else", "enum", "explicit", "extern", "false", "float",
    "for", "friend", "goto", "if", "inline", "int", "long", "namespace",
    "new", "noexcept", "nullptr", "operator", "private", "protected", "public",
    "register", "return", "short", "signed", "sizeof", "static", "struct",
    "switch", "template", "this", "throw", "true", "try", "typedef", "typename",
    "union", "unsigned", "using", "virtual", "void", "volatile", "wchar_t", "while",
}

TYPE_PREFIX = re.compile(
    r"(?:^|[;{(,])\s*"
    r"(?:const\s+|volatile\s+|static\s+|register\s+|unsigned\s+|signed\s+|long\s+|short\s+)*"
    r"(?:struct\s+[A-Za-z_]\w*|enum\s+[A-Za-z_]\w*|union\s+[A-Za-z_]\w*|"
    r"[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)"
    r"(?:\s*[*&]+)?\s+"
    r"{name}\b"
)


def tokens(code: str) -> list[tuple[str, str]]:
    return [
        (match.lastgroup or "", match.group(0))
        for match in TOKEN_RE.finditer(code)
        if match.lastgroup != "comment"
    ]


def balanced(code: str) -> bool:
    return all(
        code.count(left) == code.count(right)
        for left, right in (("(", ")"), ("[", "]"), ("{", "}"))
    )


def has_declaration(code: str, name: str) -> bool:
    pattern = TYPE_PREFIX.pattern.replace("{name}", re.escape(name))
    return bool(re.search(pattern, code))


def has_high_confidence_family_cue(name: str, family: str) -> bool:
    """Require an exact family cue after canonical Snake/Camel decomposition."""
    lowered = name.lower()
    if family == SemanticFamily.GENERIC.value:
        return lowered in EXACT_GENERIC_NAMES
    return any(token in FAMILY_LEXICONS[family] for token in _split_identifier_subtokens(name))


def shares_reviewer_alias_group(old: str, new: str) -> bool:
    old_lower = old.lower()
    new_lower = new.lower()
    return any(old_lower in group and new_lower in group for group in INTERPRETABLE_ALIAS_GROUPS)


def configure_classifier(repo_src: Path) -> None:
    """Load the semantic-family implementation from the repository under review."""
    global _assign_semantic_family, _split_identifier_subtokens
    global SemanticFamily, SEMANTIC_FAMILIES, FAMILY_LEXICONS, EXACT_GENERIC_NAMES

    resolved = repo_src.resolve()
    if not (resolved / "rag_da.py").is_file():
        raise FileNotFoundError(f"rag_da.py was not found under --repo-src: {resolved}")
    sys.path.insert(0, str(resolved))
    from rag_da import (  # type: ignore
        SEMANTIC_FAMILIES as released_families,
        SemanticFamily as released_family_enum,
        _assign_semantic_family as released_assigner,
        _split_identifier_subtokens as released_splitter,
    )

    _assign_semantic_family = released_assigner
    _split_identifier_subtokens = released_splitter
    SemanticFamily = released_family_enum
    SEMANTIC_FAMILIES = released_families
    FAMILY_LEXICONS = {
        family.value: {keyword.lower() for keyword in keywords}
        for family, keywords in SEMANTIC_FAMILIES.items()
    }
    EXACT_GENERIC_NAMES = set(SEMANTIC_FAMILIES[SemanticFamily.GENERIC])


def analyze_pair(clean: str, adversarial: str) -> dict | None:
    if not clean or clean == adversarial or not (150 <= len(clean) <= 1500):
        return None
    if not balanced(clean) or not balanced(adversarial):
        return None

    clean_tokens = tokens(clean)
    adv_tokens = tokens(adversarial)
    if len(clean_tokens) != len(adv_tokens):
        return None

    changes: list[tuple[int, str, str]] = []
    for index, (left, right) in enumerate(zip(clean_tokens, adv_tokens)):
        if left == right:
            continue
        if left[0] != "identifier" or right[0] != "identifier":
            return None
        changes.append((index, left[1], right[1]))
    if not changes:
        return None

    mappings = {(old, new) for _, old, new in changes}
    if len(mappings) != 1:
        return None
    old, new = next(iter(mappings))
    if old in KEYWORDS or new in KEYWORDS or old == new:
        return None

    old_family = _assign_semantic_family(old).value
    new_family = _assign_semantic_family(new).value
    if old_family != new_family:
        return None
    if not has_high_confidence_family_cue(old, old_family):
        return None
    if not has_high_confidence_family_cue(new, new_family):
        return None
    if not shares_reviewer_alias_group(old, new):
        return None

    clean_identifiers = {value for kind, value in clean_tokens if kind == "identifier"}
    if new in clean_identifiers:
        return None
    if not has_declaration(clean, old):
        return None

    # In these records the first parenthesis opens the function parameter list.
    # Any changed identifier before it is part of the return type, qualifier, or
    # function name rather than a parameter/local variable.
    first_lparen = next(
        (index for index, (_, value) in enumerate(clean_tokens) if value == "("),
        None,
    )
    if first_lparen is None or any(index < first_lparen for index, _, _ in changes):
        return None

    # Exclude scope/member/type/function positions.  A retained identifier may
    # be followed by '(' only when all occurrences are ordinary data uses; the
    # declaration check above supplies the positive parameter/local evidence.
    for index, _, _ in changes:
        previous = clean_tokens[index - 1][1] if index else ""
        following = clean_tokens[index + 1][1] if index + 1 < len(clean_tokens) else ""
        if previous in {"::", "->", ".", "struct", "class", "enum", "union", "typedef", "using"}:
            return None
        if following == "::":
            return None

    old_count = sum(1 for kind, value in clean_tokens if kind == "identifier" and value == old)
    new_count = sum(1 for kind, value in adv_tokens if kind == "identifier" and value == new)
    if old_count != len(changes) or new_count != len(changes):
        return None

    return {
        "old_identifier": old,
        "new_identifier": new,
        "old_family": old_family,
        "new_family": new_family,
        "replacement_count": len(changes),
        "clean_chars": len(clean),
        "adversarial_chars": len(adversarial),
        "screening_status": "included_in_executable_validation",
        "screening_basis": (
            "single collision-free token-consistent substitution; "
            "parameter/local declaration detected; balanced delimiters; "
            "no member, scope, type-keyword, or class-qualifier position changed"
        ),
    }


def build_subset(source: Path, output_dir: Path, target_size: int) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    out_jsonl = output_dir / OUT_JSONL.name
    out_csv = output_dir / OUT_CSV.name
    out_markdown = output_dir / OUT_MARKDOWN.name

    candidates: list[dict] = []
    with source.open("r", encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            for demo_index, (clean_demo, adv_demo) in enumerate(
                zip(record.get("clean_demos", []), record.get("adv_demos", []))
            ):
                clean = clean_demo.get("code", "") or ""
                adversarial = adv_demo.get("code", "") or ""
                analysis = analyze_pair(clean, adversarial)
                if analysis is None:
                    continue
                if (int(record["sample_id"]), demo_index) in MANUAL_SEMANTIC_EXCLUSIONS:
                    continue
                candidates.append(
                    {
                        "sample_id": int(record["sample_id"]),
                        "demo_index": demo_index,
                        **analysis,
                        "clean_code": clean,
                        "adversarial_code": adversarial,
                    }
                )

    # Deterministic diversity: shortest safe-looking example from each source
    # sample first, then fill by length while limiting any source sample to 3.
    candidates.sort(key=lambda item: (item["clean_chars"], item["sample_id"], item["demo_index"]))
    selected: list[dict] = []
    per_sample: dict[int, int] = {}
    used_old_identifiers: set[str] = set()
    for candidate in candidates:
        sample_id = candidate["sample_id"]
        if per_sample.get(sample_id, 0) >= 3:
            continue
        if candidate["old_identifier"] in used_old_identifiers:
            continue
        selected.append(candidate)
        per_sample[sample_id] = per_sample.get(sample_id, 0) + 1
        used_old_identifiers.add(candidate["old_identifier"])
        if len(selected) == target_size:
            break

    if len(selected) < target_size:
        raise RuntimeError(f"Only {len(selected)} conservative candidates found")

    with out_jsonl.open("w", encoding="utf-8") as handle:
        for item in selected:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")

    columns = [
        "review_id", "sample_id", "demo_index", "old_identifier", "new_identifier",
        "old_family", "new_family",
        "replacement_count", "clean_chars", "adversarial_chars", "screening_status",
        "review_decision", "review_notes",
    ]
    with out_csv.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for review_id, item in enumerate(selected, 1):
            writer.writerow(
                {
                    "review_id": review_id,
                    **{key: item[key] for key in columns if key in item},
                    "review_decision": "included",
                    "review_notes": "Passed conservative screening and included in the executable paired-transformation suite.",
                }
            )

    with out_markdown.open("w", encoding="utf-8") as handle:
        handle.write("# High-Confidence Paired Transformation Subset\n\n")
        handle.write(
            f"This is a {target_size}-pair high-confidence candidate subset extracted "
            "from the existing full `full1208_ast_demos.jsonl` artifact. These pairs are "
            "the inputs to the companion executable spot-check suite.\n\n"
        )
        handle.write(
            "This historical subset evaluates compilation and observed behavior for "
            "concrete token-consistent substitutions. Conformance of the current "
            "candidate generator is evaluated separately in "
            "`tests/test_rag_da_algorithm.py` and "
            "`../canonical_generator_review/`.\n\n"
        )
        handle.write(
            "Automated exclusions cover type/class/function/member renaming, multiple "
            "simultaneous mappings, destination-name collisions, unbalanced delimiters, "
            "and transformations without a detected parameter/local declaration. Each "
            "retained pair received a preliminary visual check for consistent uses.\n\n"
        )
        handle.write(
            "The stored family labels record the historical screening run. The subset "
            "uses each source identifier at most once, avoiding duplicate-name/different-"
            "target ambiguity. Runtime behavior is evaluated by the paired executable "
            "checks rather than inferred from lexical changes alone.\n\n"
        )
        handle.write(
            "To keep this illustrative subset interpretable, selection additionally "
            "requires an exact family-vocabulary match after the same Snake/Camel "
            "subtoken decomposition used by the canonical generator. Generic historical "
            "pairs are retained only when both names occur in its explicit generic "
            "review vocabulary.\n\n"
        )
        handle.write(
            "The final alias screen retains immediately interpretable mappings such as "
            "`result/res/ret`, `size/length/len`, and `idx/index`, while excluding "
            "broad-family edge cases such as `error/success`.\n\n"
        )
        handle.write("| ID | Source | Mapping | Historical family screen | Uses | Clean chars | Status |\n")
        handle.write("|---:|---|---|---|---:|---:|---|\n")
        for review_id, item in enumerate(selected, 1):
            handle.write(
                f"| {review_id} | `{item['sample_id']}/{item['demo_index']}` | "
                f"`{item['old_identifier']} -> {item['new_identifier']}` | "
                f"{item['old_family']} -> {item['new_family']} | "
                f"{item['replacement_count']} | {item['clean_chars']} | "
                "included in executable validation |\n"
            )
        handle.write("\n")
        for review_id, item in enumerate(selected, 1):
            handle.write(
                f"## {review_id:02d}. sample {item['sample_id']}, demo {item['demo_index']} "
                f"(`{item['old_identifier']} -> {item['new_identifier']}`)\n\n"
            )
            handle.write("Clean:\n\n```cpp\n")
            handle.write(item["clean_code"].strip() + "\n")
            handle.write("```\n\nAdversarial:\n\n```cpp\n")
            handle.write(item["adversarial_code"].strip() + "\n")
            handle.write("```\n\n")

    print(f"eligible={len(candidates)} selected={len(selected)}")
    for review_id, item in enumerate(selected, 1):
        print(
            f"{review_id:02d} sample={item['sample_id']} demo={item['demo_index']} "
            f"{item['old_identifier']}->{item['new_identifier']} "
            f"uses={item['replacement_count']} chars={item['clean_chars']}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Path to the paired clean/adversarial JSONL artifact.",
    )
    parser.add_argument(
        "--repo-src",
        type=Path,
        default=Path(__file__).resolve().parents[3] / "src",
        help="Repository src directory containing rag_da.py (default: ../src).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=OUT_DIR,
        help="Directory for the JSONL, CSV, and Markdown review files.",
    )
    parser.add_argument("--target-size", type=int, default=TARGET_SIZE)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configure_classifier(args.repo_src)
    build_subset(args.input.resolve(), args.output_dir.resolve(), args.target_size)


if __name__ == "__main__":
    main()
