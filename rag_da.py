"""Core RAG-DA implementation.

This module is the importable version of the public RAG-DA attack code.  It
keeps the attack constrained to demonstration-code identifier renaming, then
selects variants with a beam-search objective that can use recomputed
retrieval similarity for each renamed variant.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import os
import random
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from tree_sitter import Language, Parser


class VariableRole(Enum):
    PARAMETER = "parameter"
    RESOURCE = "resource"
    LOCAL = "local"
    LOOP_INDEX = "loop_index"
    FIELD = "field"


class SemanticFamily(Enum):
    COUNTER = "counter"
    BUFFER = "buffer"
    INDEX = "index"
    FLAG = "flag"
    GENERIC = "generic"


SEMANTIC_FAMILIES = {
    SemanticFamily.COUNTER: [
        "count",
        "counter",
        "total",
        "num",
        "cnt",
        "number",
        "n",
        "size",
        "length",
        "len",
        "amount",
        "sum",
        "acc",
    ],
    SemanticFamily.BUFFER: [
        "buf",
        "buffer",
        "data",
        "ptr",
        "pointer",
        "p",
        "mem",
        "memory",
        "array",
        "arr",
        "list",
        "vec",
        "vector",
    ],
    SemanticFamily.INDEX: [
        "idx",
        "index",
        "i",
        "j",
        "k",
        "pos",
        "position",
        "offset",
        "ind",
        "cursor",
        "iter",
        "iterator",
    ],
    SemanticFamily.FLAG: [
        "flag",
        "is_*",
        "has_*",
        "enable",
        "disable",
        "active",
        "valid",
        "ok",
        "success",
        "error",
        "err",
        "status",
    ],
    SemanticFamily.GENERIC: [
        "value",
        "val",
        "item",
        "obj",
        "object",
        "entry",
        "node",
        "result",
        "res",
        "ret",
        "return",
        "tmp",
        "temp",
        "var",
    ],
}

FAMILY_TEMPLATES = {
    SemanticFamily.COUNTER: ["{core}", "{core}_count", "{core}_total", "{core}_num", "{core}_cnt"],
    SemanticFamily.BUFFER: ["{core}", "{core}_buf", "{core}_data", "{core}_ptr", "{core}_mem"],
    SemanticFamily.INDEX: ["{core}", "{core}_idx", "{core}_pos", "{core}_offset", "{core}_ind"],
    SemanticFamily.FLAG: ["{core}", "is_{core}", "has_{core}", "{core}_flag", "{core}_status"],
    SemanticFamily.GENERIC: ["{core}", "{core}_val", "{core}_item", "{core}_tmp", "{core}_var"],
}

ROLE_WEIGHTS = {
    VariableRole.PARAMETER: 100.0,
    VariableRole.RESOURCE: 80.0,
    VariableRole.FIELD: 70.0,
    VariableRole.LOCAL: 50.0,
    VariableRole.LOOP_INDEX: 30.0,
}

ROLE_QUOTAS = {
    VariableRole.PARAMETER: (0, 3),
    VariableRole.RESOURCE: (0, 2),
    VariableRole.LOCAL: (0, 5),
    VariableRole.LOOP_INDEX: (0, 1),
    VariableRole.FIELD: (0, 2),
}

UNSAFE_PATTERNS = ["strcpy", "strcat", "sprintf", "gets", "scanf", "memcpy", "memmove", "memset"]


@dataclass
class VariableInfo:
    name: str
    role: VariableRole
    family: SemanticFamily
    usage_count: int
    importance_score: float
    decl_node: Optional[Any] = None
    use_nodes: Optional[List[Any]] = None

    def __post_init__(self) -> None:
        if self.use_nodes is None:
            self.use_nodes = []


VariantScoreFn = Callable[[Dict[str, Any], Dict[str, Any]], float]

_TS_LANGUAGE = None
_TS_PARSER = None


def _init_tree_sitter():
    global _TS_LANGUAGE, _TS_PARSER
    if _TS_LANGUAGE is not None:
        return _TS_LANGUAGE, _TS_PARSER

    paths = ["build/my-languages.so", "build/my-languages.dll"]
    for lib_path in paths:
        if os.path.exists(lib_path):
            try:
                _TS_LANGUAGE = Language(lib_path, "c")
                _TS_PARSER = Parser()
                if hasattr(_TS_PARSER, "set_language"):
                    _TS_PARSER.set_language(_TS_LANGUAGE)
                else:
                    _TS_PARSER.language = _TS_LANGUAGE
                return _TS_LANGUAGE, _TS_PARSER
            except Exception:
                continue
    return None, None


def _assign_semantic_family(name: str) -> SemanticFamily:
    name_lower = name.lower()
    for family, keywords in SEMANTIC_FAMILIES.items():
        for kw in keywords:
            stem = kw.replace("*", "")
            if name_lower == stem or name_lower.startswith(stem) or stem in name_lower:
                return family
    return SemanticFamily.GENERIC


def _is_pointer_type(type_hint: Optional[str]) -> bool:
    return bool(type_hint and ("*" in type_hint or "ptr" in type_hint.lower()))


def _is_resource_type(type_hint: Optional[str]) -> bool:
    if not type_hint:
        return False
    return any(kw in type_hint.lower() for kw in ["file", "socket", "handle", "fd", "resource"])


def _identify_variable_role(var_name: str, node: Any, type_hint: Optional[str]) -> VariableRole:
    parent = node.parent
    while parent is not None:
        if parent.type == "parameter_list":
            return VariableRole.PARAMETER
        if parent.type == "function_definition":
            break
        parent = parent.parent

    if _is_resource_type(type_hint) or (_is_pointer_type(type_hint) and "buf" in var_name.lower()):
        return VariableRole.RESOURCE

    parent = node.parent
    while parent is not None:
        if parent.type in ["for_statement", "while_statement"]:
            if var_name in parent.text.decode("utf8", errors="ignore"):
                return VariableRole.LOOP_INDEX
        if parent.type == "function_definition":
            break
        parent = parent.parent

    parent = node.parent
    while parent is not None:
        if parent.type in ["field_declaration", "field_declaration_list"]:
            return VariableRole.FIELD
        if parent.type == "function_definition":
            break
        parent = parent.parent

    return VariableRole.LOCAL


def _extract_type_hint(node: Any) -> Optional[str]:
    parent = node.parent
    while parent:
        if parent.type == "declaration":
            parts = [
                child.text.decode("utf8", errors="ignore")
                for child in parent.children
                if child.type in ["primitive_type", "type_identifier", "sized_type_specifier"]
            ]
            return " ".join(parts) if parts else None
        parent = parent.parent
    return None


def _count_variable_usage(var_name: str, ast_root: Any) -> int:
    count = 0

    def traverse(node: Any) -> None:
        nonlocal count
        if node.type == "identifier" and node.text.decode("utf8", errors="ignore") == var_name:
            parent = node.parent
            if parent and parent.type != "function_declarator":
                count += 1
        for child in node.children:
            traverse(child)

    traverse(ast_root)
    return count


def _find_vuln_proximity(var_name: str, ast_root: Any) -> float:
    vuln_score = 0.0

    def traverse(node: Any) -> None:
        nonlocal vuln_score
        node_text = node.text.decode("utf8", errors="ignore")
        if node.type == "call_expression" and any(pattern in node_text for pattern in UNSAFE_PATTERNS):
            if var_name in node_text:
                vuln_score += 10.0
        for child in node.children:
            traverse(child)

    traverse(ast_root)
    return vuln_score


def _collect_use_nodes(var_name: str, decl_node: Any, ast_root: Any) -> List[Any]:
    use_nodes = []
    decl_scope = None
    parent = decl_node.parent
    while parent:
        if parent.type == "function_definition":
            decl_scope = parent
            break
        parent = parent.parent

    def traverse(node: Any, in_scope: bool = False) -> None:
        if node == decl_scope:
            in_scope = True
        if in_scope and node.type == "identifier" and node.text.decode("utf8", errors="ignore") == var_name:
            if node != decl_node and node.parent and node.parent.type != "function_declarator":
                use_nodes.append(node)
        for child in node.children:
            traverse(child, in_scope)

    traverse(ast_root)
    return use_nodes


def _extract_variables(ast_root: Any) -> List[VariableInfo]:
    variables = []
    var_map = {}

    def first_identifier(node: Optional[Any]) -> Optional[Any]:
        if node is None:
            return None
        if node.type == "identifier":
            return node
        for child in node.children:
            found = first_identifier(child)
            if found is not None:
                return found
        return None

    def traverse(node: Any) -> None:
        var_name = None
        decl_node = None

        if node.type == "parameter_declaration":
            declarator = node.child_by_field_name("declarator")
            decl_node = first_identifier(declarator)
        elif node.type in ["init_declarator", "field_declaration"]:
            decl_node = first_identifier(node.child_by_field_name("declarator") or node)

        if decl_node is not None:
            var_name = decl_node.text.decode("utf8", errors="ignore")

        if var_name and var_name not in var_map:
            type_hint = _extract_type_hint(node)
            role = _identify_variable_role(var_name, decl_node, type_hint)
            family = _assign_semantic_family(var_name)
            usage_count = _count_variable_usage(var_name, ast_root)
            vuln_prox = _find_vuln_proximity(var_name, ast_root)
            role_weight = ROLE_WEIGHTS.get(role, 50.0)
            freq_score = min(usage_count * 5.0, 50.0)
            var = VariableInfo(
                name=var_name,
                role=role,
                family=family,
                usage_count=usage_count,
                importance_score=role_weight + freq_score + vuln_prox,
                decl_node=decl_node,
                use_nodes=_collect_use_nodes(var_name, decl_node, ast_root),
            )
            variables.append(var)
            var_map[var_name] = var

        for child in node.children:
            traverse(child)

    traverse(ast_root)
    return variables


def _select_variables_with_quota(variables: List[VariableInfo], max_ids: int) -> List[VariableInfo]:
    selected = []
    role_counts = {role: 0 for role in VariableRole}
    for var in sorted(variables, key=lambda v: v.importance_score, reverse=True):
        if len(selected) >= max_ids:
            break
        _min_quota, max_quota = ROLE_QUOTAS[var.role]
        if role_counts[var.role] < max_quota:
            selected.append(var)
            role_counts[var.role] += 1
    return selected


def _generate_new_name_from_template(
    old_name: str,
    family: SemanticFamily,
    existing: Set[str],
    seed: int,
) -> Optional[str]:
    templates = FAMILY_TEMPLATES[family]
    core = old_name.split("_")[0] if "_" in old_name else old_name

    for template in templates:
        candidate = template.format(core=core)
        if candidate.lower() != old_name.lower() and candidate not in existing:
            return candidate

    rnd = random.Random(seed)
    suffixes = ["tmp", "val", "var", "item"]
    rnd.shuffle(suffixes)
    for suffix in suffixes:
        candidate = f"{core}_{suffix}"
        if candidate.lower() != old_name.lower() and candidate not in existing:
            return candidate
    return None


def _apply_ast_renaming(code: str, id_map: Dict[str, str], var_info_map: Dict[str, VariableInfo]) -> str:
    code_bytes = bytearray(code.encode("utf-8"))
    replacements = []

    for old_name, new_name in id_map.items():
        var_info = var_info_map.get(old_name)
        if var_info is None:
            continue
        nodes = []
        if var_info.decl_node:
            nodes.append(var_info.decl_node)
        nodes.extend(var_info.use_nodes or [])
        for node in nodes:
            replacements.append((node.start_byte, node.end_byte, new_name))

    replacements.sort(key=lambda x: x[0], reverse=True)
    for start_byte, end_byte, new_name in replacements:
        code_bytes[start_byte:end_byte] = new_name.encode("utf-8")

    return code_bytes.decode("utf-8")


_C_LIKE_KEYWORDS = {
    "auto",
    "break",
    "case",
    "char",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extern",
    "float",
    "for",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "register",
    "restrict",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "struct",
    "switch",
    "typedef",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
}


def _collect_identifiers_lexical(code: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for token in __import__("re").findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", code):
        if token not in _C_LIKE_KEYWORDS and not token.isupper():
            counts[token] = counts.get(token, 0) + 1
    return counts


def _apply_identifier_mapping_lexical(code: str, id_map: Dict[str, str]) -> str:
    if not id_map:
        return code

    import re

    pattern = re.compile(r"\b(" + "|".join(re.escape(k) for k in sorted(id_map, key=len, reverse=True)) + r")\b")
    return pattern.sub(lambda match: id_map.get(match.group(1), match.group(1)), code)


def _rename_identifiers_lexical(code: str, max_ids: int, seed: int) -> str:
    counts = _collect_identifiers_lexical(code)
    if not counts:
        return code

    existing = set(counts)
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    id_map = {}
    for old_name, _count in ranked[:max_ids]:
        family = _assign_semantic_family(old_name)
        new_name = _generate_new_name_from_template(old_name, family, existing, seed + hash(old_name))
        if new_name:
            id_map[old_name] = new_name
            existing.add(new_name)

    return _apply_identifier_mapping_lexical(code, id_map)


def rename_identifiers_ast(code: str, max_ids: int = 2, seed: int = 42) -> str:
    """Rename selected C/C++ identifiers while preserving scope-level semantics."""
    if not code or not code.strip():
        return code

    _lang, parser = _init_tree_sitter()
    if parser is None:
        return _rename_identifiers_lexical(code, max_ids=max_ids, seed=seed)

    try:
        tree = parser.parse(code.encode("utf-8"))
        variables = _extract_variables(tree.root_node)
        selected = _select_variables_with_quota(variables, max_ids)
        if not selected:
            return code

        var_info_map = {v.name: v for v in variables}
        existing = set(var_info_map)
        id_map = {}
        for var in selected:
            new_name = _generate_new_name_from_template(var.name, var.family, existing, seed + hash(var.name))
            if new_name:
                id_map[var.name] = new_name
                existing.add(new_name)

        return _apply_ast_renaming(code, id_map, var_info_map) if id_map else code
    except Exception:
        return _rename_identifiers_lexical(code, max_ids=max_ids, seed=seed)


def _code_tokens(text: str) -> List[str]:
    import re

    return re.findall(r"[A-Za-z_][A-Za-z0-9_]*|\d+|[^\sA-Za-z0-9_]", text or "")


def normalized_levenshtein(a: str, b: str) -> float:
    """Return token-level Levenshtein distance normalized to [0, 1]."""
    ta = _code_tokens(a)
    tb = _code_tokens(b)
    if ta == tb:
        return 0.0
    if not ta:
        return 1.0 if tb else 0.0
    if not tb:
        return 1.0

    prev = list(range(len(tb) + 1))
    for i, ca in enumerate(ta, 1):
        curr = [i]
        for j, cb in enumerate(tb, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1] / max(len(ta), len(tb))


def _compute_diversity_score(demos: List[Dict[str, Any]]) -> float:
    if len(demos) < 2:
        return 0.0
    total_dist = 0.0
    count = 0
    for i in range(len(demos)):
        for j in range(i + 1, len(demos)):
            total_dist += normalized_levenshtein(demos[i].get("code", ""), demos[j].get("code", ""))
            count += 1
    return total_dist / count if count else 0.0


def _make_variants_for_item(
    item: Dict[str, Any],
    base_index: int,
    variant_m: int,
    max_ids: int,
    seed: int,
) -> List[Dict[str, Any]]:
    variants = []
    original_code = item.get("code", "") or ""

    v0 = dict(item)
    v0["_base_index"] = base_index
    v0["_variant_index"] = 0
    v0["_is_edited"] = 0
    variants.append(v0)

    for i in range(variant_m - 1):
        v = dict(item)
        try:
            v["code"] = rename_identifiers_ast(original_code, max_ids=max_ids, seed=seed + i)
        except Exception:
            v["code"] = original_code
        v["_base_index"] = base_index
        v["_variant_index"] = i + 1
        v["_is_edited"] = 1 if v["code"] != original_code else 0
        variants.append(v)

    return variants


def _variant_similarity_score(
    variant: Dict[str, Any],
    original: Dict[str, Any],
    score_fn: Optional[VariantScoreFn],
) -> float:
    if score_fn is not None:
        score = float(score_fn(variant, original))
        variant["_score_recomputed"] = score
        return score
    variant["_score_recomputed"] = float(variant.get("score", 0.0))
    return float(variant.get("score", 0.0))


def select_beam_variant_topk(
    fixed_demos: List[Dict[str, Any]],
    k: int,
    beam_width: int = 8,
    variant_m: int = 3,
    max_ids: int = 1,
    seed: int = 42,
    w_sim: float = 1.0,
    diversity_lambda: float = 0.1,
    edit_lambda: float = 0.0,
    variant_score_fn: Optional[VariantScoreFn] = None,
) -> List[Dict[str, Any]]:
    """Select adversarial demonstration variants with beam search.

    ``variant_score_fn`` should recompute retrieval similarity for the renamed
    variant when embeddings/indexes are available.  If omitted, the function
    falls back to each candidate's stored retriever score and records that score
    in ``_score_recomputed`` for transparency.
    """
    if k <= 0 or not fixed_demos:
        return []

    n = len(fixed_demos)
    all_variants = [
        _make_variants_for_item(base, base_index=i, variant_m=max(1, variant_m), max_ids=max_ids, seed=seed)
        for i, base in enumerate(fixed_demos)
    ]

    BeamState = Tuple[float, Tuple[int, ...], List[Dict[str, Any]]]
    beam: List[BeamState] = [(0.0, tuple(), [])]

    for _step in range(min(k, n)):
        next_beam: List[BeamState] = []
        for score_so_far, chosen_indices, chosen_demos in beam:
            for di in range(n):
                if di in chosen_indices:
                    continue
                for variant in all_variants[di]:
                    sim_score = _variant_similarity_score(variant, fixed_demos[di], variant_score_fn)
                    edit_penalty = 0.0
                    if edit_lambda > 0.0 and int(variant.get("_is_edited", 0)) == 1:
                        edit_penalty = normalized_levenshtein(fixed_demos[di].get("code", ""), variant.get("code", ""))

                    new_demos = chosen_demos + [variant]
                    diversity_bonus = _compute_diversity_score(new_demos)
                    add_score = (w_sim * sim_score) + (diversity_lambda * diversity_bonus) - (edit_lambda * edit_penalty)
                    new_indices = tuple(sorted(list(chosen_indices) + [di]))
                    next_beam.append((score_so_far + add_score, new_indices, new_demos))

        if not next_beam:
            break
        next_beam.sort(key=lambda x: x[0], reverse=True)
        beam = next_beam[:beam_width] if beam_width > 0 else next_beam

    if not beam:
        return [variants[0] for variants in all_variants[:k]]

    best = max(beam, key=lambda x: x[0])
    return best[2][:k]


def rag_da_attack(
    fixed_demos: List[Dict[str, Any]],
    k: int = 5,
    beam_width: int = 8,
    variant_m: int = 3,
    max_ids: int = 1,
    seed: int = 42,
    w_sim: float = 1.0,
    diversity_lambda: float = 0.1,
    edit_lambda: float = 0.0,
    variant_score_fn: Optional[VariantScoreFn] = None,
) -> List[Dict[str, Any]]:
    return select_beam_variant_topk(
        fixed_demos=fixed_demos,
        k=k,
        beam_width=beam_width,
        variant_m=variant_m,
        max_ids=max_ids,
        seed=seed,
        w_sim=w_sim,
        diversity_lambda=diversity_lambda,
        edit_lambda=edit_lambda,
        variant_score_fn=variant_score_fn,
    )
