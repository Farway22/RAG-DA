"""Core RAG-DA implementation.

This module is the importable version of the public RAG-DA attack code.  It
keeps the attack constrained to demonstration-code identifier renaming, then
selects variants with a beam-search objective that can use recomputed
retrieval similarity for each renamed variant.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import os
import random
import re
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

try:
    from tree_sitter import Language, Parser
except Exception:  # pragma: no cover - exercised in minimal smoke environments.
    Language = None
    Parser = None


class VariableRole(Enum):
    PARAMETER = "parameter"
    RESOURCE = "resource"
    LOCAL = "local"
    LOOP_INDEX = "loop_index"
    FIELD = "field"


class SemanticFamily(Enum):
    BUFFER = "buffer"
    LENGTH_SIZE = "length_size"
    INDEX_OFFSET = "index_offset"
    POINTER = "pointer"
    FLAG_STATUS = "flag_status"
    INPUT_DATA = "input_data"
    GENERIC = "generic"

    # Compatibility aliases for callers that used the shorter family names.
    COUNTER = "length_size"
    INDEX = "index_offset"
    FLAG = "flag_status"


SEMANTIC_FAMILIES = {
    SemanticFamily.BUFFER: [
        "buf",
        "buffer",
        "dst",
        "out",
        "array",
        "arr",
        "vec",
        "vector",
        "storage",
    ],
    SemanticFamily.LENGTH_SIZE: [
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
        "limit",
        "capacity",
        "width",
        "height",
    ],
    SemanticFamily.INDEX_OFFSET: [
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
    SemanticFamily.POINTER: [
        "ptr",
        "pointer",
        "p",
        "addr",
        "address",
        "handle",
        "ref",
        "mem",
        "memory",
    ],
    SemanticFamily.FLAG_STATUS: [
        "flag",
        "is",
        "has",
        "enable",
        "enabled",
        "disable",
        "disabled",
        "active",
        "valid",
        "ok",
        "success",
        "error",
        "err",
        "status",
    ],
    SemanticFamily.INPUT_DATA: [
        "input",
        "in",
        "src",
        "source",
        "data",
        "payload",
        "content",
        "bytes",
        "raw",
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
    SemanticFamily.BUFFER: [
        "{core}_buf", "tmp_{core}", "{core}_data", "{core}_ptr",
        "data_{core}", "safe_{core}", "{core}_buffer",
    ],
    SemanticFamily.LENGTH_SIZE: [
        "{core}_count", "{core}_total", "{core}_num", "max_{core}",
        "{core}_limit", "{core}_size", "{core}_len",
    ],
    SemanticFamily.INDEX_OFFSET: ["{core}_idx", "idx_{core}", "{core}_pos", "{core}_offset", "next_{core}"],
    SemanticFamily.POINTER: ["{core}_ptr", "ptr_{core}", "{core}_addr", "next_{core}_ptr", "safe_{core}_ptr"],
    SemanticFamily.FLAG_STATUS: ["is_{core}", "has_{core}", "{core}_flag", "{core}_status", "valid_{core}"],
    SemanticFamily.INPUT_DATA: ["{core}_data", "input_{core}", "src_{core}", "{core}_payload", "raw_{core}_data"],
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


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _family_mode() -> str:
    return os.getenv("RAG_DA_FAMILY_MODE", "family").strip().lower()


def _stable_name_seed(seed: int, name: str) -> int:
    """Combine a run seed and identifier without Python's randomized hash()."""
    digest = hashlib.blake2b(name.encode("utf-8"), digest_size=8).digest()
    return seed + int.from_bytes(digest, byteorder="big", signed=False)


@dataclass
class VariableInfo:
    name: str
    role: VariableRole
    family: SemanticFamily
    usage_count: int
    importance_score: float
    type_hint: Optional[str] = None
    decl_node: Optional[Any] = None
    scope_node: Optional[Any] = None
    use_nodes: Optional[List[Any]] = None

    def __post_init__(self) -> None:
        if self.use_nodes is None:
            self.use_nodes = []


VariantScoreFn = Callable[[Dict[str, Any], Dict[str, Any]], float]

_TS_LANGUAGE = None
_TS_PARSER = None
_TS_PARSERS: Dict[str, Tuple[Any, Any]] = {}


def _build_parser(language: Any) -> Any:
    parser = Parser()
    if hasattr(parser, "set_language"):
        parser.set_language(language)
    else:
        parser.language = language
    return parser


def _load_packaged_parser(language_name: str) -> Tuple[Any, Any]:
    module_name = "tree_sitter_cpp" if language_name == "cpp" else "tree_sitter_c"
    module = __import__(module_name)
    packaged_language = module.language()
    if isinstance(packaged_language, Language):
        language = packaged_language
    else:
        try:
            language = Language(packaged_language)
        except TypeError as exc:
            raise RuntimeError(
                f"{module_name} is incompatible with the installed tree-sitter; "
                "install tree-sitter>=0.23"
            ) from exc
    if not isinstance(language, Language):
        raise TypeError(f"{module_name} did not provide a tree-sitter Language")
    return language, _build_parser(language)


def _init_tree_sitter(language_name: str = "c"):
    global _TS_LANGUAGE, _TS_PARSER
    if language_name == "c" and _TS_LANGUAGE is not None and _TS_PARSER is not None:
        return _TS_LANGUAGE, _TS_PARSER
    if language_name in _TS_PARSERS:
        return _TS_PARSERS[language_name]
    if Language is None or Parser is None:
        return None, None

    try:
        language, parser = _load_packaged_parser(language_name)
        _TS_PARSERS[language_name] = (language, parser)
        if language_name == "c":
            _TS_LANGUAGE, _TS_PARSER = language, parser
        return language, parser
    except Exception:
        pass

    paths = ["build/my-languages.so", "build/my-languages.dll"]
    for lib_path in paths:
        if os.path.exists(lib_path):
            try:
                language = Language(lib_path, language_name)
                parser = _build_parser(language)
                _TS_PARSERS[language_name] = (language, parser)
                if language_name == "c":
                    _TS_LANGUAGE, _TS_PARSER = language, parser
                return language, parser
            except Exception:
                continue
    return None, None


def _tree_error_score(node: Any) -> int:
    score = 1 if node.type == "ERROR" or getattr(node, "is_missing", False) else 0
    return score + sum(_tree_error_score(child) for child in node.children)


def _parse_c_or_cpp(code: str) -> Tuple[Optional[str], Optional[Any]]:
    """Parse with both grammars and retain the tree with fewer error nodes."""
    parsed = []
    for language_name in ("c", "cpp"):
        _language, parser = _init_tree_sitter(language_name)
        if parser is None:
            continue
        try:
            tree = parser.parse(code.encode("utf-8"))
            parsed.append((_tree_error_score(tree.root_node), language_name, tree))
        except Exception:
            continue
    if not parsed:
        return None, None
    _score, language_name, tree = min(parsed, key=lambda item: (item[0], item[1] != "cpp"))
    return language_name, tree


def _split_identifier_subtokens(name: str) -> List[str]:
    """Split Snake/camel/Pascal identifiers into normalized lexical units."""
    pieces: List[str] = []
    for chunk in re.split(r"_+", name):
        if not chunk:
            continue
        pieces.extend(
            token.lower()
            for token in re.findall(
                r"[A-Z]+(?=[A-Z][a-z]|\d|$)|[A-Z]?[a-z]+|[A-Z]+|\d+",
                chunk,
            )
        )
    return pieces or [name.lower()]


def _assign_semantic_family(
    name: str,
    context_scores: Optional[Dict[SemanticFamily, float]] = None,
) -> SemanticFamily:
    if _family_mode() in {"generic", "none", "no_family", "off"}:
        return SemanticFamily.GENERIC
    subtokens = _split_identifier_subtokens(name)
    lexical_weight = _float_env("FAMILY_LEX_WEIGHT", 1.0)
    context_weight = _float_env("FAMILY_CONTEXT_WEIGHT", 0.5)
    threshold = _float_env("FAMILY_MIN_SCORE", 0.5)
    scores: Dict[SemanticFamily, float] = {}
    for family, keywords in SEMANTIC_FAMILIES.items():
        if family is SemanticFamily.GENERIC:
            continue
        lexical_overlap = float(sum(token in keywords for token in subtokens))
        context_score = float((context_scores or {}).get(family, 0.0))
        scores[family] = lexical_weight * lexical_overlap + context_weight * context_score
    if not scores:
        return SemanticFamily.GENERIC
    best_family = max(scores, key=lambda family: scores[family])
    return best_family if scores[best_family] >= threshold else SemanticFamily.GENERIC


def _semantic_family_core(name: str, family: SemanticFamily) -> str:
    """Return the first subtoken that supports the assigned family."""
    subtokens = _split_identifier_subtokens(name)
    keywords = SEMANTIC_FAMILIES.get(family, [])
    return next((token for token in subtokens if token in keywords), subtokens[0])


def _semantic_context_scores(var: VariableInfo) -> Dict[SemanticFamily, float]:
    """Compute AST-context indicators used by semantic-family inference."""
    scores = {family: 0.0 for family in SEMANTIC_FAMILIES if family is not SemanticFamily.GENERIC}
    if var.role == VariableRole.LOOP_INDEX:
        scores[SemanticFamily.INDEX_OFFSET] += 2.0
    if _is_pointer_type(var.type_hint):
        scores[SemanticFamily.POINTER] += 2.0
    if var.role == VariableRole.PARAMETER:
        scores[SemanticFamily.INPUT_DATA] += 1.0

    unsafe_argument = False
    index_context = False
    boolean_condition = False
    for use_node in var.use_nodes or []:
        parent = use_node.parent
        while parent is not None and parent != var.scope_node:
            if parent.type == "call_expression":
                call_text = parent.text.decode("utf8", errors="ignore")
                if any(pattern in call_text for pattern in UNSAFE_PATTERNS):
                    unsafe_argument = True
            if parent.type in {"for_statement", "subscript_expression"}:
                index_context = True
            elif parent.type in {"if_statement", "while_statement", "conditional_expression"}:
                condition = parent.child_by_field_name("condition")
                if condition is not None and _scope_contains(condition, use_node):
                    boolean_condition = True
            parent = parent.parent
    if unsafe_argument:
        scores[SemanticFamily.BUFFER] += 1.0
        scores[SemanticFamily.POINTER] += 0.5
        scores[SemanticFamily.INPUT_DATA] += 0.5
    if index_context:
        scores[SemanticFamily.INDEX_OFFSET] += 1.0
    if boolean_condition:
        scores[SemanticFamily.FLAG_STATUS] += 1.0
    return scores


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


def _nearest_binding_scope(node: Any, role: VariableRole) -> Any:
    parent = node.parent
    if role == VariableRole.PARAMETER:
        while parent is not None:
            if parent.type in {"function_definition", "lambda_expression"}:
                return parent
            parent = parent.parent
    elif role == VariableRole.FIELD:
        while parent is not None:
            if parent.type in {
                "field_declaration_list",
                "class_specifier",
                "struct_specifier",
                "union_specifier",
            }:
                return parent
            parent = parent.parent
    else:
        while parent is not None:
            if parent.type in {"compound_statement", "function_definition", "for_statement"}:
                return parent
            parent = parent.parent
    return node.parent


def _node_depth(node: Any) -> int:
    depth = 0
    parent = node
    while parent is not None:
        depth += 1
        parent = parent.parent
    return depth


def _scope_contains(scope: Any, node: Any) -> bool:
    return bool(scope and scope.start_byte <= node.start_byte and node.end_byte <= scope.end_byte)


def _binding_vuln_proximity(var: VariableInfo) -> float:
    matching_calls = set()
    for use_node in var.use_nodes or []:
        parent = use_node.parent
        while parent is not None and parent != var.scope_node:
            if parent.type == "call_expression":
                text = parent.text.decode("utf8", errors="ignore")
                if any(pattern in text for pattern in UNSAFE_PATTERNS):
                    matching_calls.add((parent.start_byte, parent.end_byte))
                break
            parent = parent.parent
    return 10.0 * len(matching_calls)


def _extract_variables(ast_root: Any) -> List[VariableInfo]:
    variables: List[VariableInfo] = []
    identifier_nodes: List[Any] = []

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

        if node.type == "identifier":
            identifier_nodes.append(node)

        if var_name:
            type_hint = _extract_type_hint(node)
            role = _identify_variable_role(var_name, decl_node, type_hint)
            var = VariableInfo(
                name=var_name,
                role=role,
                family=_assign_semantic_family(var_name),
                usage_count=1,
                importance_score=0.0,
                type_hint=type_hint,
                decl_node=decl_node,
                scope_node=_nearest_binding_scope(decl_node, role),
                use_nodes=[],
            )
            variables.append(var)

        for child in node.children:
            traverse(child)

    traverse(ast_root)

    declaration_positions = {
        (var.decl_node.start_byte, var.decl_node.end_byte) for var in variables if var.decl_node
    }
    for node in identifier_nodes:
        position = (node.start_byte, node.end_byte)
        if position in declaration_positions:
            continue
        if node.parent and node.parent.type == "function_declarator":
            continue
        name = node.text.decode("utf8", errors="ignore")
        candidates = [
            var
            for var in variables
            if var.name == name
            and _scope_contains(var.scope_node, node)
            and (
                var.role == VariableRole.PARAMETER
                or var.decl_node.start_byte <= node.start_byte
            )
        ]
        if not candidates:
            continue
        binding = max(
            candidates,
            key=lambda var: (_node_depth(var.scope_node), var.decl_node.start_byte),
        )
        binding.use_nodes.append(node)

    for var in variables:
        var.usage_count = 1 + len(var.use_nodes or [])
        var.family = _assign_semantic_family(var.name, _semantic_context_scores(var))
        freq_score = min(float(var.usage_count) * 5.0, 50.0)
        var.importance_score = (
            _float_env("SLOT_FREQ_WEIGHT", 1.0) * freq_score
            + _float_env("SLOT_PROX_WEIGHT", 1.0) * _binding_vuln_proximity(var)
            + _float_env("SLOT_ROLE_WEIGHT", 2.0) * ROLE_WEIGHTS.get(var.role, 50.0)
        )
    return variables


def _select_variables_with_quota(variables: List[VariableInfo], max_ids: int) -> List[VariableInfo]:
    selected = []
    role_counts = {role: 0 for role in VariableRole}
    for var in sorted(variables, key=lambda v: v.importance_score, reverse=True):
        if len(selected) >= max_ids:
            break
        if var.family is SemanticFamily.GENERIC and _family_mode() not in {
            "generic",
            "none",
            "no_family",
            "off",
        }:
            continue
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
    if family is SemanticFamily.GENERIC and _family_mode() not in {
        "generic",
        "none",
        "no_family",
        "off",
    }:
        return None
    templates = FAMILY_TEMPLATES[family]
    core = _semantic_family_core(old_name, family)

    # Seeded ordering makes repeated variant-generation attempts explore
    # different family-consistent names instead of always taking the first
    # available template.  Sorting before shuffling keeps the result stable
    # across Python processes and platforms.
    candidates = [
        candidate
        for template in templates
        for candidate in [template.format(core=core)]
        if _assign_semantic_family(candidate) == family
    ]
    candidates = sorted(set(candidates))
    random.Random(seed).shuffle(candidates)
    for candidate in candidates:
        if candidate.lower() != old_name.lower() and candidate not in existing:
            return candidate
    return None


def _apply_ast_renaming(code: str, renamings: List[Tuple[VariableInfo, str]]) -> str:
    code_bytes = bytearray(code.encode("utf-8"))
    replacements = []

    for var_info, new_name in renamings:
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
        new_name = _generate_new_name_from_template(
            old_name, family, existing, _stable_name_seed(seed, old_name)
        )
        if new_name:
            id_map[old_name] = new_name
            existing.add(new_name)

    return _apply_identifier_mapping_lexical(code, id_map)


def rename_identifiers_ast(
    code: str,
    max_ids: int = 2,
    seed: int = 42,
    allow_lexical_fallback: bool = False,
) -> str:
    """Rename selected C/C++ bindings with grammar- and scope-aware replacement.

    The paper-facing path is strict by default: if neither parser can produce a
    usable tree, the snippet is left unchanged.  Lexical renaming is retained
    only as an explicitly requested smoke-test fallback.
    """
    if not code or not code.strip():
        return code

    _language_name, tree = _parse_c_or_cpp(code)
    if tree is None or _tree_error_score(tree.root_node) > 0:
        if allow_lexical_fallback:
            return _rename_identifiers_lexical(code, max_ids=max_ids, seed=seed)
        return code

    try:
        variables = _extract_variables(tree.root_node)
        selected = _select_variables_with_quota(variables, max_ids)
        if not selected:
            return code

        existing = {v.name for v in variables}
        renamings: List[Tuple[VariableInfo, str]] = []
        for var in selected:
            new_name = _generate_new_name_from_template(
                var.name,
                var.family,
                existing,
                _stable_name_seed(seed, f"{var.name}:{var.decl_node.start_byte}"),
            )
            if new_name:
                renamings.append((var, new_name))
                existing.add(new_name)

        return _apply_ast_renaming(code, renamings) if renamings else code
    except Exception:
        if allow_lexical_fallback:
            return _rename_identifiers_lexical(code, max_ids=max_ids, seed=seed)
        return code


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


def _compute_diversity_score(
    path: List[Dict[str, Any]],
    candidate: Dict[str, Any],
) -> float:
    """Average distance from a new candidate to variants already on the path."""
    if not path:
        return 0.0
    candidate_code = candidate.get("code", "")
    return sum(
        normalized_levenshtein(candidate_code, prior.get("code", ""))
        for prior in path
    ) / len(path)


def _make_variants_for_item(
    item: Dict[str, Any],
    base_index: int,
    variant_m: int,
    max_ids: int,
    seed: int,
    allow_lexical_fallback: bool = False,
) -> List[Dict[str, Any]]:
    variants = []
    original_code = item.get("code", "") or ""

    v0 = dict(item)
    v0["_base_index"] = base_index
    v0["_variant_index"] = 0
    v0["_is_edited"] = 0
    variants.append(v0)

    # A variant pool is a set of distinct code snippets.  Some snippets have
    # too few collision-free renamings to reach variant_m, so use a bounded
    # retry loop and return the smaller genuine pool rather than duplicates.
    seen_codes = {original_code}
    attempt = 0
    max_attempts = max(8, max(0, variant_m - 1) * 16)
    while len(variants) < variant_m and attempt < max_attempts:
        v = dict(item)
        try:
            v["code"] = rename_identifiers_ast(
                original_code,
                max_ids=max_ids,
                seed=seed + attempt,
                allow_lexical_fallback=allow_lexical_fallback,
            )
        except Exception:
            v["code"] = original_code

        attempt += 1
        if v["code"] in seen_codes:
            continue

        seen_codes.add(v["code"])
        v["_base_index"] = base_index
        v["_variant_index"] = len(variants)
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
    max_ids: int = 3,
    seed: int = 42,
    w_sim: float = 1.0,
    diversity_lambda: float = 0.1,
    edit_lambda: float = 0.0,
    variant_score_fn: Optional[VariantScoreFn] = None,
    allow_lexical_fallback: bool = False,
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
        _make_variants_for_item(
            base,
            base_index=i,
            variant_m=max(1, variant_m),
            max_ids=max_ids,
            seed=seed,
            allow_lexical_fallback=allow_lexical_fallback,
        )
        for i, base in enumerate(fixed_demos)
    ]

    BeamState = Tuple[float, List[Dict[str, Any]]]
    beam: List[BeamState] = [(0.0, [])]

    for step in range(min(k, n)):
        next_beam: List[BeamState] = []
        for score_so_far, chosen_demos in beam:
            for variant in all_variants[step]:
                sim_score = _variant_similarity_score(variant, fixed_demos[step], variant_score_fn)
                edit_penalty = 0.0
                if edit_lambda > 0.0 and int(variant.get("_is_edited", 0)) == 1:
                    edit_penalty = normalized_levenshtein(
                        fixed_demos[step].get("code", ""), variant.get("code", "")
                    )

                new_demos = chosen_demos + [variant]
                diversity_bonus = _compute_diversity_score(chosen_demos, variant)
                add_score = (
                    (w_sim * sim_score)
                    + (diversity_lambda * diversity_bonus)
                    - (edit_lambda * edit_penalty)
                )
                next_beam.append((score_so_far + add_score, new_demos))

        if not next_beam:
            break
        next_beam.sort(key=lambda x: x[0], reverse=True)
        beam = next_beam[:beam_width] if beam_width > 0 else next_beam

    if not beam:
        return [variants[0] for variants in all_variants[:k]]

    best = max(beam, key=lambda x: x[0])
    return best[1][:k]


def rag_da_attack(
    fixed_demos: List[Dict[str, Any]],
    k: int = 5,
    beam_width: int = 8,
    variant_m: int = 3,
    max_ids: int = 3,
    seed: int = 42,
    w_sim: float = 1.0,
    diversity_lambda: float = 0.1,
    edit_lambda: float = 0.0,
    variant_score_fn: Optional[VariantScoreFn] = None,
    allow_lexical_fallback: bool = False,
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
        allow_lexical_fallback=allow_lexical_fallback,
    )
