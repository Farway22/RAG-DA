"""Backward-compatible entry points for identifier renaming.

The canonical implementation lives in :mod:`rag_da`. This module is kept only
because older retrieval utilities import ``rename_identifiers_ast`` from
``rename_ast``. It deliberately contains no second candidate generator.
"""

from __future__ import annotations

from typing import Optional, Set

from rag_da import (
    SEMANTIC_FAMILIES,
    SemanticFamily,
    VariableRole,
    _generate_new_name_from_template,
    _rename_identifiers_lexical,
    rename_identifiers_ast as _canonical_rename_identifiers_ast,
)


LAST_RENAME_MODE = "unknown"
LAST_RENAME_ID_MAP = {}


def _canonical_family(family: SemanticFamily) -> SemanticFamily:
    """Accept legacy enum-compatible values without duplicating the enum."""
    if isinstance(family, SemanticFamily):
        return family
    value = getattr(family, "value", family)
    return SemanticFamily(value)


def generate_new_name(
    old_name: str,
    family: SemanticFamily,
    existing: Set[str],
    seed: int,
) -> Optional[str]:
    """Delegate legacy calls to the paper-facing template generator."""
    return _generate_new_name_from_template(
        old_name,
        _canonical_family(family),
        existing,
        seed,
    )


def rename_identifiers_ast(
    code: str,
    max_ids: int = 2,
    seed: int = 42,
    enable_ast: bool = True,
    allow_lexical_fallback: bool = False,
) -> str:
    """Delegate renaming to :mod:`rag_da` while preserving the old signature."""
    global LAST_RENAME_MODE, LAST_RENAME_ID_MAP

    if not code or not code.strip():
        LAST_RENAME_MODE = "noop"
        LAST_RENAME_ID_MAP = {}
        return code

    if enable_ast:
        result = _canonical_rename_identifiers_ast(
            code,
            max_ids=max_ids,
            seed=seed,
            allow_lexical_fallback=allow_lexical_fallback,
        )
        LAST_RENAME_MODE = "canonical_ast" if result != code else "noop"
    else:
        result = _rename_identifiers_lexical(code, max_ids=max_ids, seed=seed)
        LAST_RENAME_MODE = "canonical_lexical" if result != code else "noop"

    # The old module exposed a mapping diagnostic. The canonical implementation
    # applies mappings internally, so the compatibility layer keeps no parallel
    # algorithm state.
    LAST_RENAME_ID_MAP = {}
    return result


__all__ = [
    "LAST_RENAME_ID_MAP",
    "LAST_RENAME_MODE",
    "SEMANTIC_FAMILIES",
    "SemanticFamily",
    "VariableRole",
    "generate_new_name",
    "rename_identifiers_ast",
]
