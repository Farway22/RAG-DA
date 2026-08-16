# -*- coding: utf-8 -*-
"""End-to-end clean baseline and RAG-DA attack runner.

Pipeline:
1. retrieve demonstrations with the FAISS code+description retriever;
2. optionally rewrite only retrieved demonstration code with ``src/rag_da.py``;
3. build the few-shot prompt through ``src/retrieval.py``;
4. call the configured LLM;
5. save resumable predictions to an Excel file.

Credentials are read from environment variables. Do not hard-code API keys in
release scripts.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys
from typing import Any, Dict, List, Optional, Set

import numpy as np
import pandas as pd
import yaml

_THIS = pathlib.Path(__file__).resolve()
_ROOT = _THIS.parents[1]
_SRC = _ROOT / "src"
for path in (str(_SRC), str(_ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)
os.chdir(str(_ROOT))

from rag_da import rag_da_attack


VALID_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def _retrieval_backend():
    """Load heavyweight retrieval/API dependencies only when they are used."""
    import retrieval

    return retrieval


def normalize_label(label: str) -> str:
    if not isinstance(label, str):
        return ""
    match = re.search(r"(LOW|MEDIUM|HIGH|CRITICAL)", label.upper())
    return match.group(1) if match else ""


def load_train_cve_ids(path: Optional[str]) -> Optional[Set[str]]:
    if not path:
        return None
    df = pd.read_excel(path)
    if "cve_id" not in df.columns:
        raise ValueError(f"training split file has no cve_id column: {path}")
    return set(df["cve_id"].astype(str).str.strip().str.upper())


def rag_search_train_only(
    query_code: str,
    query_desc: str,
    train_cve_ids: Optional[Set[str]],
    topk: int,
    search_factor: int,
    alpha: float,
    beta: float,
) -> List[Dict[str, Any]]:
    backend = _retrieval_backend()
    if train_cve_ids is None:
        return backend.rag_multimodal_search(
            query_code,
            query_desc,
            topk=topk,
            alpha=alpha,
            beta=beta,
            search_factor=search_factor,
            return_limit=topk,
        )

    code_vec = np.array(backend.embed_code(query_code), dtype="float32").reshape(1, -1)
    desc_vec = np.array(backend.embed_desc(query_desc), dtype="float32").reshape(1, -1)
    search_k = max(1, topk * search_factor * 2)
    _, idx_code = backend.index_code.search(code_vec, search_k)
    _, idx_desc = backend.index_desc.search(desc_vec, search_k)

    candidates = []
    for idx in set(idx_code[0].tolist() + idx_desc[0].tolist()):
        item = backend.get_vuln_info_by_faiss_idx(idx)
        if not item:
            continue
        cve_id = str(item.get("cve_id", "")).strip().upper()
        if cve_id not in train_cve_ids:
            continue
        db_code_vec = backend.index_code.reconstruct(idx)
        db_desc_vec = backend.index_desc.reconstruct(idx)
        item["score"] = alpha * float(np.dot(code_vec, db_code_vec)) + beta * float(np.dot(desc_vec, db_desc_vec))
        candidates.append(item)

    return sorted(candidates, key=lambda x: float(x.get("score", 0.0)), reverse=True)[:topk]


def build_variant_score_fn(query_code: str, query_desc: str, alpha: float, beta: float):
    backend = _retrieval_backend()
    query_code_vec = np.array(backend.embed_code(query_code), dtype="float32")
    query_desc_vec = np.array(backend.embed_desc(query_desc), dtype="float32")
    desc_cache: Dict[str, np.ndarray] = {}

    def score_variant(variant: Dict[str, Any], original: Dict[str, Any]) -> float:
        code = str(variant.get("code", "") or "")
        desc = str(variant.get("description", original.get("description", "")) or "")
        code_vec = np.array(backend.embed_code(code), dtype="float32")
        if desc not in desc_cache:
            desc_cache[desc] = np.array(backend.embed_desc(desc), dtype="float32")
        return alpha * float(np.dot(query_code_vec, code_vec)) + beta * float(np.dot(query_desc_vec, desc_cache[desc]))

    return score_variant


def select_demos(
    mode: str,
    query_code: str,
    query_desc: str,
    pool: List[Dict[str, Any]],
    args: argparse.Namespace,
) -> List[Dict[str, Any]]:
    demos = pool[: args.topk]
    if mode == "clean":
        return demos

    variant_score_fn = None
    if args.recompute_variant_similarity:
        variant_score_fn = build_variant_score_fn(query_code, query_desc, args.alpha, args.beta)

    return rag_da_attack(
        fixed_demos=demos,
        k=len(demos),
        beam_width=args.beam_width,
        variant_m=args.variant_m,
        max_ids=args.rewrite_max_ids,
        seed=args.variant_seed,
        w_sim=args.w_sim,
        diversity_lambda=args.diversity_lambda,
        edit_lambda=args.edit_lambda,
        variant_score_fn=variant_score_fn,
        allow_lexical_fallback=getattr(args, "allow_lexical_fallback", False),
    )


def predict(query_code: str, query_desc: str, demos: List[Dict[str, Any]], infer_simple: bool) -> str:
    backend = _retrieval_backend()
    if infer_simple:
        return backend.predict_vuln_level(query_code, query_desc, demos)
    return backend.predict_vuln_level_fewshot_cot(query_code, query_desc, demos)


def load_config(path: str) -> Dict[str, Any]:
    config_path = pathlib.Path(path)
    if not config_path.is_absolute():
        config_path = _ROOT / config_path
    if not config_path.exists():
        raise FileNotFoundError(f"configuration file not found: {config_path}")
    with config_path.open("r", encoding="utf-8") as stream:
        config = yaml.safe_load(stream) or {}
    if not isinstance(config, dict):
        raise ValueError(f"configuration root must be a mapping: {config_path}")
    return config


def _config_value(config: Dict[str, Any], section: str, key: str, fallback: Any) -> Any:
    values = config.get(section, {})
    return values.get(key, fallback) if isinstance(values, dict) else fallback


def _env_value(name: str, config_value: Any, cast):
    raw = os.getenv(name)
    return cast(raw) if raw is not None else cast(config_value)


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"cannot interpret as boolean: {value!r}")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    config_parser = argparse.ArgumentParser(add_help=False)
    config_parser.add_argument(
        "--config",
        default=os.getenv("RAG_DA_CONFIG", "configs/vuln_beam_best.yaml"),
        help="YAML configuration file; environment variables and CLI arguments override it",
    )
    config_args, _ = config_parser.parse_known_args(argv)
    config = load_config(config_args.config)

    parser = argparse.ArgumentParser(
        description="Run clean or attacked RAG-SVA predictions.",
        parents=[config_parser],
    )
    parser.add_argument("--mode", choices=["clean", "attack"], default=os.getenv("RAG_DA_MODE", "attack"))
    parser.add_argument(
        "--input-file",
        default=os.getenv("INPUT_FILE", _config_value(config, "artifacts", "input_file", "datasets/test/test_all.xlsx")),
    )
    parser.add_argument(
        "--output-file",
        default=os.getenv(
            "OUTPUT_FILE",
            _config_value(config, "artifacts", "output_file", "result2/rag_da_attack_results.xlsx"),
        ),
    )
    parser.add_argument(
        "--train-file",
        default=os.getenv("TRAIN_FILE", _config_value(config, "artifacts", "train_file", "")),
    )
    parser.add_argument(
        "--topk",
        type=int,
        default=_env_value("TOPK", _config_value(config, "retrieval", "topk", 5), int),
        help="Number of demonstrations passed to the prompt",
    )
    parser.add_argument(
        "--pool-size",
        type=int,
        default=_env_value("POOL_SIZE", _config_value(config, "retrieval", "pool_size", 30), int),
        help="Number of ranked retrieval candidates retained before final top-k selection",
    )
    parser.add_argument(
        "--beam-width",
        type=int,
        default=_env_value("BEAM_WIDTH", _config_value(config, "attack", "beam_width", 8), int),
    )
    parser.add_argument(
        "--variant-m",
        type=int,
        default=_env_value("VARIANT_M", _config_value(config, "attack", "variant_m", 3), int),
    )
    parser.add_argument(
        "--rewrite-max-ids",
        type=int,
        default=_env_value("REWRITE_MAX_IDS", _config_value(config, "attack", "rewrite_max_ids", 3), int),
    )
    parser.add_argument(
        "--variant-seed",
        type=int,
        default=_env_value(
            "VARIANT_SEED",
            _config_value(config, "attack", "variant_seed", os.getenv("SHUFFLE_SEED", "42")),
            int,
        ),
    )
    parser.add_argument(
        "--w-sim",
        type=float,
        default=_env_value("W_SIM", _config_value(config, "attack", "w_sim", 1.0), float),
    )
    parser.add_argument(
        "--diversity-lambda",
        type=float,
        default=_env_value(
            "DIVERSITY_LAMBDA", _config_value(config, "attack", "diversity_lambda", 0.1), float
        ),
    )
    parser.add_argument(
        "--edit-lambda",
        type=float,
        default=_env_value("EDIT_LAMBDA", _config_value(config, "attack", "edit_lambda", 0.0), float),
    )
    parser.add_argument(
        "--slot-freq-weight",
        type=float,
        default=_env_value(
            "SLOT_FREQ_WEIGHT", _config_value(config, "attack", "slot_freq_weight", 1.0), float
        ),
    )
    parser.add_argument(
        "--slot-prox-weight",
        type=float,
        default=_env_value(
            "SLOT_PROX_WEIGHT", _config_value(config, "attack", "slot_prox_weight", 1.0), float
        ),
    )
    parser.add_argument(
        "--slot-role-weight",
        type=float,
        default=_env_value(
            "SLOT_ROLE_WEIGHT", _config_value(config, "attack", "slot_role_weight", 2.0), float
        ),
    )
    parser.add_argument(
        "--family-mode",
        default=os.getenv("RAG_DA_FAMILY_MODE", _config_value(config, "attack", "family_mode", "family")),
    )
    parser.add_argument(
        "--family-lex-weight",
        type=float,
        default=_env_value(
            "FAMILY_LEX_WEIGHT", _config_value(config, "attack", "family_lex_weight", 1.0), float
        ),
    )
    parser.add_argument(
        "--family-context-weight",
        type=float,
        default=_env_value(
            "FAMILY_CONTEXT_WEIGHT",
            _config_value(config, "attack", "family_context_weight", 0.5),
            float,
        ),
    )
    parser.add_argument(
        "--family-min-score",
        type=float,
        default=_env_value(
            "FAMILY_MIN_SCORE", _config_value(config, "attack", "family_min_score", 0.5), float
        ),
    )
    parser.add_argument(
        "--allow-lexical-fallback",
        action=argparse.BooleanOptionalAction,
        default=_env_value(
            "ALLOW_LEXICAL_FALLBACK",
            _config_value(config, "attack", "allow_lexical_fallback", False),
            _as_bool,
        ),
        help="Allow lexical renaming when C/C++ parsing fails (disabled in the paper-facing configuration).",
    )
    parser.add_argument(
        "--alpha",
        type=float,
        default=_env_value("RAG_ALPHA", _config_value(config, "retrieval", "alpha", 0.6), float),
    )
    parser.add_argument(
        "--beta",
        type=float,
        default=_env_value("RAG_BETA", _config_value(config, "retrieval", "beta", 0.4), float),
    )
    parser.add_argument(
        "--search-factor",
        type=int,
        default=_env_value("RAG_SEARCH_FACTOR", _config_value(config, "retrieval", "search_factor", 4), int),
    )
    parser.add_argument("--max-run", type=int, default=int(os.getenv("SMALL_RUN_MAX", "9999")))
    cot_enabled = _env_value("PROMPT_COT", _config_value(config, "prompt", "cot", True), _as_bool)
    parser.add_argument(
        "--infer-simple",
        action="store_true",
        default=_env_value("INFER_SIMPLE", not cot_enabled, _as_bool),
    )
    parser.add_argument(
        "--recompute-variant-similarity",
        action=argparse.BooleanOptionalAction,
        default=_env_value(
            "RECOMPUTE_VARIANT_SIMILARITY",
            _config_value(config, "attack", "recompute_variant_similarity", True),
            _as_bool,
        ),
    )
    parser.add_argument("--dry-run", action="store_true", default=os.getenv("DRY_RUN", "0").strip() == "1")
    return parser.parse_args(argv)


def main() -> None:
    args = parse_args()
    if args.topk <= 0 or args.pool_size <= 0:
        raise ValueError("topk and pool_size must be positive")
    if args.pool_size < args.topk:
        raise ValueError(f"pool_size ({args.pool_size}) must be at least topk ({args.topk})")
    os.environ["SLOT_FREQ_WEIGHT"] = str(args.slot_freq_weight)
    os.environ["SLOT_PROX_WEIGHT"] = str(args.slot_prox_weight)
    os.environ["SLOT_ROLE_WEIGHT"] = str(args.slot_role_weight)
    os.environ["RAG_DA_FAMILY_MODE"] = str(args.family_mode)
    os.environ["FAMILY_LEX_WEIGHT"] = str(args.family_lex_weight)
    os.environ["FAMILY_CONTEXT_WEIGHT"] = str(args.family_context_weight)
    os.environ["FAMILY_MIN_SCORE"] = str(args.family_min_score)
    train_cve_ids = load_train_cve_ids(args.train_file) if args.train_file else None

    output_path = pathlib.Path(args.output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_file = output_path.with_suffix(output_path.suffix + ".tmp.xlsx")

    if output_path.exists():
        df = pd.read_excel(output_path)
        print(f"[resume] loaded {output_path}")
    else:
        df = pd.read_excel(args.input_file)
        df["Predicted"] = ""
        df["Predicted_raw"] = ""
        print(f"[start] loaded {args.input_file}")

    rows = df[~df["Predicted"].astype(str).str.strip().isin(VALID_LEVELS)].index
    print(
        f"[config] mode={args.mode} pool_size={args.pool_size} "
        f"topk={args.topk} beam={args.beam_width}"
    )
    print(f"[config] recompute_variant_similarity={args.recompute_variant_similarity}")
    print(
        "[config] slot_weights="
        f"freq:{args.slot_freq_weight},prox:{args.slot_prox_weight},role:{args.slot_role_weight} "
        f"family_mode={args.family_mode} "
        f"family_weights=lex:{args.family_lex_weight},ctx:{args.family_context_weight},"
        f"min:{args.family_min_score} lexical_fallback={args.allow_lexical_fallback}"
    )
    print(f"[todo] rows={len(rows)}")

    for count, idx in enumerate(rows, 1):
        if count > args.max_run:
            print(f"[stop] reached max_run={args.max_run}")
            break

        row = df.loc[idx]
        query_code = str(row.get("func_before", "") or "")
        query_desc = str(row.get("description", "") or "")
        true_sev = str(row.get("Base Severity", "")).strip().upper()
        cve_id = str(row.get("cve_id", "") or "")
        print(f"[{count}/{len(rows)}] row={idx} cve={cve_id} true={true_sev}")

        try:
            pool = rag_search_train_only(
                query_code=query_code,
                query_desc=query_desc,
                train_cve_ids=train_cve_ids,
                topk=args.pool_size,
                search_factor=args.search_factor,
                alpha=args.alpha,
                beta=args.beta,
            )
            demos = select_demos(args.mode, query_code, query_desc, pool, args)
            edited = sum(int(d.get("_is_edited", 0)) for d in demos)
            print(f"  pool={len(pool)} demos={len(demos)} edited={edited}")
            raw = "" if args.dry_run else predict(query_code, query_desc, demos, args.infer_simple)
            norm = normalize_label(raw)
        except Exception as exc:
            raw = f"ERROR: {type(exc).__name__}: {exc}"
            norm = ""
            print(f"  [error] {raw}")

        df.at[idx, "Predicted"] = norm
        df.at[idx, "Predicted_raw"] = raw
        df.to_excel(temp_file, index=False)
        os.replace(temp_file, output_path)

    print(f"[done] saved {output_path}")


if __name__ == "__main__":
    main()
