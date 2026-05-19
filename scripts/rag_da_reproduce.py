# -*- coding: utf-8 -*-
"""Canonical RAG-DA reproduction runner.

Pipeline:
1. retrieve demonstrations with the FAISS code+description retriever;
2. optionally rewrite only retrieved demonstration code with ``rag_da.py``;
3. build the few-shot prompt through ``retrieval.py``;
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

_THIS = pathlib.Path(__file__).resolve()
_ROOT = _THIS.parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
os.chdir(str(_ROOT))

from rag_da import rag_da_attack
from retrieval import (
    embed_code,
    embed_desc,
    get_vuln_info_by_faiss_idx,
    index_code,
    index_desc,
    predict_vuln_level,
    predict_vuln_level_fewshot_cot,
    rag_multimodal_search,
)


VALID_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


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
    if train_cve_ids is None:
        return rag_multimodal_search(
            query_code,
            query_desc,
            topk=topk,
            alpha=alpha,
            beta=beta,
            search_factor=search_factor,
            return_limit=topk,
        )

    code_vec = np.array(embed_code(query_code), dtype="float32").reshape(1, -1)
    desc_vec = np.array(embed_desc(query_desc), dtype="float32").reshape(1, -1)
    search_k = max(1, topk * search_factor * 2)
    _, idx_code = index_code.search(code_vec, search_k)
    _, idx_desc = index_desc.search(desc_vec, search_k)

    candidates = []
    for idx in set(idx_code[0].tolist() + idx_desc[0].tolist()):
        item = get_vuln_info_by_faiss_idx(idx)
        if not item:
            continue
        cve_id = str(item.get("cve_id", "")).strip().upper()
        if cve_id not in train_cve_ids:
            continue
        db_code_vec = index_code.reconstruct(idx)
        db_desc_vec = index_desc.reconstruct(idx)
        item["score"] = alpha * float(np.dot(code_vec, db_code_vec)) + beta * float(np.dot(desc_vec, db_desc_vec))
        candidates.append(item)

    return sorted(candidates, key=lambda x: float(x.get("score", 0.0)), reverse=True)[:topk]


def build_variant_score_fn(query_code: str, query_desc: str, alpha: float, beta: float):
    query_code_vec = np.array(embed_code(query_code), dtype="float32")
    query_desc_vec = np.array(embed_desc(query_desc), dtype="float32")
    desc_cache: Dict[str, np.ndarray] = {}

    def score_variant(variant: Dict[str, Any], original: Dict[str, Any]) -> float:
        code = str(variant.get("code", "") or "")
        desc = str(variant.get("description", original.get("description", "")) or "")
        code_vec = np.array(embed_code(code), dtype="float32")
        if desc not in desc_cache:
            desc_cache[desc] = np.array(embed_desc(desc), dtype="float32")
        return alpha * float(np.dot(query_code_vec, code_vec)) + beta * float(np.dot(query_desc_vec, desc_cache[desc]))

    return score_variant


def select_demos(
    mode: str,
    query_code: str,
    query_desc: str,
    pool: List[Dict[str, Any]],
    args: argparse.Namespace,
) -> List[Dict[str, Any]]:
    if mode == "clean":
        return pool[: args.topk]

    variant_score_fn = None
    if args.recompute_variant_similarity:
        variant_score_fn = build_variant_score_fn(query_code, query_desc, args.alpha, args.beta)

    return rag_da_attack(
        fixed_demos=pool[: args.pool_size],
        k=args.topk,
        beam_width=args.beam_width,
        variant_m=args.variant_m,
        max_ids=args.rewrite_max_ids,
        seed=args.variant_seed,
        w_sim=args.w_sim,
        diversity_lambda=args.diversity_lambda,
        edit_lambda=args.edit_lambda,
        variant_score_fn=variant_score_fn,
    )


def predict(query_code: str, query_desc: str, demos: List[Dict[str, Any]], infer_simple: bool) -> str:
    if infer_simple:
        return predict_vuln_level(query_code, query_desc, demos)
    return predict_vuln_level_fewshot_cot(query_code, query_desc, demos)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run clean or attacked RAG-SVA predictions.")
    parser.add_argument("--mode", choices=["clean", "attack"], default=os.getenv("RAG_DA_MODE", "attack"))
    parser.add_argument("--input-file", default=os.getenv("INPUT_FILE", "datasets/test/test_all.xlsx"))
    parser.add_argument("--output-file", default=os.getenv("OUTPUT_FILE", "result2/rag_da_attack_results.xlsx"))
    parser.add_argument("--train-file", default=os.getenv("TRAIN_FILE", ""))
    parser.add_argument("--topk", type=int, default=int(os.getenv("TOPK", "5")))
    parser.add_argument("--pool-size", type=int, default=int(os.getenv("POOL_SIZE", "30")))
    parser.add_argument("--beam-width", type=int, default=int(os.getenv("BEAM_WIDTH", "8")))
    parser.add_argument("--variant-m", type=int, default=int(os.getenv("VARIANT_M", "3")))
    parser.add_argument("--rewrite-max-ids", type=int, default=int(os.getenv("REWRITE_MAX_IDS", "3")))
    parser.add_argument("--variant-seed", type=int, default=int(os.getenv("VARIANT_SEED", os.getenv("SHUFFLE_SEED", "42"))))
    parser.add_argument("--w-sim", type=float, default=float(os.getenv("W_SIM", "1.0")))
    parser.add_argument("--diversity-lambda", type=float, default=float(os.getenv("DIVERSITY_LAMBDA", "0.1")))
    parser.add_argument("--edit-lambda", type=float, default=float(os.getenv("EDIT_LAMBDA", "0.0")))
    parser.add_argument("--alpha", type=float, default=float(os.getenv("RAG_ALPHA", "0.6")))
    parser.add_argument("--beta", type=float, default=float(os.getenv("RAG_BETA", "0.4")))
    parser.add_argument("--search-factor", type=int, default=int(os.getenv("RAG_SEARCH_FACTOR", "4")))
    parser.add_argument("--max-run", type=int, default=int(os.getenv("SMALL_RUN_MAX", "9999")))
    parser.add_argument("--infer-simple", action="store_true", default=os.getenv("INFER_SIMPLE", "0").strip() == "1")
    parser.add_argument(
        "--recompute-variant-similarity",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("RECOMPUTE_VARIANT_SIMILARITY", "1").strip() != "0",
    )
    parser.add_argument("--dry-run", action="store_true", default=os.getenv("DRY_RUN", "0").strip() == "1")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
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
    print(f"[config] mode={args.mode} topk={args.topk} pool={args.pool_size} beam={args.beam_width}")
    print(f"[config] recompute_variant_similarity={args.recompute_variant_similarity}")
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
