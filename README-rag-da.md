# RAG-DA: Retrieval-Augmented Demonstration Attack

Public release layout for running clean and attacked RAG-SVA predictions.
See `docs/REPRODUCTION_SCOPE.md` for what is in-repo vs external.

## Entry points

- `src/rag_da.py`: importable core attack implementation.
- `examples/rag-da-example.py`: dependency-free smoke test.
- `scripts/rag_da_reproduce.py`: clean baseline and RAG-DA attack runner.
- `scripts/compute_metrics.py`: accuracy / F1 / MCC plus CMR, DSR, and true ASR.
- `configs/vuln_beam_best.yaml`: default beam-search settings (Section 5.4).
- `src/retrieval.py`: FAISS retrieval, prompt construction, and LLM inference.

## Minimal Usage

```python
from rag_da import rag_da_attack

fixed_demos = [...]  # fixed retriever output D_q
attack_demos = rag_da_attack(
    fixed_demos=fixed_demos,
    k=5,
    beam_width=8,
    variant_m=3,
    max_ids=3,
    seed=42,
    w_sim=1.0,
    diversity_lambda=0.1,
    edit_lambda=0.0,
)
```

```powershell
python examples/rag-da-example.py
```

## Beam-Search Objective

The public implementation uses token-level normalized Levenshtein distance for
edit/stealth and diversity terms.  The similarity term supports:

- default: use the candidate's stored retriever score (`score`);
- with recompute: pass `variant_score_fn(variant, original)` to refresh retrieval
  similarity after identifier renaming (default in the runner).

## Parameters

- `fixed_demos`: fixed demonstration set D_q
- `k`: number of demonstrations to select
- `beam_width`: beam search width
- `variant_m`: number of variants per base demo
- `max_ids`: maximum identifiers to rename per demo
- `w_sim`: similarity weight
- `diversity_lambda`: diversity bonus weight
- `edit_lambda`: edit penalty weight
- `variant_score_fn`: optional callback for recomputing retrieval similarity

The default runner uses `topk=5` (Section 5.4.1) and variant-first beam search
with one selected variant per retrieved demonstration (Algorithm 1).

Environment variables for the full pipeline include `CODE_EMBEDDING_MODEL`,
`DESC_EMBEDDING_MODEL`, `EMBED_MAX_LENGTH`, `EMBED_POOLING`, `RAG_ALPHA`,
`RAG_BETA`, `TOPK`, `FAISS_CODE_INDEX`, `FAISS_DESC_INDEX`, and `FAISS_ID_MAP`.

## Evaluation Metrics

`src/rag_da_metrics.py` defines:

- **CMR_adv**: Critical Miss Rate
- **DSR**: Downgrade Success Rate on ground-truth High/Critical samples
- **True ASR**: under-triage rate on clean-correct samples

Run:

```powershell
python scripts/compute_metrics.py --predictions result2/reproduce/megavul_attack.xlsx --clean result2/reproduce/megavul_clean.xlsx
```

## Threat Model

- **Fixed D_q**: retriever output is fixed; only variant selection changes
- **Black-box**: no ground-truth labels in attack scoring
- **AST-consistent**: renaming preserves syntax and scope semantics

## Public Release Scope

Include source code, configs, documentation, and small sample data only.
Do not publish API keys, private database passwords, or raw third-party datasets
whose licenses do not permit redistribution.
