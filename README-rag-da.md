# RAG-DA: Retrieval-Augmented Demonstration Attack

This directory contains both the minimal public RAG-DA artifact and the larger
experiment scripts used by the paper.

## Code Map

- `rag_da.py`: importable core attack implementation.
- `rag-da.py`: compatibility wrapper for the historical hyphenated filename.
- `rag-da-example.py`: small runnable example.
- `rag-da-metrics.py`: CMR, DSR, and clean-correct ASR metrics.
- `rename_ast.py`: richer AST identifier-renaming implementation used by the full pipeline.
- `retrieval.py`: FAISS retrieval, prompt construction, and LLM inference.
- `scripts/run_bigvul_clean_baseline.py`: BigVul zero-transfer clean baseline.
- `scripts/run_bigvul_attack.py`: BigVul zero-transfer attack runner.
- `run_*attack*.ps1` and `run_*rag*.ps1`: model-specific experiment launchers.
- `defense_cross_modal_alignment.py` and `defense_stability_filter.py`: semantic defense prototypes.

## Minimal Usage

```python
from rag_da import rag_da_attack

fixed_demos = [...]  # fixed retriever output D_q
attack_demos = rag_da_attack(
    fixed_demos=fixed_demos,
    k=5,
    beam_width=8,
    variant_m=3,
    max_ids=1,
    seed=42,
    w_sim=1.0,
    diversity_lambda=0.1,
    edit_lambda=0.0,
)
```

For a quick smoke test:

```powershell
python rag-da-example.py
```

## Beam-Search Objective

The public implementation now uses token-level normalized Levenshtein
distance for edit/stealth and diversity terms.  The similarity term supports
two modes:

- default: use the candidate's stored retriever score (`score`);
- paper-aligned: pass `variant_score_fn(variant, original)` to recompute
  retrieval similarity after identifier renaming.

The second mode is the one to use when the FAISS index and embedding models are
available, because renamed variants should be scored with their own retrieval
similarity rather than silently inheriting the original demonstration score.

## Parameters

- `fixed_demos`: fixed demonstration set D_q
- `k`: Number of demonstrations to select
- `beam_width`: Beam search width
- `variant_m`: Number of variants per base demo
- `max_ids`: Maximum identifiers to rename per demo
- `w_sim`: Similarity weight (from retriever score)
- `diversity_lambda`: Diversity bonus weight
- `edit_lambda`: Edit penalty weight (stealth constraint)
- `variant_score_fn`: Optional callback for recomputing retrieval similarity
  for each renamed variant

## Evaluation Metrics

See `rag-da-metrics.py` for:
- **CMR_adv**: Critical Miss Rate (1 - Recall_Critical)
- **DSR**: Downgrade Success Rate
- **True ASR**: Attack Success Rate on clean-correct samples

## Dependencies

- tree-sitter (C language parser)
- tree-sitter-c (C grammar)

## Threat Model

- **Fixed D_q**: Retriever output is fixed, only variant selection is allowed
- **Black-box**: No ground-truth labels used in scoring
- **AST-consistent**: Renaming preserves syntax and scope semantics

## What To Open Source

For a reproducibility release, include the source files above, configs, prompt
templates, metric scripts, and small sample data.  Do not publish API keys,
private database passwords, paid model credentials, or raw third-party datasets
whose licenses do not permit redistribution.  For large datasets, publish
preparation scripts, split IDs, hashes, and download instructions instead.


