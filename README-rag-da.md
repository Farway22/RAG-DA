# RAG-DA: Retrieval-Augmented Demonstration Attack

This directory contains the minimal public RAG-DA artifact plus the canonical
runner used to reproduce clean and attacked RAG-SVA predictions.  Large private
experiment dumps and scratch launchers are intentionally omitted from git.

## Code Map

- `src/rag_da.py`: importable core attack implementation.
- `src/rag-da.py`: compatibility wrapper for the historical hyphenated filename.
- `examples/rag-da-example.py`: small runnable example.
- `src/rag-da-metrics.py`: CMR, DSR, and clean-correct ASR metrics.
- `src/rename_ast.py`: richer AST identifier-renaming implementation used by the full pipeline.
- `src/retrieval.py`: FAISS retrieval, prompt construction, and LLM inference.
- `scripts/rag_da_reproduce.py`: canonical clean baseline and RAG-DA attack runner.
- `configs/vuln_beam_best.yaml`: paper-aligned public beam-search configuration.
- `src/stealth_eval.py`: archival helper that requires omitted private `code_trans/` assets.

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

For a quick smoke test:

```powershell
python examples/rag-da-example.py
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
- `max_ids`: Maximum identifiers to rename per demo.  The paper-aligned
  public config uses `3`; the smoke test may use a smaller value for readability.
- `w_sim`: Similarity weight (from retriever score)
- `diversity_lambda`: Diversity bonus weight
- `edit_lambda`: Edit penalty weight (stealth constraint)
- `variant_score_fn`: Optional callback for recomputing retrieval similarity
  for each renamed variant

## Evaluation Metrics

See `src/rag-da-metrics.py` for:
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
