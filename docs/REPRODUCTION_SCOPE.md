# Reproduction Scope

The GitHub repository is a reference implementation of RAG-DA. It is intended
to make the method, prompts, configurations, and metric interfaces inspectable
without implying that the main branch alone reproduces every paper table.

## Available in the repository

- AST-aware identifier-renaming and variant-selection code;
- retrieval and prompt-construction code;
- a human-readable paper configuration manifest;
- CMR, DSR, and true-ASR metric interfaces;
- query-level bootstrap, exact McNemar, paired sign-flip, and Holm-adjustment code;
- deterministic algorithm checks and a data-free smoke example;
- expected paths for external datasets, indexes, and prediction artifacts.

The logic-level checks can be run with:

```powershell
python tests/test_rag_da_algorithm.py
python examples/rag-da-example.py
```

## Required for exact table reproduction

Exact paper values depend on the following matched artifacts:

| Dependency | Why it matters |
| --- | --- |
| Dataset snapshots and split identifiers | Define the exact query and retrieval populations. |
| FAISS indexes and row maps | Fix the retrieved candidates and their ordering. |
| Model checkpoints or API endpoints | Determine model outputs and may change over time. |
| Prompt/configuration manifest | Fixes inference and attack settings. |
| Paired clean/attack prediction files | Permit query-level metric and significance checks. |
| Software/hardware environment | Affects local inference and embedding behavior. |

These artifacts are not all stored in the Git main branch. Expected locations
are listed in `EXPERIMENT_MANIFEST.md`.

## Metric conventions

The manuscript uses the following conventions:

- DSR: `y_adv < y_true` on ground-truth `HIGH`/`CRITICAL` queries;
- CMR: adversarial prediction below `CRITICAL` on true-`CRITICAL` queries;
- true ASR: `y_adv < y_true` among queries correctly classified by the paired
  clean baseline.

Clean and attack predictions must be joined by a stable query identifier before
paired metrics are computed; row position alone is not a sufficient key.

## Release plan

Subject to third-party licenses, the authors plan to archive split metadata,
checksums, compact derived result summaries, and remaining audit material upon
paper acceptance. Raw third-party benchmarks, model weights, API credentials,
and provider-controlled endpoints are not redistributed by this repository.

## Interpretation

Appropriate claim:

> The repository releases a reference implementation, prompt and configuration
> specifications, metric code, and logic-level checks for RAG-DA.

Claim to avoid:

> Cloning the GitHub repository alone reproduces every value in the paper.
