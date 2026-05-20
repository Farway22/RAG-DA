# RAG-DA: Retrieval-Augmented Demonstration Attack for SVA

This repository contains the code and experiment artifacts for the
Retrieval-Augmented Demonstration Attack (RAG-DA) study on software
vulnerability assessment (SVA).  RAG-DA studies the security of
retrieval-augmented SVA pipelines by manipulating only the retrieved
demonstrations, while keeping the user query, retriever, prompt template, and
model parameters unchanged.

The original ReVul-CoT codebase is retained because the paper builds on its
RAG-SVA pipeline.  The repository is organized around a small runnable example,
a canonical reproduction path, and the experiment artifacts used for the paper.

## Quick Start

Run the minimal example first:

```powershell
uv run --python 3.12.10 python examples/rag-da-example.py
```

If Python and the dependencies are already installed, the plain command also
works:

```powershell
python examples/rag-da-example.py
```

Expected behavior:

- the script imports `rag_da` successfully;
- it prints two toy CVE demonstrations;
- each example reports `Edited: 1`, showing that RAG-DA selected an identifier
  rename instead of returning the original code.

This smoke test does not require the full MegaVul/BigVul data, FAISS indexes,
PostgreSQL, or model API credentials.

## Repository Map

The main files for RAG-DA are:

| Purpose | File |
| --- | --- |
| Core RAG-DA attack module | `src/rag_da.py` |
| Backward-compatible script wrapper | `src/rag-da.py` |
| Minimal runnable example | `examples/rag-da-example.py` |
| Clean/attack reproduction runner | `scripts/rag_da_reproduce.py` |
| Retrieval, prompt construction, and LLM calls | `src/retrieval.py` |
| Metric helpers | `src/rag-da-metrics.py`, `src/evaluation.py` |
| Detailed RAG-DA API notes | `README-rag-da.md` |
| Full reproduction guide | `docs/REPRODUCIBILITY.md` |
| Paper-table artifact map | `docs/EXPERIMENT_MANIFEST.md` |

For new runs, start from `src/rag_da.py` and `scripts/rag_da_reproduce.py`.  The
public repository intentionally omits paper-development scratch files and
historical sweep outputs that are not required to reproduce the RAG-DA method.

## What RAG-DA Does

RAG-DA attacks the retrieved demonstrations in a RAG-based SVA system while
leaving the user query, retriever, prompt template, and model weights
unchanged.  The implementation follows the paper method:

1. retrieve candidate demonstrations for a query vulnerability;
2. localize renamable identifiers in retrieved code snippets;
3. generate semantics-preserving identifier-renaming variants;
4. select one variant per demonstration with a variant-first beam search;
5. send the resulting demonstration set to the same downstream SVA prompt.

The current `src/rag_da.py` uses token-level normalized Levenshtein distance and
supports recomputing retrieval similarity after renaming through
`variant_score_fn`, matching the paper's variant-selection objective.

## Full Reproduction

Install the full-pipeline dependencies:

```powershell
pip install -r requirements/requirements.txt
```

Configure a model backend with environment variables.  Example:

```powershell
$env:DEEPSEEK_API_KEY = "<api key>"
$env:DEEPSEEK_BASE_URL = "https://api.siliconflow.cn/v1"
$env:DEEPSEEK_MODEL = "deepseek-ai/DeepSeek-V3.2"
```

Then run the canonical clean baseline:

```powershell
$env:INPUT_FILE = "datasets/test/test_all.xlsx"
$env:OUTPUT_FILE = "result2/reproduce/megavul_clean.xlsx"
python scripts/rag_da_reproduce.py --mode clean
```

Run the RAG-DA attack:

```powershell
$env:INPUT_FILE = "datasets/test/test_all.xlsx"
$env:OUTPUT_FILE = "result2/reproduce/megavul_attack.xlsx"
python scripts/rag_da_reproduce.py --mode attack --recompute-variant-similarity
```

For BigVul zero-transfer, set:

```powershell
$env:INPUT_FILE = "datasets/bigvul_hf/test_subset_1208_no_overlap.xlsx"
$env:TRAIN_FILE = "datasets/train/train_all.xlsx"
```

More commands and options are documented in `docs/REPRODUCIBILITY.md`.

## Data and Indexes

The full experiments expect these local artifacts:

| Artifact | Expected path |
| --- | --- |
| MegaVul test split | `datasets/test/test_all.xlsx` |
| MegaVul training split | `datasets/train/train_all.xlsx` |
| BigVul zero-transfer split | `datasets/bigvul_hf/test_subset_1208_no_overlap.xlsx` |
| FAISS code index | `faiss/faiss_index_code.index` |
| FAISS description index | `faiss/faiss_index_desc.index` |
| FAISS row map | `faiss/id_map.json` |
| CSV fallback knowledge base | `datasets/megavul_simple_cpp_success_getast.csv` |

`src/retrieval.py` treats PostgreSQL as optional.  If the database is unavailable,
the runner falls back to the CSV knowledge base when possible.

Some benchmark datasets are large or have redistribution constraints.  See
`datasets/README.md` for public release guidance and expected local paths.

## Model Backends

The model labels used by the release are:

| Model label | Release model string |
| --- | --- |
| DeepSeek-V3.2 | `deepseek-ai/DeepSeek-V3.2` |
| Qwen3-Coder | `Qwen/Qwen3-Coder-30B-A3B-Instruct` |
| GPT-5.1 | `gpt-5.1` |
| Grok-4.1-Fast | `x-ai/grok-4.1-fast:free` |

The release scripts use OpenAI-compatible backend adapters for convenience.
The RAG-DA attack, retrieval, prompt construction, and evaluation logic are
independent of whether the model is served locally or through a compatible
endpoint.  API keys are read from environment variables and should never be
committed.

## Experiment Artifacts

The GitHub repository is intentionally code-first.  Raw datasets, FAISS indexes,
full prediction workbooks, prompt/response traces, and paper figures are not
committed to the main branch.  Place downloaded or archived result files under
the paths documented in `docs/EXPERIMENT_MANIFEST.md` if you want to recompute paper
tables locally.

Use `docs/ARTIFACT_RELEASE.md` for the recommended release policy and
`result2/README.md` for the expected location of generated result files.

## Security and Release Hygiene

Before uploading a public artifact, run:

```powershell
Select-String -Path (Get-ChildItem -Recurse -Include *.ps1,*.py,*.md -File).FullName -Pattern 'sk-[A-Za-z0-9_-]+'
```

The public scripts use environment-variable placeholders such as
`YOUR_QWEN_API_KEY_1`.  Do not commit real model credentials.  For
reproducibility, record the model string, backend configuration, decoding
settings, and artifact paths used for each run.
