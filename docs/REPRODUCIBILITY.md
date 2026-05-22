# RAG-DA Reproducibility Guide

This guide documents how to run the RAG-DA experiments beyond the small toy
example in the main README.

## Entry Points

- Minimal attack example: `python examples/rag-da-example.py`
- Canonical clean/attack runner: `python scripts/rag_da_reproduce.py`
- Core attack implementation: `src/rag_da.py`
- Retrieval, prompts, and LLM calls: `src/retrieval.py`
- Metrics: `src/rag-da-metrics.py`, `src/evaluation.py`

`scripts/rag_da_reproduce.py` is the canonical RAG-DA pipeline because it calls
the shared `src/rag_da.py` implementation.  Historical scratch scripts and sweep
outputs are intentionally omitted from the public code release.

## Environment

Install the Python dependencies used by the full pipeline:

```powershell
pip install -r requirements/requirements.txt
```

The runner reads model credentials from environment variables.  Do not commit
real API keys.

```powershell
$env:DEEPSEEK_API_KEY = "<api key>"
$env:DEEPSEEK_BASE_URL = "https://api.example.com/v1"
$env:DEEPSEEK_MODEL = "deepseek-ai/DeepSeek-V3.2"
```

OpenAI-compatible backends can also be configured with `GPT_API_KEY`,
`GPT_BASE_URL`, and `GPT_MODEL`, or `QWEN_API_KEY`, `QWEN_BASE_URL`, and
`QWEN_MODEL`.

## Data and Indexes

Expected local files:

- MegaVul test set: `datasets/test/test_all.xlsx`
- MegaVul training split: `datasets/train/train_all.xlsx`
- BigVul test set: `datasets/bigvul_hf/test_subset_1208_no_overlap.xlsx`
- FAISS indexes: `faiss/faiss_index_code.index`, `faiss/faiss_index_desc.index`
- FAISS-to-row map: `faiss/id_map.json`
- CSV fallback: `datasets/megavul_simple_cpp_success_getast.csv`

`src/retrieval.py` now treats PostgreSQL as optional.  If `POSTGRES_*` variables are
not set or the database is unavailable, it falls back to the CSV file above when
possible.

## MegaVul Clean and Attack Runs

Clean RAG baseline:

```powershell
$env:INPUT_FILE = "datasets/test/test_all.xlsx"
$env:OUTPUT_FILE = "result2/reproduce/megavul_clean.xlsx"
python scripts/rag_da_reproduce.py --mode clean
```

RAG-DA attack:

```powershell
$env:INPUT_FILE = "datasets/test/test_all.xlsx"
$env:OUTPUT_FILE = "result2/reproduce/megavul_attack.xlsx"
$env:TOPK = "5"
$env:POOL_SIZE = "30"
$env:BEAM_WIDTH = "8"
$env:VARIANT_M = "3"
$env:REWRITE_MAX_IDS = "3"
$env:DIVERSITY_LAMBDA = "0.1"
$env:EDIT_LAMBDA = "0.0"
python scripts/rag_da_reproduce.py --mode attack --recompute-variant-similarity
```

`--recompute-variant-similarity` is enabled by default.  It recomputes the
retrieval similarity for each renamed demonstration variant using the same
code/description embedding functions as clean RAG.

## BigVul Zero-Transfer Runs

Clean baseline:

```powershell
$env:INPUT_FILE = "datasets/bigvul_hf/test_subset_1208_no_overlap.xlsx"
$env:TRAIN_FILE = "datasets/train/train_all.xlsx"
$env:OUTPUT_FILE = "result2/reproduce/bigvul_clean.xlsx"
python scripts/rag_da_reproduce.py --mode clean
```

Attack:

```powershell
$env:INPUT_FILE = "datasets/bigvul_hf/test_subset_1208_no_overlap.xlsx"
$env:TRAIN_FILE = "datasets/train/train_all.xlsx"
$env:OUTPUT_FILE = "result2/reproduce/bigvul_attack.xlsx"
python scripts/rag_da_reproduce.py --mode attack --recompute-variant-similarity
```

The `TRAIN_FILE` filter keeps retrieved demonstrations within the MegaVul
training split while evaluating on BigVul.

## Dry Run

To verify retrieval and attack selection without spending LLM calls:

```powershell
$env:SMALL_RUN_MAX = "3"
python scripts/rag_da_reproduce.py --mode attack --dry-run
```

The log reports the retrieved pool size, selected demonstration count, and how
many selected demonstrations were edited.

## Metrics

After producing clean and attack prediction files, use the metric helpers:

- `src/rag-da-metrics.py` for CMR, DSR on ground-truth High/Critical samples,
  and clean-correct under-triage ASR primitives;
- `src/evaluation.py` for standard accuracy/F1/MCC.

For a camera-ready or archival release, add one command per paper table under
`scripts/`, so users can trace each number directly to its analysis script.
Those paper-table scripts are not included in this compact public artifact yet.

## Release Hygiene

Before publishing:

- confirm `Select-String -Recurse -Pattern 'sk-'` returns no API keys;
- keep only sanitized run scripts with environment-variable credentials;
- include split IDs or hashes for datasets that cannot be redistributed;
- include exact model version strings, release-script endpoints, and decoding
  settings used for each table;
- mark legacy scripts as archival if they are not used to generate the final
  reported numbers.
