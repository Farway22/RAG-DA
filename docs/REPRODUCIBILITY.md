# Running the RAG-DA Artifact

How to run clean baselines and RAG-DA attacks beyond the in-repo smoke test.
For what is (and is not) covered by the public code alone, see
`docs/REPRODUCTION_SCOPE.md`.

## Entry points

| Purpose | Command / file |
| --- | --- |
| Algorithm structure (no data) | `python tests/test_rag_da_algorithm.py` |
| Smoke test | `python examples/rag-da-example.py` |
| Clean / attack runner | `python scripts/rag_da_reproduce.py` |
| Attack core | `src/rag_da.py` |
| Retrieval + LLM | `src/retrieval.py` |
| Metrics CLI | `python scripts/compute_metrics.py` |
| Default beam settings | `configs/vuln_beam_best.yaml` |

`scripts/rag_da_reproduce.py` wires retrieval, `src/rag_da.py`, prompting, and
LLM calls with the defaults in `configs/vuln_beam_best.yaml`. Other ad-hoc
scripts are not part of this release.

## Environment

```powershell
pip install -r requirements/requirements.txt
```

Model credentials are read from environment variables. Do not commit real API keys.

```powershell
$env:DEEPSEEK_API_KEY = "<api key>"
$env:DEEPSEEK_BASE_URL = "https://api.example.com/v1"
$env:DEEPSEEK_MODEL = "deepseek-ai/DeepSeek-V3.2"
```

OpenAI-compatible backends can also be configured with `GPT_API_KEY`, `GPT_BASE_URL`,
and `GPT_MODEL`, or `QWEN_API_KEY`, `QWEN_BASE_URL`, and `QWEN_MODEL`.

## Data and indexes

Expected local files:

- MegaVul test set: `datasets/test/test_all.xlsx`
- MegaVul training split: `datasets/train/train_all.xlsx`
- BigVul test set: `datasets/bigvul_hf/test_subset_1208_no_overlap.xlsx`
- FAISS indexes: `faiss/faiss_index_code.index`, `faiss/faiss_index_desc.index`
- FAISS-to-row map: `faiss/id_map.json`
- CSV fallback: `datasets/megavul_simple_cpp_success_getast.csv`

PostgreSQL is optional. If `POSTGRES_*` variables are not set, `src/retrieval.py`
falls back to the CSV file above when possible. FAISS indexes are loaded lazily,
so importing the module does not require local indexes until retrieval starts.

## MegaVul clean and attack runs

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
$env:BEAM_WIDTH = "8"
$env:VARIANT_M = "3"
$env:REWRITE_MAX_IDS = "3"
$env:DIVERSITY_LAMBDA = "0.1"
$env:EDIT_LAMBDA = "0.0"
python scripts/rag_da_reproduce.py --mode attack --recompute-variant-similarity
```

`--recompute-variant-similarity` is enabled by default. It recomputes retrieval
similarity for each renamed demonstration variant using the same embedding models
as clean RAG.

## BigVul zero-transfer runs

```powershell
$env:INPUT_FILE = "datasets/bigvul_hf/test_subset_1208_no_overlap.xlsx"
$env:TRAIN_FILE = "datasets/train/train_all.xlsx"
$env:OUTPUT_FILE = "result2/reproduce/bigvul_clean.xlsx"
python scripts/rag_da_reproduce.py --mode clean
```

```powershell
$env:INPUT_FILE = "datasets/bigvul_hf/test_subset_1208_no_overlap.xlsx"
$env:TRAIN_FILE = "datasets/train/train_all.xlsx"
$env:OUTPUT_FILE = "result2/reproduce/bigvul_attack.xlsx"
python scripts/rag_da_reproduce.py --mode attack --recompute-variant-similarity
```

`TRAIN_FILE` keeps retrieved demonstrations within the MegaVul training split
while evaluating on BigVul.

## Dry run

```powershell
$env:SMALL_RUN_MAX = "3"
python scripts/rag_da_reproduce.py --mode attack --dry-run
```

## Metrics

```powershell
python scripts/compute_metrics.py `
  --predictions result2/reproduce/megavul_attack.xlsx `
  --clean result2/reproduce/megavul_clean.xlsx
```

This prints accuracy, macro-F1, MCC, CMR_adv, DSR, and true ASR using
`src/rag_da_metrics.py`.

## Release hygiene

Before publishing:

- confirm `Select-String -Recurse -Pattern 'sk-'` returns no API keys;
- keep only sanitized scripts with environment-variable credentials;
- include split IDs or hashes for datasets that cannot be redistributed;
- document model strings, decoding settings, and artifact paths used in your runs.
