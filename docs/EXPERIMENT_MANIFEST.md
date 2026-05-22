# Experiment Manifest

This manifest documents where full experiment artifacts should be placed when
reproducing the paper locally.  The GitHub repository keeps code and
placeholders only; datasets, FAISS indexes, full prediction workbooks, logs,
and paper figures should be distributed through an external artifact archive
when licensing and size permit.

## Canonical Code Path

| Purpose | Path |
| --- | --- |
| Core RAG-DA implementation | `src/rag_da.py` |
| Minimal runnable example | `examples/rag-da-example.py` |
| Clean/attack runner | `scripts/rag_da_reproduce.py` |
| Retrieval and prompting | `src/retrieval.py` |
| Metrics | `src/rag_da_metrics.py`, `scripts/compute_metrics.py` |

## Model Labels

| Paper label | Release model string |
| --- | --- |
| DeepSeek-V3.2 | `deepseek-ai/DeepSeek-V3.2` |
| Qwen3-Coder | `Qwen/Qwen3-Coder-30B-A3B-Instruct` |
| GPT-5.1 | `gpt-5.1` |
| Grok-4.1-Fast | `x-ai/grok-4.1-fast:free` |

## Expected External Artifacts

Place external artifacts at these paths if you want to verify paper tables from
cached predictions rather than rerunning the models:

| Area | Expected local path |
| --- | --- |
| BigVul clean baseline | `result2/bigvul_cross_dataset/deepseek_v3_2/clean_baseline/baseline_k5_results.xlsx` |
| BigVul RAG-DA attack | `result2/bigvul_cross_dataset/deepseek_v3_2/attack/attack_results.xlsx` |
| BigVul summary metrics | `result2/bigvul_results_metrics.json` |
| CoT ablation metrics | `result2/cot_ablation_dsr_cmr_results.json` |
| No-CoT attack predictions | `result2/attack_no_cot.xlsx` |
| No-CoT clean baseline | `result2/clean_baseline_no_cot.xlsx` |
| Qwen attack predictions | `result2/qwen_full_attack_results.xlsx` |
| GPT-5.1 attack predictions | `result2/gpt51_full_attack_results.xlsx` |
| Ablation summaries | `results/ablation_*.csv` |

These files are not committed by default.  Use GitHub Releases, Zenodo, OSF, or
another archival service for the full artifact bundle.

## Dataset and Index Paths

| Purpose | Expected local path |
| --- | --- |
| MegaVul test split | `datasets/test/test_all.xlsx` |
| MegaVul training split | `datasets/train/train_all.xlsx` |
| BigVul zero-transfer split | `datasets/bigvul_hf/test_subset_1208_no_overlap.xlsx` |
| CSV fallback knowledge base | `datasets/megavul_simple_cpp_success_getast.csv` |
| FAISS code index | `faiss/faiss_index_code.index` |
| FAISS description index | `faiss/faiss_index_desc.index` |
| FAISS row map | `faiss/id_map.json` |
