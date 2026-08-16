# Experiment Artifact Manifest

This manifest separates material committed to the main branch from artifacts
required for exact paper-table auditing.

## In the main branch

| Purpose | Path |
| --- | --- |
| Attack implementation | `src/rag_da.py` |
| Retrieval and prompting | `src/retrieval.py` |
| Reference clean/attack runner | `scripts/rag_da_reproduce.py` |
| Metric implementation | `src/rag_da_metrics.py`, `scripts/compute_metrics.py` |
| Main-result statistics | `src/rag_da_statistics.py`, `scripts/analyze_main_statistics.py` |
| Paper configuration manifest | `configs/vuln_beam_best.yaml` |
| Prompt specification | `docs/PROMPT_TEMPLATES.md` |
| Split provenance | `docs/DATA_SPLITS.md` |
| Split IDs and checksums | `artifacts/split_manifests/` |
| BigVul subset builder | `scripts/prepare_bigvul_subset.py` |
| Logic-level checks | `tests/test_*.py` |

`scripts/rag_da_reproduce.py` is the only supported experiment entry point. It
calls `rag_da.rag_da_attack` for demonstration-only beam selection. The
retrieval module does not expose a second beam implementation, accept the
ground-truth severity as a selection input, or support query rewriting.

## External dataset and index artifacts

| Artifact | Expected local path | Main-branch status |
| --- | --- | --- |
| MegaVul test split | `datasets/test/test_all.xlsx` | External |
| MegaVul training split | `datasets/train/train_all.xlsx` | External |
| MegaVul validation split | `datasets/valid/valid_all.xlsx` | External |
| BigVul transfer split | `datasets/bigvul_hf/test_subset_1208_no_overlap.xlsx` | External |
| Code FAISS index | `faiss/faiss_index_code.index` | Generated/external |
| Description FAISS index | `faiss/faiss_index_desc.index` | Generated/external |
| FAISS row map | `faiss/id_map.json` | Generated/external |
| CSV knowledge-base fallback | `datasets/megavul_simple_cpp_success_getast.csv` | External |

## Released retriever defaults and index compatibility

The `embedding` block in `configs/vuln_beam_best.yaml` records the defaults of
the released runner: `microsoft/codebert-base` for code,
`shibing624/text2vec-base-multilingual` for descriptions, maximum input length
256, `first_last_avg` pooling, and L2-normalized output vectors. The code and
description similarities are combined with `alpha=0.6` and `beta=0.4`.

These values document the public implementation; they are not a reconstructed
claim about unretained historical metadata. Exact model revisions, FAISS index
type/metric, index-build commands, and index checksums were not retained in the
public artifact. Any externally supplied indexes must have been built with
encoders and preprocessing compatible with the runner. A future archival index
release should include those fields and the row-map checksum before claiming
fresh-run equivalence with the reported tables.

## Paired prediction and summary artifacts

| Analysis | Expected artifact |
| --- | --- |
| MegaVul clean baseline | `result2/paper/megavul_clean_predictions.*` |
| MegaVul RAG-DA attack | `result2/paper/megavul_attack_predictions.*` |
| Four-model main summary | `result2/paper/table2_metrics.*` |
| Component ablations | `result2/paper/table4_ablation_metrics.*` |
| Identifier-density analysis | `result2/paper/table10_identifier_density.*` |
| CoT sensitivity | `result2/paper/cot_sensitivity.*` |
| Retriever sensitivity | `result2/paper/retriever_sensitivity.*` |
| Paired statistical analysis | `result2/paper/statistical_inference.*` |
| Compact four-model audit input | `artifacts/main_predictions.csv` |

These filenames define the intended archival layout; the corresponding payloads
are not currently committed to the main branch.

The compact prediction schema is exactly
`model,query_id,y_true,y_clean,y_adv`. It contains no source code, vulnerability
description, prompt, rationale, or raw provider response. Once the matched
four-model snapshot is frozen, `scripts/analyze_main_statistics.py` reports the
integer numerator and denominator for every percentage and rejects duplicate
model/query pairs.

## Retained configuration-selection record

The final paper configuration is `configs/vuln_beam_best.yaml`. The retained
search record supports the final setting and the reported beam-width sensitivity
set `B in {2, 4, 8, 16}`. The full pilot-search trace was not retained, so the
artifact does not claim an exhaustive grid or reconstruct unverified search
ranges after the fact.

## Model and provider records

| Paper label | Provider / execution mode | API base URL type | Request model string | Version / snapshot record | Run date record |
| --- | --- | --- | --- | --- | --- |
| DeepSeek-V3.2 | Local open-weight inference | Not applicable | `deepseek-ai/DeepSeek-V3.2` | Repository/model checkpoint name | Not retained in the public artifact |
| Qwen3-Coder | Local open-weight inference | Not applicable | `Qwen/Qwen3-Coder-30B-A3B-Instruct` | Repository/model checkpoint name | Not retained in the public artifact |
| GPT-5.1 | Official OpenAI API | `https://api.openai.com/v1` | `gpt-5.1` | The requested alias was logged; a separately resolved backend snapshot was not exposed in the retained metadata | Not retained in the public artifact |
| Grok-4.1-Fast | Official xAI API | `https://api.x.ai/v1` | `grok-4-1-fast-reasoning` | Reasoning variant selected by the model ID; no separate immutable backend snapshot was exposed in the retained metadata | Not retained in the public artifact |

The commercial-model entries distinguish the API provider from the request
model string. They do not substitute third-party gateway routing names for the
identifiers sent to the official providers. Provider-side revisions and the
absence of immutable backend fingerprints limit exact fresh-run equivalence;
the planned compact prediction archive is therefore the audit record for the
reported table values.

## Planned archival metadata

Stable query identifiers and split-file checksums are already included in the
main branch. Subject to benchmark licenses, the acceptance-stage archive is
planned to add index metadata, configuration snapshots, compact table-level
summaries, and paired prediction identifiers sufficient to audit the reported
metrics. Raw third-party datasets, model weights, and API credentials are
outside the release scope.
