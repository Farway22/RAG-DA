# RAG-DA: Retrieval-Augmented Demonstration Attack for SVA

![RAG-DA Framework](framework.png)

This repository provides a reference implementation of the
Retrieval-Augmented Demonstration Attack (RAG-DA) for software vulnerability
assessment (SVA). RAG-DA modifies only retrieved demonstration code while
leaving the assessed query, demonstration labels and metadata, prompt template,
and model parameters unchanged.

## Artifact scope

The repository includes the attack logic, prompt construction, configuration
manifest, metric code, and logic-level checks. Reproducing the exact paper
tables additionally requires matched benchmark snapshots, split metadata,
FAISS artifacts, prediction files, and model/API backends. See
`docs/REPRODUCTION_SCOPE.md` for the precise boundary.

## Quick checks

The following checks require neither benchmark data nor API credentials:

```powershell
python tests/test_rag_da_algorithm.py
python examples/rag-da-example.py
```

The smoke example should print two toy demonstrations with `Edited: 1`.

The executable spot check first regenerates 15 pairs with the
released canonical generator, then compiles and executes them. It requires
MSVC Build Tools but no benchmark data or API credentials:

```powershell
Push-Location artifacts/rq2_stealthiness/canonical_generator_review
python build_canonical_generator_subset.py
python ../executable_spotcheck/run_spotchecks.py `
  --subset canonical_generator_pairs.jsonl `
  --sources-dir canonical_sources `
  --build-dir canonical_build `
  --results-json canonical_spotcheck_results.json `
  --results-md canonical_spotcheck_results.md
Pop-Location
```

An additional audit of the frozen historical pairs is available via
`python artifacts/rq2_stealthiness/executable_spotcheck/run_spotchecks.py`.

## Repository map

| Purpose | Path |
| --- | --- |
| Attack core | `src/rag_da.py` |
| Retrieval, prompting, and backend calls | `src/retrieval.py` |
| Reference clean/attack runner | `scripts/rag_da_reproduce.py` |
| Semantic-lexicon frequency builder | `scripts/build_semantic_lexicon.py` |
| Metric CLI | `scripts/compute_metrics.py` |
| Generic paired statistics and tests | `scripts/analyze_main_statistics.py` |
| Metric primitives | `src/rag_da_metrics.py` |
| Paper configuration manifest | `configs/vuln_beam_best.yaml` |
| Prompt template specification | `docs/PROMPT_TEMPLATES.md` |
| Run guide | `docs/REPRODUCIBILITY.md` |
| Split construction and provenance | `docs/DATA_SPLITS.md` |
| License-safe split IDs/checksums | `artifacts/split_manifests/` |
| Public/external artifact boundary | `docs/REPRODUCTION_SCOPE.md` |
| Expected experiment artifacts | `docs/EXPERIMENT_MANIFEST.md` |
| Release policy | `docs/ARTIFACT_RELEASE.md` |
| Executable paired-transformation spot checks | `artifacts/rq2_stealthiness/executable_spotcheck/` |
| Current-generator paired compilation/behavior check | `artifacts/rq2_stealthiness/canonical_generator_review/` |
| Frozen spot-check subset and selection audit | `artifacts/rq2_stealthiness/validation_subset_review/` |

`src/rag_da.py` provides the canonical beam-search and candidate-generation
implementation used by the reference runner. `src/retrieval.py` handles
retrieval, prompt construction, and backend calls, while query rewriting is
outside its interface. `src/rename_ast.py` forwards older imports to the
canonical candidate generator.

## Reference pipeline

The public runner demonstrates the following workflow:

1. retrieve vulnerability demonstrations with the dual-channel retriever;
2. construct identifier-renaming variants for retrieved code;
3. select one variant per demonstration with heuristic beam search;
4. build the same downstream SVA prompt for clean and attacked runs;
5. call a configured model backend and save resumable predictions;
6. compute downgrade-oriented metrics from paired outputs.

The runner loads `configs/vuln_beam_best.yaml` by default. Environment variables
override YAML defaults, and explicit CLI arguments override both. A different
manifest can be selected with `--config`.

The public core loads both tree-sitter C and C++ grammars, selects the cleaner
parse for each snippet, and resolves identifier uses to the nearest visible
lexical declaration so nested shadowed bindings remain distinct. It follows
the recorded experiment heuristic: dictionary-based identifier families;
capped occurrence, unsafe-call, and role terms for slot
ranking with weights `1.0/1.0/2.0`; and cumulative beam scoring over query
similarity and average candidate-to-path diversity. Stealthiness is enforced
primarily through constrained candidate generation, while edit-distance
regularization remains configurable. Identifier-level randomness uses a
stable digest combined with the configured variant seed. Candidate pools are
deduplicated; if a snippet has fewer collision-free renamings than `variant_m`,
the core returns the smaller set of distinct variants.

## External-data run

Install dependencies:

```powershell
pip install -r requirements/requirements.txt
```

Configure an OpenAI-compatible backend, for example:

```powershell
$env:DEEPSEEK_API_KEY = "<api key>"
$env:DEEPSEEK_BASE_URL = "https://api.example.com/v1"
$env:DEEPSEEK_MODEL = "deepseek-ai/DeepSeek-V3.2"
```

Run the reference clean and attack paths:

```powershell
$env:INPUT_FILE = "datasets/test/test_all.xlsx"
$env:OUTPUT_FILE = "result2/reproduce/megavul_clean.xlsx"
python scripts/rag_da_reproduce.py --mode clean

$env:OUTPUT_FILE = "result2/reproduce/megavul_attack.xlsx"
python scripts/rag_da_reproduce.py --mode attack --recompute-variant-similarity
```

Then compute metrics from paired prediction files:

```powershell
python scripts/compute_metrics.py `
  --predictions result2/reproduce/megavul_attack.xlsx `
  --clean result2/reproduce/megavul_clean.xlsx
```

For paired uncertainty estimates and statistical tests on any compatible
prediction snapshot, use the compact format described in
`docs/REPRODUCIBILITY.md`:

```powershell
python scripts/analyze_main_statistics.py `
  --input artifacts/main_predictions.csv `
  --output-prefix artifacts/main_statistics
```

This produces JSON, CSV, and Markdown summaries using 10,000 paired
query-level bootstrap resamples, 100,000 paired sign-flip permutations,
two-sided exact McNemar tests, and Holm correction across models. The analysis
uses compact paired prediction records rather than source-code payloads,
prompts, rationales, or API credentials.

Reported values remain external to the script. An optional reference-value
JSON can be supplied with `--targets` for an explicit check against a matched
prediction snapshot.

These commands use user-supplied data, indexes, and a compatible model backend.
Digit-level comparison with the paper requires the matched experiment
artifacts.

## Expected external artifacts

| Artifact | Expected path |
| --- | --- |
| MegaVul test split | `datasets/test/test_all.xlsx` |
| MegaVul training split | `datasets/train/train_all.xlsx` |
| BigVul transfer split | `datasets/bigvul_hf/test_subset_1208_no_overlap.xlsx` |
| FAISS code index | `faiss/faiss_index_code.index` |
| FAISS description index | `faiss/faiss_index_desc.index` |
| FAISS row map | `faiss/id_map.json` |
| CSV fallback knowledge base | `datasets/megavul_simple_cpp_success_getast.csv` |

The BigVul transfer split can be rebuilt with
`scripts/prepare_bigvul_subset.py`; the exact no-overlap rule, severity-stratum
sampling procedure, and seed are documented in `docs/DATA_SPLITS.md`.

## Model labels used in the study

| Paper label | Provider / mode | Recorded request model string |
| --- | --- | --- |
| DeepSeek-V3.2 | Local open-weight inference | `deepseek-ai/DeepSeek-V3.2` |
| Qwen3-Coder | Local open-weight inference | `Qwen/Qwen3-Coder-30B-A3B-Instruct` |
| GPT-5.1 | Official OpenAI API | `gpt-5.1` |
| Grok-4.1-Fast | Official xAI API | `grok-4-1-fast-reasoning` |

The exact API base URLs and the limits of the retained provider-version record
are documented in `docs/EXPERIMENT_MANIFEST.md`. API credentials must be
supplied through environment variables and must not be committed.

## Release status

The main branch contains license-safe split identifiers and checksums under
`artifacts/split_manifests/`. Third-party dataset payloads, generated FAISS
indexes, full prompt/response traces, and large prediction workbooks are
managed as external artifacts. Subject to benchmark licenses, compact result
summaries and the remaining audit artifacts are planned for an archival release
upon paper acceptance. The expected paths and release categories are documented
in `docs/EXPERIMENT_MANIFEST.md` and `docs/ARTIFACT_RELEASE.md`.
