# Running the Reference Artifact

This guide covers the public reference runner. It assumes that the user has
obtained compatible benchmark files, FAISS artifacts, and a model backend. See
`REPRODUCTION_SCOPE.md` before comparing fresh outputs with paper tables.

## Logic-only checks

```powershell
python tests/test_rag_da_algorithm.py
python examples/rag-da-example.py
```

These checks require no benchmark data, index, database, or API credential.

## Environment

```powershell
pip install -r requirements/requirements.txt
```

Credentials and endpoint settings must be supplied through environment
variables. Do not commit real keys.

```powershell
$env:DEEPSEEK_API_KEY = "<api key>"
$env:DEEPSEEK_BASE_URL = "https://api.example.com/v1"
$env:DEEPSEEK_MODEL = "deepseek-ai/DeepSeek-V3.2"
```

Equivalent OpenAI-compatible backends may be configured with the corresponding
`GPT_*`, `QWEN_*`, or `XAI_*` variables. The commercial API configurations
recorded for the study are:

```powershell
$env:OPENAI_API_KEY = "<OpenAI API key>"
$env:GPT_BASE_URL = "https://api.openai.com/v1"
$env:GPT_MODEL = "gpt-5.1"

$env:XAI_API_KEY = "<xAI API key>"
$env:XAI_BASE_URL = "https://api.x.ai/v1"
$env:XAI_MODEL = "grok-4-1-fast-reasoning"
```

These are official-provider request identifiers, not third-party gateway route
names. Because commercial providers can revise or retire served backends, a
fresh call may not reproduce an archived response exactly.

## External files

| Purpose | Expected path |
| --- | --- |
| MegaVul test split | `datasets/test/test_all.xlsx` |
| MegaVul training split | `datasets/train/train_all.xlsx` |
| BigVul transfer split | `datasets/bigvul_hf/test_subset_1208_no_overlap.xlsx` |
| Code FAISS index | `faiss/faiss_index_code.index` |
| Description FAISS index | `faiss/faiss_index_desc.index` |
| FAISS row map | `faiss/id_map.json` |
| CSV fallback knowledge base | `datasets/megavul_simple_cpp_success_getast.csv` |

PostgreSQL is optional. The CSV fallback is used when a database connection is
not configured and the fallback file is available.

The exact split counts, license-safe row identifiers, file checksums, BigVul
sampling algorithm, and random seed are documented in `DATA_SPLITS.md` and
`../artifacts/split_manifests/`.

## Reference MegaVul run

Clean baseline:

```powershell
$env:INPUT_FILE = "datasets/test/test_all.xlsx"
$env:OUTPUT_FILE = "result2/reproduce/megavul_clean.xlsx"
python scripts/rag_da_reproduce.py --mode clean
```

Attack run:

```powershell
$env:INPUT_FILE = "datasets/test/test_all.xlsx"
$env:OUTPUT_FILE = "result2/reproduce/megavul_attack.xlsx"
$env:TOPK = "5"
$env:POOL_SIZE = "30"
$env:BEAM_WIDTH = "8"
$env:VARIANT_M = "3"
$env:REWRITE_MAX_IDS = "3"
python scripts/rag_da_reproduce.py --mode attack --recompute-variant-similarity
```

The public runner loads `configs/vuln_beam_best.yaml` by default. Environment
variables override its values, and explicit CLI arguments override both. Use
`--config <path>` to select another manifest. `POOL_SIZE` controls the retained
retrieval candidate pool; `TOPK` controls the ordered demonstrations passed to
the prompt.

The slot-ranking configuration records frequency, unsafe-call proximity, and
role weights of `1.0`, `1.0`, and `2.0`, respectively. Frequency is capped as
`min(5 * occurrence_count, 50)`; unsafe-call proximity adds 10 per matching call
expression. `family_mode: family` enables Snake/Camel identifier decomposition
and assignment to the six semantic families described in the paper. Family
membership combines lexical-overlap and AST-context scores with weights `1.0`
and `0.5`; the minimum assignment score is `0.5`, and lower-scoring identifiers
are left unchanged. Family-specific templates are implemented in
`src/rag_da.py`. The variant seed is combined with a stable identifier digest,
so it does not depend on Python's process-randomized `hash()`.

The offline dataset-frequency step used to curate the seed lexicons is exposed
by `scripts/build_semantic_lexicon.py`. It uses the same C/C++ parser and
variable extraction path as the attack implementation and reports identifier
and Snake/Camel subtoken frequencies without changing the frozen lexicons at
run time.

Both `tree-sitter-c` and `tree-sitter-cpp` are installed by the requirements
manifest. The attack parses each snippet with the available C and C++ grammars,
keeps an error-free parse, and resolves uses to the nearest visible lexical
declaration before applying a rename. The paper-facing configuration sets
`allow_lexical_fallback: false`: if neither grammar yields an error-free tree,
the candidate is left unchanged. The runner exposes `--allow-lexical-fallback`
only for explicit smoke-test use.

## Reference BigVul transfer run

Build the transfer subset from locally obtained benchmark tables:

```powershell
python scripts/prepare_bigvul_subset.py `
  --mega-test datasets/test/test_all.xlsx `
  --bigvul-test datasets/bigvul_hf/test_all.xlsx `
  --description-source knowledge/train_all_with_nvd_cwe.xlsx `
  --output datasets/bigvul_hf/test_subset_1208_no_overlap.xlsx `
  --seed 42
```

Use the BigVul query split while retaining the MegaVul training pool:

```powershell
$env:INPUT_FILE = "datasets/bigvul_hf/test_subset_1208_no_overlap.xlsx"
$env:TRAIN_FILE = "datasets/train/train_all.xlsx"
$env:OUTPUT_FILE = "result2/reproduce/bigvul_attack.xlsx"
python scripts/rag_da_reproduce.py --mode attack --recompute-variant-similarity
```

## Metrics

```powershell
python scripts/compute_metrics.py `
  --predictions result2/reproduce/megavul_attack.xlsx `
  --clean result2/reproduce/megavul_clean.xlsx
```

Paired metrics must use a stable query identifier shared by the clean and attack
files. The manuscript definitions are summarized in `REPRODUCTION_SCOPE.md`.

## Paired statistical analysis

`scripts/analyze_main_statistics.py` accepts a compact query-level CSV:

| Column | Meaning |
| --- | --- |
| `model` | Paper model label |
| `query_id` | Stable identifier within the model |
| `y_true` | Ground-truth severity |
| `y_clean` | Parsed clean prediction |
| `y_adv` | Parsed attacked prediction |

The file contains labels only; it need not disclose vulnerability source code,
retrieved demonstrations, prompts, explanations, or model responses. Blank
prediction fields represent unparseable responses and remain incorrect cases
in the global-accuracy denominator.

```powershell
python scripts/analyze_main_statistics.py `
  --input artifacts/main_predictions.csv `
  --output-prefix artifacts/main_statistics
```

The output records the input SHA-256 digest and reports point estimates and
counts, 95% bootstrap intervals, two-sided exact McNemar tests,
paired sign-flip tests on the ground-truth High/Critical subset, and Holm
adjustments across models. The default settings match the manuscript: 10,000
bootstrap resamples, 100,000 permutations, and seed `20260201`.

No manuscript values or prediction snapshot are built into the command. When a
matched private or archival snapshot is available, an optional JSON of
reference values can be passed with `--targets` to check displayed precision.

## What a fresh run can establish

A fresh run can check that the public pipeline executes and that the same metric
definitions can be applied to paired outputs. Matching every published digit
requires the original split, indexes, model/backend version, and paired
prediction artifacts; API-backed outputs may also vary as providers update
their services.
