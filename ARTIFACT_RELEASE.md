# Artifact Release Guide

This file records what should be committed to the GitHub repository and what is
better published as a release asset or external archive.

## Current Size Snapshot

Approximate local sizes observed in the working directory before pruning the
public release:

| Path | Size |
| --- | ---: |
| `result2/` | 388 MB |
| `datasets/` | 173 MB |
| `code_trans/` | 141 MB |
| `faiss/` | 43 MB |

The largest files in `result2/` are long run logs and full demonstration dumps,
for example:

| File type | Example size |
| --- | ---: |
| GPT-5.1 attack log | 89.77 MB |
| Grok attack log | 58.63 MB |
| Qwen full attack workbook/log copy | 42.42 MB |
| Baseline demonstration JSONL dumps | about 23 MB each |

These files are below GitHub's hard 100 MB per-file limit, but committing many
of them makes the repository slow to clone and review.

## Recommended GitHub Contents

Commit to git:

- source code and scripts;
- README and reproduction documentation;
- small sample data;
- table-level summaries such as compact `.json`, `.md`, or small `.xlsx`
  files;
- split metadata, hashes, and preprocessing scripts;
- small figures used by the paper or README.

Publish outside git when large:

- raw benchmark datasets;
- FAISS indexes and embedding caches;
- full run logs;
- full prompt/response traces;
- large intermediate JSONL dumps;
- model weights and tokenizer caches.

Good external locations include GitHub Releases, Zenodo, OSF, institutional
storage, or Google Drive.  If an artifact is external, keep its expected local
path in the README so users know where to place it after download.

Dataset payloads are ignored by `.gitignore` in this repository.  The public
repository should keep only `datasets/README.md` and subdirectory placeholder
READMEs unless the dataset license explicitly permits redistribution and the
file size is appropriate for git.

## Suggested Result Policy

Keep enough external result files to make the paper tables traceable:

- compact metric summaries, such as `result2/bigvul_results_metrics.json`;
- final prediction workbooks used for reported numbers;
- `EXPERIMENT_MANIFEST.md`, which maps result files to paper sections.

Avoid committing generated logs such as `*_run.log` and large intermediate
`*_demos_full.jsonl` files unless they are necessary for a specific archival
claim.
