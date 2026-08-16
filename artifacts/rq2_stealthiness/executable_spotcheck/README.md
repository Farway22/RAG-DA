# Executable transformation spot checks

This directory contains 15 paired clean/adversarial C/C++ spot checks. The
committed `sources/` files are generated from the frozen review subset. Build
products are written only to `build/` and are intentionally ignored.

The suite provides compilation and observed-behavior evidence for these
historical pairs. It does not assert that every historical destination name is
emitted by the current core-preserving template generator; conformance of that
algorithm is checked in `tests/test_rag_da_algorithm.py`.

## Run

On Windows with Visual Studio Build Tools 2022 installed:

```powershell
python run_spotchecks.py
```

Optional paths can be overridden:

```powershell
python run_spotchecks.py `
  --subset ../validation_subset_review/validation_subset_candidates.jsonl `
  --sources-dir sources `
  --build-dir build `
  --results-json spotcheck_results.json `
  --results-md spotcheck_results.md
```

The runner locates MSVC through `vswhere`, compiles clean and adversarial
variants separately, executes each pair with identical inputs, and compares
exit status, standard output, standard error, and compiler diagnostic
categories. The checked-in summary records the compiler family and version,
not machine-specific paths.

This suite is an executable spot check on self-contained or minimally stubbed
functions. It does not establish project-level compilability or behavioral
equivalence for the full dataset.
