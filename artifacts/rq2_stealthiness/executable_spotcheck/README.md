# Executable transformation spot checks

This directory contains 15 paired clean/adversarial C/C++ spot checks. The
committed `sources/` files are generated from the frozen review subset. Build
products are written only to `build/` and are intentionally ignored.

The suite provides compilation and observed-behavior evidence for these
historical pairs. Conformance of the current core-preserving template generator
is checked separately in `tests/test_rag_da_algorithm.py`.

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

The evidence scope is the 15 self-contained or minimally stubbed functions in
this executable spot check; project-level validation uses the corresponding
upstream projects and full experiment artifacts.
