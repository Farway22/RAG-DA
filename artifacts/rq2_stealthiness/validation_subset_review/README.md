# High-confidence transformation subset

`validation_subset_candidates.jsonl` contains the 15 frozen historical pairs
used by the executable spot checks. The subset is derived deterministically
from the full paired-demonstration artifact. Its stored family labels describe
the historical screening run and are not presented as output from the current
canonical generator.

These pairs test whether a token-consistent identifier substitution can retain
compilation and observed behavior. They are not a golden-output test for the
paper-facing candidate generator. Candidate-generation conformance and a
separate set of pairs regenerated from the current implementation are provided
in `tests/test_rag_da_algorithm.py` and `../canonical_generator_review/`.

To rebuild it, provide the artifact and repository source paths explicitly:

```powershell
python build_validation_subset.py `
  --input path/to/full1208_ast_demos.jsonl `
  --repo-src ../../../src `
  --output-dir . `
  --target-size 15
```

The rebuild script evaluates names using the current Snake/Camel subtoken
classifier. The full input artifact is not bundled in this review subset. The
checked-in JSONL, CSV, and Markdown outputs remain available to inspect the
historical pairs.
