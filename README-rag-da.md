# RAG-DA Reference API Notes

This file provides a compact import example for the attack core. For artifact
scope and end-to-end instructions, use `README.md` and
`docs/REPRODUCIBILITY.md`.

```python
from rag_da import rag_da_attack

fixed_demos = [...]  # retriever output for one query
attack_demos = rag_da_attack(
    fixed_demos=fixed_demos,
    k=5,
    beam_width=8,
    variant_m=3,
    max_ids=3,
    seed=42,
    w_sim=1.0,
    diversity_lambda=0.1,
    edit_lambda=0.0,
)
```

The function returns one selected variant for each demonstration supplied to
the reference attack core. Non-code fields should remain unchanged.

## Important parameters

- `fixed_demos`: demonstrations supplied by the retrieval stage;
- `k`: number of demonstrations passed to the prompt;
- `beam_width`: retained partial paths;
- `variant_m`: maximum number of distinct variants per demonstration,
  including the unchanged variant; a smaller pool is returned when necessary;
- `max_ids`: maximum identifiers rewritten per demonstration;
- `variant_score_fn`: optional callback for recomputing query similarity after
  identifier renaming.

The recorded default uses `diversity_lambda=0.1` and `edit_lambda=0.0`.
Consequently, edit distance is available as an optional regularizer but is not
part of the default beam ranking.

This import example checks the attack interface only. Paper-table reproduction
also requires the matched datasets, indexes, prompts, model backends, paired
predictions, and configuration snapshot listed in
`docs/EXPERIMENT_MANIFEST.md`.
