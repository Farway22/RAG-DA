# Artifact Scope

This repository is a **reference implementation** of RAG-DA as described in the
paper. Reviewers and third parties can inspect the attack logic, default
hyperparameters, and metric code here. **End-to-end numbers** (CMR, DSR, accuracy,
etc.) still depend on datasets, FAISS indexes, and model endpoints that are
distributed separately and may drift over time.

## What you can check in this repository

1. **Threat model** — Only retrieved demonstration *code* is modified; query,
   retriever index, prompt template, and model weights stay fixed
   (`scripts/rag_da_reproduce.py`).

2. **Algorithm 1 structure** — For `topk = k` retrieved demonstrations, beam
   search returns `k` variants with **one variant per demonstration** (no
   subsampling from a larger pool):

   ```powershell
   python tests/test_rag_da_algorithm.py
   ```

3. **Default hyperparameters** — `configs/vuln_beam_best.yaml` and environment
   defaults (`TOPK=5`, `BEAM_WIDTH=8`, `VARIANT_M=3`, `REWRITE_MAX_IDS=3`,
   `RAG_ALPHA=0.6`, `RAG_BETA=0.4`).

4. **Metric definitions** — `src/rag_da_metrics.py` and
   `scripts/compute_metrics.py` implement DSR, CMR, and true ASR as in Section 5.5.

5. **Smoke test without external data** — `python examples/rag-da-example.py`
   exercises AST renaming and beam selection on toy demonstrations only.

## What this repository does not claim

| Factor | Why reported numbers may differ across runs |
| --- | --- |
| Commercial LLM APIs | Provider updates, routing, decoding (see Section 5.6). |
| Local GPU / driver stack | PyTorch/CUDA build differences for open-weight models. |
| Dataset snapshots | MegaVul/BigVul splits are not redistributed in git. |
| FAISS indexes | Must be rebuilt or downloaded; ties can change with caches. |
| Beam weights | Paper λ₁, λ₂, λ₃ were tuned on validation; public defaults are in `configs/vuln_beam_best.yaml`. |

## Suggested wording (paper / README / rebuttal)

- Reasonable: “We release code that implements RAG-DA (Section 4) and the metric
  definitions used in our evaluation.”
- Reasonable: “In-repo unit tests and the smoke example check attack structure
  without external data.”
- Avoid: “Cloning this repo alone reproduces every value in Table 2.”
- Avoid: “Independent reruns will match our lab numbers bit-for-bit.”

## Suggested workflow for external readers

1. `python tests/test_rag_da_algorithm.py` — structure only, no API.
2. `python examples/rag-da-example.py` — toy demo, no API.
3. Obtain datasets + FAISS per `datasets/README.md` and `faiss/` instructions.
4. Configure model credentials; run `scripts/rag_da_reproduce.py` (clean, then attack).
5. Use `scripts/compute_metrics.py` on your outputs; compare **trends** (e.g.,
   higher CMR/DSR under attack) when setups are similar, not necessarily every
   table digit unless artifacts and backends match ours.
