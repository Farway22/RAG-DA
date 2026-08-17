# Dataset Split and Subset Provenance

This document records the retained data preparation needed to identify the
evaluation populations. The benchmark payloads remain governed by their
original licenses and are not redistributed here.

## MegaVul

The MegaVul release reports 17,380 vulnerabilities. The retained C/C++
function-level snapshot used by this project contains 14,235 rows. Requiring a
non-empty function, one of the four severity labels, and successful parsing
leaves 12,071 rows. Five residual rows are omitted when fixing the per-class
integer allocation for the retained stratified 80/10/10 split.

| Split | Rows | LOW | MEDIUM | HIGH | CRITICAL |
| --- | ---: | ---: | ---: | ---: | ---: |
| Train | 9,651 | 238 | 3,791 | 4,453 | 1,169 |
| Validation | 1,207 | 30 | 474 | 557 | 146 |
| Test | 1,208 | 29 | 475 | 557 | 147 |
| Total | 12,066 | 297 | 4,740 | 5,567 | 1,462 |

The retained files are an instance-level split. A CVE identifier can occur in
more than one split; clean accuracy should therefore not be interpreted as an
unseen-CVE generalization estimate.

The license-safe row identifiers and hashes under
`artifacts/split_manifests/` bind these counts to the retained external files
without publishing source code or descriptions. They can be regenerated with
`scripts/build_split_manifest.py`.

## BigVul zero-transfer subset

The BigVul subset is generated as follows:

1. Load the retained BigVul test table.
2. Remove every row whose `cve_id` occurs in the MegaVul test split.
3. For each severity independently, sample the number of rows observed in the
   MegaVul test split using pandas `DataFrame.sample(..., random_state=42)`.
4. Concatenate the strata in sorted severity order.

This produces 1,208 rows with counts LOW=29, MEDIUM=475, HIGH=557, and
CRITICAL=147, and zero CVE-ID overlap with the MegaVul test split. Run:

```powershell
python scripts/prepare_bigvul_subset.py `
  --mega-test datasets/test/test_all.xlsx `
  --bigvul-test datasets/bigvul_hf/test_all.xlsx `
  --description-source knowledge/train_all_with_nvd_cwe.xlsx `
  --output datasets/bigvul_hf/test_subset_1208_no_overlap.xlsx `
  --seed 42
```

Descriptions used by the inference pipeline are joined by `cve_id` after
sampling from the first retained description per CVE; that metadata join does
not change subset membership.

## Hyperparameter record

The reported configuration is frozen in `configs/vuln_beam_best.yaml`.
The retained selection record covers the final setting and the reported beam
sensitivity values `B in {2, 4, 8, 16}`. The complete pilot-search trace is
unavailable; the documented record is therefore limited to these retained
settings.
