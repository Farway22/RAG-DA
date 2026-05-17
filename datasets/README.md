# Datasets

This directory contains local dataset files used by the RAG-DA experiments.
Some benchmark datasets are large or have redistribution constraints, so a
public release may include only small samples, split metadata, checksums, and
download/preparation instructions.

The repository `.gitignore` excludes dataset payloads by default.  Keep this
README and the subdirectory placeholder READMEs in git, then place the real
files at the paths below after downloading or preprocessing the datasets.

## Expected Files

The full reproduction scripts look for the following paths:

| Purpose | Expected path |
| --- | --- |
| MegaVul test split | `datasets/test/test_all.xlsx` |
| MegaVul training split | `datasets/train/train_all.xlsx` |
| BigVul zero-transfer test split | `datasets/bigvul_hf/test_subset_1208_no_overlap.xlsx` |
| CSV fallback knowledge base | `datasets/megavul_simple_cpp_success_getast.csv` |

## Minimal Example

The smoke test in the repository root does not require these datasets:

```powershell
python rag-da-example.py
```

## Public Release Guidance

For datasets that cannot be redistributed directly:

- provide the original download link or citation;
- provide preprocessing scripts when licensing permits;
- provide split IDs, row hashes, or checksums;
- include a small synthetic/sample file for testing the code path;
- do not commit private data, credentials, or license-restricted raw dumps.

The full RAG pipeline also expects FAISS indexes under `faiss/`.  If the index
files are too large for git, publish them through GitHub Releases, Zenodo, or
another archival storage service and document the download location in the main
README.
