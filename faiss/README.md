# FAISS Index Placeholder

The full RAG/RAG-DA pipeline expects local FAISS indexes in this directory:

- `faiss_index_code.index`
- `faiss_index_desc.index`
- `id_map.json`

The `.index` files are generated artifacts derived from the local dataset and
are not committed by default.  Rebuild them from the released/prepared dataset,
or download them from the external artifact archive if one is provided.
