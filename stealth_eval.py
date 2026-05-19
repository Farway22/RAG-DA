"""Archival stealth-metric helper for private experiment dumps.

The public artifact intentionally omits the historical ``code_trans/`` tree
and large demonstration JSONL files.  Keep this script only as a pointer for
authors who have the private archive; public users should rely on
``rag-da-metrics.py`` and ``evaluation.py``.
"""

import json

try:
    from code_trans.gen_attack.compute_ast_structure_distance import compute_ast_structure_stats
except ImportError as exc:
    raise SystemExit(
        "stealth_eval.py requires the omitted code_trans/ tree and private "
        "baseline_*_demos_full.jsonl files. It is not part of the public "
        "reproduction path."
    ) from exc


paths = {
    "lexical": "result2/baseline_lexical_demos_full.jsonl",
    "random": "result2/baseline_random_demos_full.jsonl",
    "greedy": "result2/baseline_greedy_demos_full.jsonl",
    "attack_only": "result2/baseline_attack_only_demos_full.jsonl",
}

res = {}
for name, path in paths.items():
    try:
        stats = compute_ast_structure_stats(path, max_sample_id=None, max_pairs=100)
        res[name] = stats
    except Exception as e:
        res[name] = {"error": str(e)}

print(json.dumps(res, indent=2))
