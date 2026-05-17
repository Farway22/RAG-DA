import json
from code_trans.gen_attack.compute_ast_structure_distance import compute_ast_structure_stats

paths = {
    'lexical': 'result2/baseline_lexical_demos_full.jsonl',
    'random': 'result2/baseline_random_demos_full.jsonl',
    'greedy': 'result2/baseline_greedy_demos_full.jsonl',
    'attack_only': 'result2/baseline_attack_only_demos_full.jsonl',
}

res = {}
for name, path in paths.items():
    try:
        stats = compute_ast_structure_stats(path, max_sample_id=None, max_pairs=100)
        res[name] = stats
    except Exception as e:
        res[name] = {'error': str(e)}

print(json.dumps(res, indent=2))
