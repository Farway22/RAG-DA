import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from rag_da import rag_da_attack

fixed_demos = [
    {
        "code": "void process_data(char* buffer, int size) { memcpy(dest, buffer, size); }",
        "description": "Buffer copy without bounds check",
        "cve_id": "CVE-2023-XXXX",
        "base_severity": "HIGH",
        "score": 0.95,
        "cwe_ids": "CWE-120"
    },
    {
        "code": "int parse_input(char* input) { strcpy(buf, input); return 0; }",
        "description": "Unsafe string copy",
        "cve_id": "CVE-2023-YYYY",
        "base_severity": "CRITICAL",
        "score": 0.92,
        "cwe_ids": "CWE-120"
    }
]

attack_demos = rag_da_attack(
    fixed_demos=fixed_demos,
    k=2,
    beam_width=8,
    variant_m=3,
    max_ids=3,
    seed=42,
    w_sim=1.0,
    diversity_lambda=0.1,
    edit_lambda=0.0,
    # Demo-only tie breaker so the smoke test visibly shows an edited variant.
    # Full experiments pass a retriever-based variant_score_fn instead.
    variant_score_fn=lambda variant, original: float(original.get("score", 0.0)) + 0.01 * int(variant.get("_is_edited", 0)),
)

for i, demo in enumerate(attack_demos):
    print(f"Demo {i+1}:")
    print(f"  CVE: {demo.get('cve_id')}")
    print(f"  Edited: {demo.get('_is_edited')}")
    print(f"  Code: {demo.get('code')[:50]}...")

