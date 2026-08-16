# coding:utf-8
import pandas as pd
import re
import requests
import psycopg2
import faiss
import numpy as np
import torch
from transformers import AutoTokenizer, AutoModel, AutoModelForSequenceClassification
import transformers
import os
import json
from openai import OpenAI
import time
from prompt_templates import build_simple_prompt
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"

# ================== 閰嶇疆 ==================
DEVICE = torch.device(os.getenv("DEVICE", "cuda" if torch.cuda.is_available() else "cpu"))
MAX_LENGTH = int(os.getenv("EMBED_MAX_LENGTH", "256"))
POOLING = os.getenv("EMBED_POOLING", "first_last_avg")
CODE_EMBEDDING_MODEL = os.getenv("CODE_EMBEDDING_MODEL", "microsoft/codebert-base")
DESC_EMBEDDING_MODEL = os.getenv("DESC_EMBEDDING_MODEL", "shibing624/text2vec-base-multilingual")
ALPHA = float(os.getenv("RAG_ALPHA", "0.6"))
BETA = float(os.getenv("RAG_BETA", "0.4"))
TOPK = int(os.getenv("TOPK", "5"))
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "1024"))

# ================== 鏁版嵁搴撹繛鎺?===================
def _connect_postgres():
    """Return an optional PostgreSQL connection.

    Public releases should not encode local database credentials.  Set either
    POSTGRES_DSN or POSTGRES_USER/POSTGRES_PASSWORD/POSTGRES_HOST explicitly
    when using a local vulnerability database.
    """
    dsn = os.getenv("POSTGRES_DSN", "").strip()
    user = os.getenv("POSTGRES_USER", "").strip()
    if not dsn and not user:
        print("[WARN] PostgreSQL not configured; using CSV fallback when possible.")
        return None, None

    kwargs = {
        "dbname": os.getenv("POSTGRES_DB", "rag-vul"),
        "user": user,
        "password": os.getenv("POSTGRES_PASSWORD", ""),
        "host": os.getenv("POSTGRES_HOST", "localhost"),
        "port": os.getenv("POSTGRES_PORT", "5432"),
    }
    try:
        conn_obj = psycopg2.connect(dsn) if dsn else psycopg2.connect(**kwargs)
        return conn_obj, conn_obj.cursor()
    except Exception as exc:
        print(f"[WARN] PostgreSQL unavailable; using CSV fallback when possible: {exc}")
        return None, None


conn, cur = _connect_postgres()

# Fallback dataset (when DB row missing): lazy loaded
_FALLBACK_DF = None
def _load_fallback_df():
    global _FALLBACK_DF
    if _FALLBACK_DF is not None:
        return _FALLBACK_DF
    try:
        csv_path = os.getenv("FALLBACK_CSV", "datasets/megavul_simple_cpp_success_getast.csv")
        _FALLBACK_DF = pd.read_csv(csv_path)
    except Exception:
        _FALLBACK_DF = None
    return _FALLBACK_DF

# ================== FAISS indexes (lazy) ==================
_index_code = None
_index_desc = None
_id_map = None


def _faiss_paths():
    root = os.getenv("FAISS_DIR", "faiss")
    return (
        os.getenv("FAISS_CODE_INDEX", os.path.join(root, "faiss_index_code.index")),
        os.getenv("FAISS_DESC_INDEX", os.path.join(root, "faiss_index_desc.index")),
        os.getenv("FAISS_ID_MAP", os.path.join(root, "id_map.json")),
    )


def _ensure_faiss_loaded() -> None:
    global _index_code, _index_desc, _id_map
    if _index_code is not None:
        return
    code_path, desc_path, map_path = _faiss_paths()
    for path, label in (
        (code_path, "code index"),
        (desc_path, "description index"),
        (map_path, "id map"),
    ):
        if not os.path.isfile(path):
            raise FileNotFoundError(
                f"Missing FAISS artifact ({label}): {path}. "
                "Place indexes under faiss/ or set FAISS_CODE_INDEX / "
                "FAISS_DESC_INDEX / FAISS_ID_MAP."
            )
    _index_code = faiss.read_index(code_path)
    _index_desc = faiss.read_index(desc_path)
    with open(map_path, "r", encoding="utf-8") as fh:
        _id_map = json.load(fh)


class _LazyFaissIndex:
    """Defer FAISS loading so imports work without local indexes."""

    def __init__(self, which: str) -> None:
        self._which = which

    def _index(self):
        _ensure_faiss_loaded()
        return _index_code if self._which == "code" else _index_desc

    def search(self, *args, **kwargs):
        return self._index().search(*args, **kwargs)

    def reconstruct(self, *args, **kwargs):
        return self._index().reconstruct(*args, **kwargs)


index_code = _LazyFaissIndex("code")
index_desc = _LazyFaissIndex("desc")


def get_vuln_info_by_faiss_idx(idx):
    _ensure_faiss_loaded()
    db_id = _id_map.get(str(idx))
    if db_id is None:
        return None
    try:
        if cur is None:
            raise RuntimeError("PostgreSQL cursor is not configured")
        cur.execute("""
                    SELECT cve_id,
                           cwe_ids,
                           code,
                           description,
                           base_score,
                           base_severity,
                           nvd_info,
                           cwe_info
                    FROM vulnerabilities
                    WHERE id = %s
                    """, (db_id,))
        row = cur.fetchone()
        if row:
            return {
                "cve_id": row[0],
                "cwe_ids": row[1],
                "code": row[2],
                "description": row[3],
                "base_score": row[4],
                "base_severity": row[5],
                "nvd_info": row[6],
                "cwe_info": row[7]
            }
    except Exception:
        pass
    # Fallback to CSV by row index (db_id assumed 1-based)
    df = _load_fallback_df()
    try:
        if df is not None and 1 <= int(db_id) <= len(df):
            r = df.iloc[int(db_id) - 1]
            return {
                "cve_id": r.get("cve_id", ""),
                "cwe_ids": r.get("cwe_ids", ""),
                "code": r.get("func_before", ""),
                "description": r.get("description", ""),
                "base_score": r.get("Base Score", 0.0),
                "base_severity": str(r.get("Base Severity", "")).upper(),
                "nvd_info": "",
                "cwe_info": "",
            }
    except Exception:
        pass
    return None


# ================== Embedding models (lazy) ==================
_code_tokenizer = None
_code_model = None
_desc_tokenizer = None
_desc_model = None


def _ensure_embed_models() -> None:
    global _code_tokenizer, _code_model, _desc_tokenizer, _desc_model
    if _code_model is not None:
        return
    _code_tokenizer = AutoTokenizer.from_pretrained(CODE_EMBEDDING_MODEL)
    _code_model = AutoModel.from_pretrained(CODE_EMBEDDING_MODEL).to(DEVICE)
    _code_model.eval()
    _desc_tokenizer = AutoTokenizer.from_pretrained(DESC_EMBEDDING_MODEL)
    _desc_model = AutoModel.from_pretrained(DESC_EMBEDDING_MODEL).to(DEVICE)
    _desc_model.eval()


# ================== Embedding helpers ==================
def embed_text(text, tokenizer, model, max_length=MAX_LENGTH, pooling=POOLING):
    # Ensure the embedding input is a string.
    if not isinstance(text, str):
        if text is None:
            text = ''
        else:
            text = str(text)
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=max_length)
    inputs = {k: v.to(DEVICE) for k, v in inputs.items()}
    with torch.no_grad():
        outputs = model(**inputs, output_hidden_states=True, return_dict=True)
        hidden_states = outputs.hidden_states
        if pooling == 'first_last_avg':
            vec = (hidden_states[-1] + hidden_states[1]).mean(dim=1)
        elif pooling == 'last_avg':
            vec = hidden_states[-1].mean(dim=1)
        elif pooling == 'last2avg':
            vec = (hidden_states[-1] + hidden_states[-2]).mean(dim=1)
        else:
            raise ValueError(f"Unknown pooling type: {pooling}")
    vec = vec.cpu().numpy()[0]
    return vec / np.linalg.norm(vec)

def embed_code(text):
    _ensure_embed_models()
    return embed_text(text, _code_tokenizer, _code_model)

def embed_desc(text):
    _ensure_embed_models()
    return embed_text(text, _desc_tokenizer, _desc_model)

# ================== Multimodal RAG retrieval ==================
# def cross_encoder_rerank(query_code, query_desc, candidates, topk, batch_size=8):
#     texts_a = [query_desc + "\n" + query_code] * len(candidates)
#     texts_b = [cand['description'] + "\n" + cand['code'] for cand in candidates]
#
#     scores = []
#     rerank_model.eval()
#
#     # 鍒?batch 澶勭悊
#     for i in range(0, len(candidates), batch_size):
#         batch_a = texts_a[i:i + batch_size]
#         batch_b = texts_b[i:i + batch_size]
#         inputs = rerank_tokenizer(
#             batch_a,
#             batch_b,
#             padding=True,
#             truncation=True,
#             max_length=512,
#             return_tensors="pt"
#         ).to(DEVICE)
#         with torch.no_grad():
#             logits = rerank_model(**inputs).logits  # [batch, 1] 鎴?[batch, 2]
#             # 濡傛灉鏄簩鍒嗙被锛屽彇姝ｇ被姒傜巼
#             if logits.size(1) == 2:
#                 prob = torch.softmax(logits, dim=1)[:, 1]  # 姝ｇ被姒傜巼
#             else:
#                 prob = logits.squeeze()
#             scores.extend(prob.cpu().numpy().tolist())
#
#     # 鎺掑簭
#     ranked = sorted(zip(candidates, scores), key=lambda x: x[1], reverse=True)
#     return [item[0] for item in ranked[:topk]]

def rag_multimodal_search(query_code, query_desc, topk=TOPK, alpha=ALPHA, beta=BETA, search_factor: int = None, return_limit: int = None):
    """Retrieve and fuse code- and description-based nearest neighbors.

    ``search_factor`` expands each FAISS search before fusion, while
    ``return_limit`` caps the number of fused candidates returned.
    """
    # 1. 鑾峰彇鍚戦噺
    code_vec = np.array(embed_code(query_code), dtype='float32').reshape(1, -1)
    desc_vec = np.array(embed_desc(query_desc), dtype='float32').reshape(1, -1)

    if search_factor is None:
        try:
            search_factor = int(os.getenv("RAG_SEARCH_FACTOR", "4"))
        except Exception:
            search_factor = 2
    if search_factor < 1:
        search_factor = 1
    if return_limit is None:
        return_limit = topk

    # 2. Search an expanded neighborhood in each FAISS index.
    search_k = max(1, topk * search_factor)
    _, idx_code = index_code.search(code_vec, search_k)
    _, idx_desc = index_desc.search(desc_vec, search_k)

    # 3. 鍚堝苟鍊欓€夌储寮?
    candidate_idx = list(set(idx_code[0].tolist() + idx_desc[0].tolist()))

    results = []
    missing = 0
    for idx in candidate_idx:
        vuln_info = get_vuln_info_by_faiss_idx(idx)
        if not vuln_info:
            missing += 1
            continue
        db_code_vec = index_code.reconstruct(idx)
        db_desc_vec = index_desc.reconstruct(idx)

        # 4. Compute code and description similarity.
        code_sim = np.dot(code_vec, db_code_vec).item()
        desc_sim = np.dot(desc_vec, db_desc_vec).item()

        # 5. 鍔犳潈
        score = alpha * code_sim + beta * desc_sim
        vuln_info["score"] = score
        results.append(vuln_info)

    # Optional retrieval diagnostics.
    try:
        if os.getenv("PRINT_RAG", "0").strip() == "1":
            print(f"[RAG] candidates={len(candidate_idx)} mapped={len(results)} missing_map={missing} (search_k={search_k}, return_limit={return_limit})")
    except Exception:
        pass

    # Rank and truncate the fused candidates.
    results = sorted(results, key=lambda x: x["score"], reverse=True)
    if return_limit is not None and return_limit > 0:
        results = results[:return_limit]

    return results
    # # 浣跨敤 Cross-Encoder 杩涜閲嶆帓搴?
    # ranked_candidates = cross_encoder_rerank(query_code, query_desc, results, topk)
    # for item in ranked_candidates:
    #     # print(f"CVE ID: {item['cve_id']}, CWE IDs: {item['cwe_ids']}, Base Score: {item['base_score']}, "
    #     #       f"Base Severity: {item['base_severity']}, Code: {item['code']}, Description: {item['description']}, "
    #     #       f"NVD Info: {item['nvd_info']}, CWE Info: {item['cwe_info']}, Score: {item['score']:.4f}")
    #     print(f"Score: {item['score']:.4f}, Code: {item['code']}")
    # print('========================================================================')
    # # 杩斿洖閲嶆帓搴忓悗鐨勭粨鏋?
    # return ranked_candidates


# ================== LLM client (OpenAI-compatible) ==================
_BASE_URL = (
    os.getenv("GPT_BASE_URL")
    or os.getenv("XAI_BASE_URL")
    or os.getenv("QWEN_BASE_URL")
    or os.getenv("DEEPSEEK_BASE_URL")
    or "https://api.deepseek.com"
).strip()
_MODEL = (
    os.getenv("GPT_MODEL")
    or os.getenv("XAI_MODEL")
    or os.getenv("QWEN_MODEL")
    or os.getenv("DEEPSEEK_MODEL")
    or "deepseek-ai/DeepSeek-V3.2"
).strip()
_API_KEY = (
    os.getenv("GPT_API_KEY")
    or os.getenv("XAI_API_KEY")
    or os.getenv("QWEN_API_KEY")
    or os.getenv("DEEPSEEK_API_KEY")
    or os.getenv("OPENAI_API_KEY")
    or ""
).strip()

def _chat_official(messages):
    """Optional: use the exact official SDK call path if USE_OFFICIAL_DIRECT=1"""
    if os.getenv("USE_OFFICIAL_DIRECT", "0").strip() != "1":
        return None
    import time
    max_retries = int(os.getenv("LLM_MAX_RETRIES", "3"))
    timeout = float(os.getenv("LLM_TIMEOUT", "180"))
    backoff = float(os.getenv("LLM_BACKOFF", "2"))
    
    last_err = None
    for attempt in range(max_retries):
        try:
            client = OpenAI(api_key=_API_KEY, base_url=_BASE_URL, timeout=timeout)
            resp = client.chat.completions.create(
                model=_MODEL,
                messages=messages,
                temperature=0.0,
                max_tokens=LLM_MAX_TOKENS,
                stream=False,
            )
            if resp and resp.choices and resp.choices[0].message.content:
                return resp
            else:
                raise ValueError("Empty response from API")
        except Exception as e:
            last_err = e
            if attempt < max_retries - 1:
                wait_time = backoff * (attempt + 1)
                print(f"[WARN] Official API call failed (attempt {attempt+1}/{max_retries}), retrying in {wait_time}s: {e}")
                time.sleep(wait_time)
            else:
                print(f"[ERROR] Official API call failed after {max_retries} attempts: {e}")
                return None
    return None

def _chat_raw(messages):
    """Fallback: direct HTTP call via requests if USE_RAW_HTTP=1"""
    if os.getenv("USE_RAW_HTTP", "0").strip() != "1":
        return None
    import requests as _rq
    import time
    url = _BASE_URL.rstrip("/") + "/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": _MODEL,
        "messages": messages,
        "temperature": 0.0,
        "max_tokens": LLM_MAX_TOKENS,
        "stream": False,
    }
    max_retries = int(os.getenv("LLM_MAX_RETRIES", "3"))
    timeout = float(os.getenv("LLM_TIMEOUT", "180"))  # seconds
    backoff = float(os.getenv("LLM_BACKOFF", "2"))
    
    last_err = None
    for attempt in range(max_retries):
        try:
            resp = _rq.post(url, headers=headers, json=payload, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            class _Obj:  # tiny shim for unified access
                def __init__(self, d):
                    self.choices = [{"message": {"content": d.get("choices", [{}])[0].get("message", {}).get("content", "")}}] if d.get("choices") else []
            return _Obj(data)
        except Exception as e:
            last_err = e
            if attempt < max_retries - 1:
                wait_time = backoff * (attempt + 1)
                print(f"[WARN] API call failed (attempt {attempt+1}/{max_retries}), retrying in {wait_time}s: {e}")
                time.sleep(wait_time)
            else:
                print(f"[ERROR] API call failed after {max_retries} attempts: {e}")
                raise


def _call_llm(messages) -> str:
    """Canonical OpenAI-compatible inference path for the public release."""
    if not _API_KEY:
        raise RuntimeError(
            "No LLM API key configured. Set DEEPSEEK_API_KEY, OPENAI_API_KEY, "
            "GPT_API_KEY, XAI_API_KEY, or QWEN_API_KEY before running inference."
        )
    off = _chat_official(messages)
    if off is not None:
        return off.choices[0].message.content if off and off.choices else ""
    raw = _chat_raw(messages)
    if raw is not None:
        return raw.choices[0]["message"]["content"] if raw and getattr(raw, "choices", None) else ""
    client = OpenAI(api_key=_API_KEY, base_url=_BASE_URL)
    resp = client.chat.completions.create(
        model=_MODEL,
        messages=messages,
        temperature=0.0,
        max_tokens=LLM_MAX_TOKENS,
        stream=False,
    )
    return resp.choices[0].message.content if resp and resp.choices else ""


def _log_prompt_tokens(system_content: str, user_content: str) -> None:
    """Optional prompt token logging; disabled unless LOG_PROMPT_TOKENS=1."""
    if os.getenv("LOG_PROMPT_TOKENS", "0").strip() != "1":
        return
    tok_dir = os.getenv("CHAT_TOKENIZER_DIR", "").strip()
    if not tok_dir or not os.path.isdir(tok_dir):
        return
    try:
        tokenizer = transformers.AutoTokenizer.from_pretrained(tok_dir, trust_remote_code=True)
        total = len(tokenizer.encode(system_content)) + len(tokenizer.encode(user_content))
        print(f"[tokens] total={total}")
    except Exception as exc:
        print(f"[WARN] token counting skipped: {exc}")


def predict_vuln_level(query_code, query_desc, topk_samples):
    """Predict severity with the public No-CoT/simple prompt."""
    # Slim prompt mode: only include code, optionally truncated, to reduce payload size
    slim = os.getenv("SLIM_PROMPT", "0").strip() == "1"
    trunc_chars = 0
    try:
        trunc_chars = max(0, int(os.getenv("CODE_TRUNC_CHARS", "0")))
    except Exception:
        trunc_chars = 0

    prompt = build_simple_prompt(
        query_code,
        query_desc,
        topk_samples,
        slim=slim,
        trunc_chars=trunc_chars,
    )

    system_content = (
        "You are an expert in code vulnerability assessment, and you will rate "
        "the vulnerabilities based on the following scoring criteria:\n"
        "0.1-3.9: LOW, 4.0-6.9: MEDIUM, 7.0-8.9: HIGH, 9.0-10.0: CRITICAL."
    )
    _log_prompt_tokens(system_content, prompt)
    messages = [
        {"role": "system", "content": system_content},
        {"role": "user", "content": prompt},
    ]
    return _call_llm(messages)

# ================== Experimental two-call LLM path ==================
# Experimental two-call knowledge prompt retained for comparison only. It is
# not invoked by scripts/rag_da_reproduce.py or by the paper-facing pipeline.
def generate_explanatory_knowledge(query_code, query_desc, topk_samples):
    """Generate explanatory knowledge from retrieved examples in a first LLM call."""
    prompt = "Step 1: Analyze the following 5 similar vulnerability examples. For each example, consider:\n"
    prompt += "- Functional semantics of the code\n- Vulnerability causes\n- Official severity (Base Severity) and its rationale\n"
    prompt += "- NVD/CWE descriptions for context\n- Possible fixing solutions\n\n"

    for i, item in enumerate(topk_samples):
        prompt += f"Sample {i + 1}:\n"
        prompt += f"- CVE ID: {item['cve_id']}\n"
        prompt += f"- CWE IDs: {item['cwe_ids']}\n"
        prompt += f"- Base Score: {item['base_score']}\n"
        prompt += f"- Base Severity: {item['base_severity']}\n"
        prompt += f"- Code: {item['code']}\n"
        prompt += f"- Description: {item['description']}\n"
        prompt += f"- NVD Info: {item['nvd_info']}\n"
        prompt += f"- CWE Info: {item['cwe_info']}\n\n"

    prompt += "Step 2: Based on the patterns, severity reasoning, functional semantics, and fixes observed in the above examples,\n"
    prompt += "analyze the target vulnerability below and generate **structured explanatory knowledge** in the following format:\n\n"
    prompt += "Explanatory Knowledge:\n"
    prompt += "1. Functional Semantics: [...]\n"
    prompt += "2. Vulnerability Causes: [...]\n"
    prompt += "3. Fixing Solutions: [...]\n\n"

    prompt += "Target Vulnerability:\n"
    prompt += f"- Code: {query_code}\n"
    prompt += f"- Description: {query_desc}\n\n"

    system_content = "You are an expert in code vulnerability assessment."
    _log_prompt_tokens(system_content, prompt)
    messages = [
        {"role": "system", "content": system_content},
        {"role": "user", "content": prompt},
    ]
    explanatory_knowledge = _call_llm(messages)
    print(explanatory_knowledge)
    return explanatory_knowledge

def predict_vuln_level_with_knowledge(query_code, query_desc, topk_samples):
    """Predict severity in a second LLM call using generated knowledge."""
    explanatory_knowledge = generate_explanatory_knowledge(query_code, query_desc, topk_samples)

    prompt = "Below is explanatory knowledge extracted from similar vulnerabilities:\n"
    prompt += f"{explanatory_knowledge}\n\n"

    prompt += "Target Vulnerability:\n"
    prompt += f"- Code: {query_code}\n"
    prompt += f"- Description: {query_desc}\n\n"

    prompt = "Based on the explanatory knowledge above, determine the severity level of the target vulnerability.\n"
    prompt += "Please only output one of the following: LOW, MEDIUM, HIGH, CRITICAL, without any explanation."

    system_content = (
        "You are an expert in code vulnerability assessment, and you will rate "
        "the vulnerabilities based on the following scoring criteria:\n"
        "0.1-3.9: LOW, 4.0-6.9: MEDIUM, 7.0-8.9: HIGH, 9.0-10.0: CRITICAL."
    )
    _log_prompt_tokens(system_content, prompt)
    messages = [
        {"role": "system", "content": system_content},
        {"role": "user", "content": prompt},
    ]
    return _call_llm(messages)

# ================== Few-shot CoT ==================
def predict_vuln_level_fewshot_cot(query_code, query_desc, topk_samples):
    """Few-shot chain-of-thought severity prediction (ReVul-CoT-style)."""
    prompt = "Your task is to analyze vulnerabilities step by step and finally output only the severity of the target vulnerability.\n\n"

    # Step 1: analyze the retrieved examples internally.
    prompt += "Step 1: For each of the following similar vulnerability samples, internally construct a step-by-step explanation that considers:\n"
    prompt += "- Functional semantics of the code\n"
    prompt += "- Vulnerability causes\n"
    prompt += "- Fixing solutions\n"
    prompt += "- Impact scope (affected modules, attack surface)\n"
    prompt += "- Exploitability (attack vector, authentication, preconditions)\n"
    prompt += "- Impact type (confidentiality, integrity, availability, privilege escalation, RCE, data leak)\n"
    prompt += "- Security context (required privileges, privilege level gained)\n"
    prompt += "- Severity mapping clues (why it was classified as LOW, MEDIUM, HIGH, or CRITICAL)\n"
    prompt += "- Official severity (Base Severity)\n\n"

    for i, item in enumerate(topk_samples):
        prompt += f"Sample {i + 1}:\n"
        prompt += f"- CVE ID: {item['cve_id']}\n"
        prompt += f"- CWE IDs: {item['cwe_ids']}\n"
        prompt += f"- Base Score: {item['base_score']}\n"
        prompt += f"- Base Severity: {item['base_severity']}\n"
        prompt += f"- Code: {item['code']}\n"
        prompt += f"- Description: {item['description']}\n"
        prompt += f"- NVD Info: {item['nvd_info']}\n"
        prompt += f"- CWE Info: {item['cwe_info']}\n\n"

    # Step 2: analyze the target using the retrieved patterns.
    prompt += "Step 2: Based on the patterns observed in Step 1, internally analyze the target vulnerability step by step.\n"
    prompt += "Construct the following structured explanatory knowledge before deciding severity:\n"
    prompt += "Explanatory Knowledge:\n"
    prompt += "1. Functional Semantics: [...]\n"
    prompt += "2. Vulnerability Causes: [...]\n"
    prompt += "3. Fixing Solutions: [...]\n\n"
    prompt += "4. Impact Scope: [Affected components/modules, size of attack surface]\n"
    prompt += "5. Exploitability: [Attack vector, authentication required, preconditions]\n"
    prompt += "6. Impact Type: [Confidentiality, Integrity, Availability, privilege escalation, RCE, data leak]\n"
    prompt += "7. Security Context: [Required privileges for exploitation, privilege level gained]\n"
    prompt += "8. Severity Mapping Clues: [Summarize why similar cases were rated at certain severity levels]\n\n"

    prompt += "Target Vulnerability:\n"
    prompt += f"- Code: {query_code}\n"
    prompt += f"- Description: {query_desc}\n\n"

    # Step 3: emit only the final severity label.
    prompt += "Step 3: Based on Step 1 and Step 2, output the severity level of the target vulnerability.\n"
    prompt += "Do not output any explanation, reasoning process, or the severity levels of the previous sample examples.\n"
    prompt += "Output exactly one line in the format:\n"
    prompt += "SEVERITY: <LOW|MEDIUM|HIGH|CRITICAL>\n"

    system_content = (
        "You are an expert in code vulnerability assessment, and you will rate "
        "the vulnerabilities based on the following scoring criteria:\n"
        "0.1-3.9: LOW, 4.0-6.9: MEDIUM, 7.0-8.9: HIGH, 9.0-10.0: CRITICAL."
    )
    _log_prompt_tokens(system_content, prompt)
    messages = [
        {"role": "system", "content": system_content},
        {"role": "user", "content": prompt},
    ]
    return _call_llm(messages)

# ================== Legacy standalone runner ==================
def predict_vuln_level_rag_llm(query_code, query_desc):
    # 1. Retrieve the top-k multimodal RAG examples.
    topk_samples = rag_multimodal_search(query_code, query_desc)

    # 2. COT
    level = predict_vuln_level_fewshot_cot(query_code, query_desc, topk_samples)
    return level


# No beam-search entry is exposed from this module. The canonical experiment
# runner is scripts/rag_da_reproduce.py, backed by rag_da.rag_da_attack.
if __name__ == "__main__":
    raise SystemExit(
        "src/retrieval.py is a library module. Use "
        "scripts/rag_da_reproduce.py for clean or RAG-DA attack runs."
    )
