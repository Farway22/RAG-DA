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

# Global reference to current evaluation DataFrame (for NO_RAG pool)
CURRENT_EVAL_DF = None

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
    # 纭繚text鏄瓧绗︿覆绫诲瀷
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

# ================== 澶氭ā鎬?RAG 妫€绱?==================
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
    """
    妫€绱㈠苟鍚堝苟 code/desc 鍊欓€夈€?
    - search_factor: 姣忔ā鎬佹悳绱㈡墿澶х郴鏁帮紙榛樿2锛屾垨鐢辩幆澧冨彉閲?RAG_SEARCH_FACTOR 瑕嗙洊锛?
    - return_limit: 杩斿洖涓婇檺锛堥粯璁や笌 topk 鐩稿悓锛?
    """
    # 1. 鑾峰彇鍚戦噺
    code_vec = np.array(embed_code(query_code), dtype='float32').reshape(1, -1)
    desc_vec = np.array(embed_desc(query_desc), dtype='float32').reshape(1, -1)

    if search_factor is None:
        try:
            search_factor = int(os.getenv("RAG_SEARCH_FACTOR", "2"))
        except Exception:
            search_factor = 2
    if search_factor < 1:
        search_factor = 1
    if return_limit is None:
        return_limit = topk

    # 2. L2鎼滅储锛屽彇鍚勮嚜鎵╁ぇ鍚庣殑 topk
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

        # 4. 璁＄畻浣欏鸡鐩镐技搴?
        code_sim = np.dot(code_vec, db_code_vec).item()
        desc_sim = np.dot(desc_vec, db_desc_vec).item()

        # 5. 鍔犳潈
        score = alpha * code_sim + beta * desc_sim
        vuln_info["score"] = score
        results.append(vuln_info)

    # 缁熻鏄犲皠瑕嗙洊
    try:
        if os.getenv("PRINT_RAG", "0").strip() == "1":
            print(f"[RAG] candidates={len(candidate_idx)} mapped={len(results)} missing_map={missing} (search_k={search_k}, return_limit={return_limit})")
    except Exception:
        pass

    # 鎺掑簭骞堕檺鍒惰繑鍥炴暟閲?
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
    or os.getenv("QWEN_BASE_URL")
    or os.getenv("DEEPSEEK_BASE_URL")
    or "https://api.deepseek.com"
).strip()
_MODEL = (
    os.getenv("GPT_MODEL")
    or os.getenv("QWEN_MODEL")
    or os.getenv("DEEPSEEK_MODEL")
    or "deepseek-ai/DeepSeek-V3.2"
).strip()
_API_KEY = (
    os.getenv("GPT_API_KEY")
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
                max_tokens=512,
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
        "max_tokens": 512,
        "stream": False,
    }
    max_retries = int(os.getenv("LLM_MAX_RETRIES", "3"))
    timeout = float(os.getenv("LLM_TIMEOUT", "180"))  # 澧炲姞鍒?80绉?
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
            "GPT_API_KEY, or QWEN_API_KEY before running inference."
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
        max_tokens=512,
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


# ================== Identifier renaming helpers ==================
_C_LIKE_KEYWORDS = set([
    'auto','break','case','char','const','continue','default','do','double','else','enum','extern','float','for','goto','if','inline','int','long','register','restrict','return','short','signed','sizeof','static','struct','switch','typedef','union','unsigned','void','volatile','while','_Alignas','_Alignof','_Atomic','_Bool','_Complex','_Generic','_Imaginary','_Noreturn','_Static_assert','_Thread_local',
    'class','namespace','public','private','protected','template','typename','using','virtual','operator','new','delete','this','friend','nullptr','bool','wchar_t','char16_t','char32_t','constexpr','mutable','throw','try','catch','reinterpret_cast','static_cast','const_cast','dynamic_cast','typeid','explicit',
])

_RENAME_DICT = [
    'data','item','value','buffer','ptr','tmp','count','index','flag','result','node','entry','param','offset','length','size','limit','cursor','state','acc','sum','hash','token','key','ident','map','list','array','record','buf','ctx','env','cfg','msg','err','res','val','cur','iter','out','inp'
]

def _is_ident_start(ch: str) -> bool:
    return (ch.isalpha() or ch == '_')

def _is_ident_part(ch: str) -> bool:
    return (ch.isalnum() or ch == '_')

def _collect_identifiers_c_like(code: str):
    """
    鏋佺畝 C/C++ 椋庢牸璇嶆硶鍣細璺宠繃娉ㄩ噴/瀛楃涓?瀛楃瀛楅潰閲忥紝浠呭湪浠ｇ爜娈甸噰闆嗘爣璇嗙 token 鍙婂叾璁℃暟銆?
    杩斿洖 (id_counts: dict[str,int])銆?
    """
    i = 0
    n = len(code)
    in_line_cmt = False
    in_blk_cmt = False
    in_str = False
    in_char = False
    esc = False
    counts = {}
    while i < n:
        ch = code[i]
        nxt = code[i+1] if i + 1 < n else ''
        if in_line_cmt:
            if ch == '\n':
                in_line_cmt = False
            i += 1
            continue
        if in_blk_cmt:
            if ch == '*' and nxt == '/':
                in_blk_cmt = False
                i += 2
            else:
                i += 1
            continue
        if in_str:
            if not esc and ch == '"':
                in_str = False
            esc = (not esc and ch == '\\')
            i += 1
            continue
        if in_char:
            if not esc and ch == '\'':
                in_char = False
            esc = (not esc and ch == '\\')
            i += 1
            continue

        # comment starts
        if ch == '/' and nxt == '/':
            in_line_cmt = True
            i += 2
            continue
        if ch == '/' and nxt == '*':
            in_blk_cmt = True
            i += 2
            continue
        # string/char starts
        if ch == '"':
            in_str = True
            esc = False
            i += 1
            continue
        if ch == '\'':
            in_char = True
            esc = False
            i += 1
            continue

        # identifier
        if _is_ident_start(ch):
            j = i + 1
            while j < n and _is_ident_part(code[j]):
                j += 1
            ident = code[i:j]
            if ident not in _C_LIKE_KEYWORDS:
                counts[ident] = counts.get(ident, 0) + 1
            i = j
            continue

        i += 1
    return counts

def _apply_identifier_mapping(code: str, id_map: dict) -> str:
    """
    浣跨敤鐩稿悓鐨勬瀬绠€璇嶆硶鍣紝浠呭湪浠ｇ爜娈碉紙闈炴敞閲?瀛楃涓?瀛楃锛変笖绮剧‘ token 鍖归厤鏃舵浛鎹€?
    """
    i = 0
    n = len(code)
    in_line_cmt = False
    in_blk_cmt = False
    in_str = False
    in_char = False
    esc = False
    out_chars = []
    while i < n:
        ch = code[i]
        nxt = code[i+1] if i + 1 < n else ''
        if in_line_cmt:
            out_chars.append(ch)
            if ch == '\n':
                in_line_cmt = False
            i += 1
            continue
        if in_blk_cmt:
            out_chars.append(ch)
            if ch == '*' and nxt == '/':
                out_chars.append(nxt)
                in_blk_cmt = False
                i += 2
            else:
                i += 1
            continue
        if in_str:
            out_chars.append(ch)
            if not esc and ch == '"':
                in_str = False
            esc = (not esc and ch == '\\')
            i += 1
            continue
        if in_char:
            out_chars.append(ch)
            if not esc and ch == '\'':
                in_char = False
            esc = (not esc and ch == '\\')
            i += 1
            continue

        # comment starts
        if ch == '/' and nxt == '/':
            out_chars.append(ch); out_chars.append(nxt)
            in_line_cmt = True
            i += 2
            continue
        if ch == '/' and nxt == '*':
            out_chars.append(ch); out_chars.append(nxt)
            in_blk_cmt = True
            i += 2
            continue
        # string/char starts
        if ch == '"':
            out_chars.append(ch)
            in_str = True
            esc = False
            i += 1
            continue
        if ch == '\'':
            out_chars.append(ch)
            in_char = True
            esc = False
            i += 1
            continue

        # identifier replacement
        if _is_ident_start(ch):
            j = i + 1
            while j < n and _is_ident_part(code[j]):
                j += 1
            ident = code[i:j]
            repl = id_map.get(ident)
            out_chars.append(repl if repl is not None else ident)
            i = j
            continue

        out_chars.append(ch)
        i += 1
    return ''.join(out_chars)

def _generate_new_name_pool(existing: set, seed: int):
    import random
    rnd = random.Random(seed)
    pool = list(_RENAME_DICT)
    rnd.shuffle(pool)
    # 纭繚涓嶄笌宸插瓨鍦ㄥ啿绐?
    for p in list(pool):
        if p in existing:
            pool.remove(p)
    # 鍏滃簳鎵╁睍
    i = 0
    while len(pool) < 256 and i < 1000:
        cand = f"var{i}"
        if cand not in existing:
            pool.append(cand)
        i += 1
    return pool

def rename_identifiers_safe(code: str, max_ids: int = 2, seed: int = 42, use_ast: bool = True) -> str:
    """
    鍙橀噺閲嶅懡鍚嶅嚱鏁帮紝浼樺厛浣跨敤AST鏂规硶锛屽け璐ユ椂闄嶇骇鍒拌瘝娉曞垎鏋?
    
    Args:
        code: C/C++浠ｇ爜
        max_ids: 鏈€澶氭敼鍐欑殑鍙橀噺鏁?
        seed: 闅忔満绉嶅瓙
        use_ast: 鏄惁浼樺厛灏濊瘯AST鏂规硶锛堥粯璁rue锛?
    
    Returns:
        鏀瑰啓鍚庣殑浠ｇ爜
    """
    # 浼樺厛灏濊瘯AST鏂规硶
    if use_ast:
        try:
            from rename_ast import rename_identifiers_ast
            result = rename_identifiers_ast(code, max_ids=max_ids, seed=seed, enable_ast=True)
            # 濡傛灉AST鏂规硶鎴愬姛锛堣繑鍥炰簡涓嶅悓鐨勪唬鐮侊級锛屼娇鐢ㄥ畠
            if result != code:
                return result
        except Exception:
            # AST鏂规硶澶辫触锛岄檷绾у埌璇嶆硶鍒嗘瀽
            pass
    
    # 闄嶇骇鍒拌瘝娉曞垎鏋愭柟娉曪紙浣跨敤瀹夊叏鐨刦allback锛?
    try:
        from retrieval_fallback_safe import rename_identifiers_fallback_safe
        result = rename_identifiers_fallback_safe(code, max_ids=max_ids, seed=seed)
        
        # 璁剧疆fallback妯″紡鐨勯噸鍛藉悕鏄犲皠锛堢敤浜庤瘖鏂拰鏃ュ織锛?
        try:
            import rename_ast
            rename_ast.LAST_RENAME_MODE = "fallback"
        except:
            pass
        
        return result
    except (ImportError, Exception) as e:
        # 濡傛灉鏂版ā鍧椾笉鍙敤锛屼娇鐢ㄦ棫鐨刦allback閫昏緫锛堜笉鎺ㄨ崘锛?
        print(f"[fallback] Warning: Using legacy fallback (less safe): {e}", flush=True)
        # 闄嶇骇鍒拌瘝娉曞垎鏋愭柟娉曪紙鍘熸湁閫昏緫 - 浠呬綔涓烘渶鍚庡閫夛級
        counts = _collect_identifiers_c_like(code)
        if not counts:
            return code
        # 杩囨护涓嶅彲鏀瑰悕鐨?鐤戜技绫诲瀷/瀹?锛堝惎鍙戝紡锛夛細鍏ㄥぇ鍐欎笖鍚笅鍒掔嚎锛涙垨闀垮害<=1
        renameables = [ident for ident, c in counts.items() if len(ident) > 1 and not (ident.isupper() and '_' in ident)]
        if not renameables:
            return code
        # 閫夋嫨鍑虹幇娆℃暟澶氱殑浼樺厛
        renameables.sort(key=lambda x: counts[x], reverse=True)
        picked = renameables[:max(1, max_ids)]
        # 鐢熸垚鏂板悕
        existing = set(counts.keys())
        pool = _generate_new_name_pool(existing, seed)
        id_map = {}
        pi = 0
        for old in picked:
            # 璺宠繃宸插湪鏄犲皠
            if old in id_map:
                continue
            # 閫夋嫨涓€涓湭鍐茬獊鐨勬柊鍚?
            while pi < len(pool) and pool[pi] in existing:
                pi += 1
            if pi >= len(pool):
                break
            id_map[old] = pool[pi]
            existing.add(pool[pi])
            pi += 1
        if not id_map:
            return code
        return _apply_identifier_mapping(code, id_map)

# ================== NO-RAG 鍊欓€夋睜锛堝叏灞€闅忔満閲囨牱锛?==================
def _build_no_rag_pool(
    exclude_code: str,
    exclude_desc: str,
    pool_size: int,
    seed: int = 42,
):
    import random
    rnd = random.Random(seed)

    # 浼樺厛浣跨敤澶栭儴鎸囧畾 CSV
    df_pool = None
    csv_path = os.getenv("FALLBACK_NO_RAG_CSV", "")
    if csv_path and os.path.exists(csv_path):
        try:
            df_pool = pd.read_csv(csv_path)
        except Exception:
            df_pool = None

    # 鍏舵浣跨敤 fallback CSV 鍔犺浇
    if df_pool is None:
        df_pool = _load_fallback_df()

    # 鏈€鍚庨€€鍖栦负褰撳墠璇勬祴 DF锛堥伩鍏嶆娊鍒拌嚜韬牱鏈級
    if df_pool is None:
        df_pool = CURRENT_EVAL_DF

    results = []
    if df_pool is None or df_pool.empty:
        return results

    # 瑙勮寖鍒楀悕鏄犲皠
    code_col = 'func_before' if 'func_before' in df_pool.columns else ('code' if 'code' in df_pool.columns else None)
    desc_col = 'description' if 'description' in df_pool.columns else None
    sev_col = 'Base Severity' if 'Base Severity' in df_pool.columns else ('base_severity' if 'base_severity' in df_pool.columns else None)

    # 鍊欓€夌储寮?
    idxs = list(range(len(df_pool)))
    rnd.shuffle(idxs)

    for i in idxs:
        if len(results) >= pool_size:
            break
        r = df_pool.iloc[i]
        code = str(r.get(code_col, "")) if code_col else ""
        desc = str(r.get(desc_col, "")) if desc_col else ""

        # 璺宠繃涓庣洰鏍囧畬鍏ㄧ浉鍚岀殑鏉＄洰
        if code and desc and code == exclude_code and desc == exclude_desc:
            continue

        sev = str(r.get(sev_col, "")).strip().upper() if sev_col else ""
        # 闅忔満鐩镐技搴﹀垎鏁颁互椹卞姩閫夋嫨鍣ㄦ帓搴?
        sim_score = float(rnd.random())

        results.append({
            "cve_id": str(r.get("cve_id", "")),
            "cwe_ids": str(r.get("cwe_ids", "")),
            "code": code,
            "description": desc,
            "base_score": float(r.get("Base Score", r.get("base_score", 0.0)) or 0.0),
            "base_severity": sev,
            "nvd_info": str(r.get("nvd_info", "")),
            "cwe_info": str(r.get("cwe_info", "")),
            "score": sim_score,
        })

    # 淇濇寔鎸?score 闄嶅簭
    results.sort(key=lambda x: x.get("score", 0.0), reverse=True)
    return results

# ================== 涓€娆¤皟鐢↙LM锛堟棤COT锛?==================
def predict_vuln_level(query_code, query_desc, topk_samples):
    """
    涓€杞甃LM锛堟棤COT锛? 鏍规嵁鐩镐技婕忔礊鏍锋湰锛岀洿鎺ョ敓鎴愮洰鏍囨紡娲炵殑涓ラ噸绛夌骇
    """
    # Slim prompt mode: only include code, optionally truncated, to reduce payload size
    slim = os.getenv("SLIM_PROMPT", "0").strip() == "1"
    trunc_chars = 0
    try:
        trunc_chars = max(0, int(os.getenv("CODE_TRUNC_CHARS", "0")))
    except Exception:
        trunc_chars = 0

    def _maybe_trunc(s: str) -> str:
        if trunc_chars and len(s) > trunc_chars:
            return s[:trunc_chars]
        return s

    prompt = ""
    if slim:
        prompt += "Below are a few code snippets. Infer the severity of the target code as one of: LOW, MEDIUM, HIGH, CRITICAL.\n\n"
        for i, item in enumerate(topk_samples):
            code_i = _maybe_trunc(str(item.get('code', '') or ''))
            sev_i = str(item.get('base_severity', '') or '')
            prompt += f"Sample {i + 1}:\n- Code:\n{code_i}\n- Severity: {sev_i}\n\n"
        prompt += "Target:\n"
        prompt += f"- Code:\n{_maybe_trunc(query_code)}\n\n"
        prompt += "Output only one token among: LOW, MEDIUM, HIGH, CRITICAL."
    else:
        prompt += "Below are several similar vulnerability samples with their code, description, and corresponding severity levels. "
        prompt += "Based on these samples, you will determine the severity of the target vulnerability example. "
        prompt += "Please only output the severity level of the target vulnerability example without providing any explanations or severity levels of the similar samples.\n\n"
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
        prompt += "Target Vulnerability:\n"
        prompt += f"- Code: {query_code}\n"
        prompt += f"- Description: {query_desc}\n\n"
    # prompt += "Please only output the severity level (LOW, MEDIUM, HIGH, CRITICAL) of the target vulnerability example, without any explanation."

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

# ================== 涓ゆ璋冪敤LLM ==================
def generate_explanatory_knowledge(query_code, query_desc, topk_samples):
    """
    绗竴杞?LLM锛氬厛鍒嗘瀽鐩镐技婕忔礊鏍锋湰锛屽湪缁撳悎鍒嗘瀽鐩存帴鐢熸垚鐩爣婕忔礊鐨勭粨鏋勫寲瑙ｉ噴鎬х煡璇?
    """
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
    """
    绗簩杞?LLM锛氱粨鍚堢涓€杞敓鎴愮殑瑙ｉ噴鎬х煡璇嗭紝棰勬祴鐩爣婕忔礊绛夌骇
    """
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
    """
    灏戞牱鏈珻OT 鍏堝垎鏋愮浉浼兼紡娲炴牱鏈紝鍦ㄧ粨鍚堝垎鏋愮洿鎺ョ敓鎴愮洰鏍囨紡娲炵殑缁撴瀯鍖栬В閲婃€х煡璇嗭紝鏈€鍚庣敓鎴愭紡娲炵瓑绾?
    """
    prompt = "Your task is to analyze vulnerabilities step by step and finally output only the severity of the target vulnerability.\n\n"

    # Step1: 鍒嗘瀽绀轰緥
    prompt += "Step 1: Analyze the following several similar vulnerability samples. For each sample, consider:\n"
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

    # Step2: 鍒嗘瀽鐩爣婕忔礊
    prompt += "Step 2: Based on the patterns observed in Step 1, analyze the target vulnerability.\n"
    prompt += "Generate structured explanatory knowledge before deciding severity:\n"
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

    # Step3: 杈撳嚭涓ラ噸绛夌骇锛堜繚鐣欐柊鐗堟湰鐨勬牸寮忚姹傦級
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
    # 1. RAG 澶氭ā鎬佹绱?topK 鏍锋湰
    topk_samples = rag_multimodal_search(query_code, query_desc)

    # 2. COT
    level = predict_vuln_level_fewshot_cot(query_code, query_desc, topk_samples)
    return level


def predict_vuln_level_rag_llm_beam(
    query_code: str,
    query_desc: str,
    true_severity: str,
    k: int = TOPK,
    pool_size: int = 30,
    strategy: str = "beam",
    beam_width: int = 8,
    w_sim: float = 0.7,
    w_sev: float = 0.3,
    diversity_lambda: float = 0.1,
) -> str:
    """Legacy beam runner over a retrieved demonstration pool."""
    # PING_ONLY: minimal connectivity check without building the full prompt
    try:
        if os.getenv("PING_ONLY", "0").strip() == "1":
            return _call_llm([
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Hello"},
            ])
    except Exception:
        pass
    use_no_rag = os.getenv("NO_RAG", "0").strip() == "1"
    if use_no_rag:
        try:
            seed = int(os.getenv("NO_RAG_SEED", os.getenv("SHUFFLE_SEED", "42")))
        except Exception:
            seed = 42
        pool = _build_no_rag_pool(query_code, query_desc, pool_size, seed)
    else:
        pool = rag_multimodal_search(query_code, query_desc, topk=pool_size, search_factor=int(os.getenv("RAG_SEARCH_FACTOR", "4")), return_limit=pool_size)
    if not pool:
        # fallback tier 1: increase search factor
        fallback_factor = 8
        print(f"[WARN] empty pool with topk={pool_size}, retry with search_factor={fallback_factor}")
        if use_no_rag:
            pool = _build_no_rag_pool(query_code, query_desc, pool_size, seed)
        else:
            pool = rag_multimodal_search(query_code, query_desc, topk=pool_size, search_factor=fallback_factor, return_limit=pool_size)
    if not pool:
        # fallback tier 2: shrink return limit
        for limit in (20, 10, 5):
            print(f"[WARN] still empty, retry with return_limit={limit}")
            if use_no_rag:
                pool = _build_no_rag_pool(query_code, query_desc, limit, seed)
            else:
                pool = rag_multimodal_search(query_code, query_desc, topk=limit, search_factor=fallback_factor, return_limit=limit)
            if pool:
                break
    demos = pool[:k]
    # optional debug dump of selected demos
    try:
        if os.getenv("DUMP_DEMOS", "0").strip() == "1":
            print(f"[DUMP_DEMOS] strategy={strategy} k={k} pool_size={pool_size} beam_width={beam_width} w_sim={w_sim} w_sev={w_sev} div={diversity_lambda}")
            print(f"[DUMP_DEMOS] selected_count={len(demos)}")
            cves = []
            for i, d in enumerate(demos):
                cves.append(str(d.get('cve_id','')))
                print(f"  demo[{i}] CVE={d.get('cve_id','')} sev={d.get('base_severity','')} score={d.get('score',0):.4f} cwe={d.get('cwe_ids','')}")
            try:
                print(f"[DUMP_DEMOS] CVE_LIST={','.join(cves)}")
            except Exception:
                pass
    except Exception:
        pass

    # 鍙€夛細瀵?query / demos 鎵ц鏍囪瘑绗﹂噸鍛藉悕锛堟紨绀烘敾鍑伙級
    try:
        if os.getenv("APPLY_REWRITE", "0").strip() == "1":
            target = os.getenv("REWRITE_TARGET", "demos").strip().lower()  # demos|query|both
            max_ids = int(os.getenv("REWRITE_MAX_IDS", "3"))
            seed = int(os.getenv("REWRITE_SEED", os.getenv("SHUFFLE_SEED", "42")))
            if target in ("query", "both"):
                query_code = rename_identifiers_safe(query_code, max_ids=max_ids, seed=seed)
            if target in ("demos", "both"):
                new_demos = []
                for d in demos:
                    d2 = dict(d)
                    try:
                        d2['code'] = rename_identifiers_safe(d2.get('code', '') or '', max_ids=max_ids, seed=seed)
                    except Exception:
                        pass
                    new_demos.append(d2)
                demos = new_demos
            if os.getenv("DUMP_DEMOS", "0").strip() == "1":
                print(f"[REWRITE] applied identifier renaming: target={target} max_ids={max_ids} seed={seed}")
    except Exception as _e:
        print(f"[REWRITE] skip due to error: {_e}")

    # DRY_RUN: 璺宠繃 LLM锛屼粎杈撳嚭閫夋牱淇℃伅
    try:
        if os.getenv("DRY_RUN", "0").strip() == "1":
            print("[DRY_RUN] skip LLM call; selection prepared above.")
            return ""
    except Exception:
        pass

    # Choose inference mode: simple vs CoT
    try:
        if os.getenv("INFER_SIMPLE", "0").strip() == "1":
            level = predict_vuln_level(query_code, query_desc, demos)
        else:
            level = predict_vuln_level_fewshot_cot(query_code, query_desc, demos)
    except Exception:
        level = predict_vuln_level_fewshot_cot(query_code, query_desc, demos)
    return level


# ================== Legacy standalone runner ==================
if __name__ == "__main__":
    print(
        "[WARN] Direct execution of src/retrieval.py is legacy. "
        "Use scripts/rag_da_reproduce.py for paper reproduction."
    )
    input_file = os.getenv("INPUT_FILE", "datasets/test/test_all.xlsx")
    output_file = os.getenv("OUTPUT_FILE", "test_all_predicted2.xlsx")
    temp_file = os.getenv("TEMP_FILE", os.path.splitext(output_file)[0] + "_temp.xlsx")

    valid_levels = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    if os.path.exists(output_file):
        df = pd.read_excel(output_file)
        print(f"[resume] loaded {output_file}")
    else:
        df = pd.read_excel(input_file)
        df["Predicted"] = ""
        print(f"[start] loaded {input_file}")

    try:
        globals()["CURRENT_EVAL_DF"] = df
    except Exception:
        pass

    rows_to_predict = df[~df["Predicted"].astype(str).str.strip().isin(valid_levels)].index
    if os.getenv("SHUFFLE_ROWS", "0").strip() == "1":
        try:
            import random

            seed = int(os.getenv("SHUFFLE_SEED", "42"))
            rnd = random.Random(seed)
            rows_list = list(rows_to_predict)
            rnd.shuffle(rows_list)
            rows_to_predict = rows_list
        except Exception:
            pass

    strategy = os.getenv("STRATEGY", "beam").strip().lower()
    use_beam = strategy in ("beam", "adversarial", "baseline")
    max_run = int(os.getenv("SMALL_RUN_MAX", "20"))
    topk_run = int(os.getenv("TOPK", str(TOPK)))
    pool_size = int(os.getenv("POOL_SIZE", "30"))
    beam_width = int(os.getenv("BEAM_WIDTH", "8"))
    w_sim = float(os.getenv("W_SIM", "0.7"))
    w_sev = float(os.getenv("W_SEV", "0.3"))
    diversity = float(os.getenv("DIVERSITY_LAMBDA", "0.1"))

    if len(rows_to_predict) == 0:
        print("All rows already have valid predictions.")
    else:
        processed = 0
        for idx in rows_to_predict:
            row = df.loc[idx]
            query_code = row["func_before"]
            query_desc = row["description"]

            try:
                if use_beam:
                    true_sev = str(row.get("Base Severity", "")).strip().upper()
                    level = predict_vuln_level_rag_llm_beam(
                        query_code=query_code,
                        query_desc=query_desc,
                        true_severity=true_sev,
                        k=topk_run,
                        pool_size=pool_size,
                        strategy=strategy,
                        beam_width=beam_width,
                        w_sim=w_sim,
                        w_sev=w_sev,
                        diversity_lambda=diversity,
                    )
                else:
                    level = predict_vuln_level_rag_llm(query_code, query_desc)
                print(f"Row {idx}: {level} (Base Severity: {row['Base Severity']})")
            except Exception as exc:
                print(f"Error at row {idx}: {exc}")
                level = ""

            df.at[idx, "Predicted"] = level
            df.to_excel(temp_file, index=False)
            os.replace(temp_file, output_file)

            processed += 1
            if processed >= max_run:
                print(f"Reached SMALL_RUN_MAX={max_run}, stopping early.")
                break

        print(f"Predictions saved to {output_file}")
