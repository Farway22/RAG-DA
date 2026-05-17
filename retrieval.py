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
import pathlib
import sys
import time
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"

# ================== 配置 ==================
DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
MAX_LENGTH = 256
POOLING = 'first_last_avg'
ALPHA = 0.6  # code 权重
BETA = 0.4  # description 权重
TOPK = 5

# ================== 数据库连接 ===================
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

# ================== 加载 FAISS 索引 ==================
index_code = faiss.read_index("faiss/faiss_index_code.index")
index_desc = faiss.read_index("faiss/faiss_index_desc.index")
# ================== FAISS idx → 数据库 id 映射 ==================
with open("faiss/id_map.json", "r", encoding="utf-8") as f:
    id_map = json.load(f)  # id_map: {faiss_idx_str: db_id}

def get_vuln_info_by_faiss_idx(idx):
    db_id = id_map.get(str(idx))  # FAISS 索引对应数据库 id
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


# ================== 加载模型 ==================
code_model_name = "microsoft/codebert-base"
desc_model_name = "shibing624/text2vec-base-multilingual"
# rerank_model_name = "microsoft/unixcoder-base"

code_tokenizer = AutoTokenizer.from_pretrained(code_model_name)
code_model = AutoModel.from_pretrained(code_model_name).to(DEVICE)
code_model.eval()

desc_tokenizer = AutoTokenizer.from_pretrained(desc_model_name)
desc_model = AutoModel.from_pretrained(desc_model_name).to(DEVICE)
desc_model.eval()

# rerank_tokenizer = AutoTokenizer.from_pretrained(rerank_model_name)
# rerank_model = AutoModelForSequenceClassification.from_pretrained(rerank_model_name).to(DEVICE)
# rerank_model.eval()

# ================== 向量化函数 ==================
def embed_text(text, tokenizer, model, max_length=MAX_LENGTH, pooling=POOLING):
    # 确保text是字符串类型
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
    return embed_text(text, code_tokenizer, code_model)

def embed_desc(text):
    return embed_text(text, desc_tokenizer, desc_model)

# ================== 多模态 RAG 检索 ==================
# def cross_encoder_rerank(query_code, query_desc, candidates, topk, batch_size=8):
#     texts_a = [query_desc + "\n" + query_code] * len(candidates)
#     texts_b = [cand['description'] + "\n" + cand['code'] for cand in candidates]
#
#     scores = []
#     rerank_model.eval()
#
#     # 分 batch 处理
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
#             logits = rerank_model(**inputs).logits  # [batch, 1] 或 [batch, 2]
#             # 如果是二分类，取正类概率
#             if logits.size(1) == 2:
#                 prob = torch.softmax(logits, dim=1)[:, 1]  # 正类概率
#             else:
#                 prob = logits.squeeze()
#             scores.extend(prob.cpu().numpy().tolist())
#
#     # 排序
#     ranked = sorted(zip(candidates, scores), key=lambda x: x[1], reverse=True)
#     return [item[0] for item in ranked[:topk]]

def rag_multimodal_search(query_code, query_desc, topk=TOPK, alpha=ALPHA, beta=BETA, search_factor: int = None, return_limit: int = None):
    """
    检索并合并 code/desc 候选。
    - search_factor: 每模态搜索扩大系数（默认2，或由环境变量 RAG_SEARCH_FACTOR 覆盖）
    - return_limit: 返回上限（默认与 topk 相同）
    """
    # 1. 获取向量
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

    # 2. L2搜索，取各自扩大后的 topk
    search_k = max(1, topk * search_factor)
    _, idx_code = index_code.search(code_vec, search_k)
    _, idx_desc = index_desc.search(desc_vec, search_k)

    # 3. 合并候选索引
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

        # 4. 计算余弦相似度
        code_sim = np.dot(code_vec, db_code_vec).item()
        desc_sim = np.dot(desc_vec, db_desc_vec).item()

        # 5. 加权
        score = alpha * code_sim + beta * desc_sim
        vuln_info["score"] = score
        results.append(vuln_info)

    # 统计映射覆盖
    try:
        if os.getenv("PRINT_RAG", "0").strip() == "1":
            print(f"[RAG] candidates={len(candidate_idx)} mapped={len(results)} missing_map={missing} (search_k={search_k}, return_limit={return_limit})")
    except Exception:
        pass

    # 排序并限制返回数量
    results = sorted(results, key=lambda x: x["score"], reverse=True)
    if return_limit is not None and return_limit > 0:
        results = results[:return_limit]

    return results
    # # 使用 Cross-Encoder 进行重排序
    # ranked_candidates = cross_encoder_rerank(query_code, query_desc, results, topk)
    # for item in ranked_candidates:
    #     # print(f"CVE ID: {item['cve_id']}, CWE IDs: {item['cwe_ids']}, Base Score: {item['base_score']}, "
    #     #       f"Base Severity: {item['base_severity']}, Code: {item['code']}, Description: {item['description']}, "
    #     #       f"NVD Info: {item['nvd_info']}, CWE Info: {item['cwe_info']}, Score: {item['score']:.4f}")
    #     print(f"Score: {item['score']:.4f}, Code: {item['code']}")
    # print('========================================================================')
    # # 返回重排序后的结果
    # return ranked_candidates


# ================== DeepSeek 调用 ==================
# import beam selector (Demonstration attack policy)
try:
    sys.path.append(str(pathlib.Path("Demontration attack").resolve()))
    from da.policy import select_topk
except Exception:
    select_topk = None

# LLM client configuration - supports DeepSeek, Qwen, and GPT
# Priority: GPT_* > QWEN_* > DEEPSEEK_* > default
_BASE_URL = (
    os.getenv("GPT_BASE_URL") or 
    os.getenv("QWEN_BASE_URL") or 
    os.getenv("DEEPSEEK_BASE_URL") or 
    "https://api.deepseek.com"
).strip()
_MODEL = (
    os.getenv("GPT_MODEL") or 
    os.getenv("QWEN_MODEL") or 
    os.getenv("DEEPSEEK_MODEL") or 
    "deepseek-chat"
).strip()
_API_KEY = (
    os.getenv("GPT_API_KEY") or 
    os.getenv("QWEN_API_KEY") or 
    os.getenv("DEEPSEEK_API_KEY") or 
    os.getenv("OPENAI_API_KEY") or 
    ""
).strip()

# Optional import of DeepseekClient (fallback only)
deepseek_client = None
try:
    from code_trans.gen_attack.utils.llm import DeepseekClient
    deepseek_client = DeepseekClient(
        base_url=_BASE_URL,
        model_primary=_MODEL,
        model_fallback=_MODEL,
        temperature=0.0,
        max_tokens=512,
    )
except (ImportError, Exception):
    # If DeepseekClient is not available, we'll use OpenAI client as fallback
    deepseek_client = None

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
    timeout = float(os.getenv("LLM_TIMEOUT", "180"))  # 增加到180秒
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

# ================== 演示攻击：安全标识符重命名（可开关） ==================
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
    极简 C/C++ 风格词法器：跳过注释/字符串/字符字面量，仅在代码段采集标识符 token 及其计数。
    返回 (id_counts: dict[str,int])。
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
    使用相同的极简词法器，仅在代码段（非注释/字符串/字符）且精确 token 匹配时替换。
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
    # 确保不与已存在冲突
    for p in list(pool):
        if p in existing:
            pool.remove(p)
    # 兜底扩展
    i = 0
    while len(pool) < 256 and i < 1000:
        cand = f"var{i}"
        if cand not in existing:
            pool.append(cand)
        i += 1
    return pool

def rename_identifiers_safe(code: str, max_ids: int = 2, seed: int = 42, use_ast: bool = True) -> str:
    """
    变量重命名函数，优先使用AST方法，失败时降级到词法分析
    
    Args:
        code: C/C++代码
        max_ids: 最多改写的变量数
        seed: 随机种子
        use_ast: 是否优先尝试AST方法（默认True）
    
    Returns:
        改写后的代码
    """
    # 优先尝试AST方法
    if use_ast:
        try:
            from rename_ast import rename_identifiers_ast
            result = rename_identifiers_ast(code, max_ids=max_ids, seed=seed, enable_ast=True)
            # 如果AST方法成功（返回了不同的代码），使用它
            if result != code:
                return result
        except Exception:
            # AST方法失败，降级到词法分析
            pass
    
    # 降级到词法分析方法（使用安全的fallback）
    try:
        from retrieval_fallback_safe import rename_identifiers_fallback_safe
        result = rename_identifiers_fallback_safe(code, max_ids=max_ids, seed=seed)
        
        # 设置fallback模式的重命名映射（用于诊断和日志）
        try:
            import rename_ast
            rename_ast.LAST_RENAME_MODE = "fallback"
        except:
            pass
        
        return result
    except (ImportError, Exception) as e:
        # 如果新模块不可用，使用旧的fallback逻辑（不推荐）
        print(f"[fallback] Warning: Using legacy fallback (less safe): {e}", flush=True)
        # 降级到词法分析方法（原有逻辑 - 仅作为最后备选）
        counts = _collect_identifiers_c_like(code)
        if not counts:
            return code
        # 过滤不可改名的"疑似类型/宏"（启发式）：全大写且含下划线；或长度<=1
        renameables = [ident for ident, c in counts.items() if len(ident) > 1 and not (ident.isupper() and '_' in ident)]
        if not renameables:
            return code
        # 选择出现次数多的优先
        renameables.sort(key=lambda x: counts[x], reverse=True)
        picked = renameables[:max(1, max_ids)]
        # 生成新名
        existing = set(counts.keys())
        pool = _generate_new_name_pool(existing, seed)
        id_map = {}
        pi = 0
        for old in picked:
            # 跳过已在映射
            if old in id_map:
                continue
            # 选择一个未冲突的新名
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

# ================== NO-RAG 候选池（全局随机采样） ==================
def _build_no_rag_pool(
    exclude_code: str,
    exclude_desc: str,
    pool_size: int,
    seed: int = 42,
):
    import random
    rnd = random.Random(seed)

    # 优先使用外部指定 CSV
    df_pool = None
    csv_path = os.getenv("FALLBACK_NO_RAG_CSV", "")
    if csv_path and os.path.exists(csv_path):
        try:
            df_pool = pd.read_csv(csv_path)
        except Exception:
            df_pool = None

    # 其次使用 fallback CSV 加载
    if df_pool is None:
        df_pool = _load_fallback_df()

    # 最后退化为当前评测 DF（避免抽到自身样本）
    if df_pool is None:
        df_pool = CURRENT_EVAL_DF

    results = []
    if df_pool is None or df_pool.empty:
        return results

    # 规范列名映射
    code_col = 'func_before' if 'func_before' in df_pool.columns else ('code' if 'code' in df_pool.columns else None)
    desc_col = 'description' if 'description' in df_pool.columns else None
    sev_col = 'Base Severity' if 'Base Severity' in df_pool.columns else ('base_severity' if 'base_severity' in df_pool.columns else None)

    # 候选索引
    idxs = list(range(len(df_pool)))
    rnd.shuffle(idxs)

    for i in idxs:
        if len(results) >= pool_size:
            break
        r = df_pool.iloc[i]
        code = str(r.get(code_col, "")) if code_col else ""
        desc = str(r.get(desc_col, "")) if desc_col else ""

        # 跳过与目标完全相同的条目
        if code and desc and code == exclude_code and desc == exclude_desc:
            continue

        sev = str(r.get(sev_col, "")).strip().upper() if sev_col else ""
        # 随机相似度分数以驱动选择器排序
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

    # 保持按 score 降序
    results.sort(key=lambda x: x.get("score", 0.0), reverse=True)
    return results

# ================== 一次调用LLM（无COT） ==================
def predict_vuln_level(query_code, query_desc, topk_samples):
    """
    一轮LLM（无COT）: 根据相似漏洞样本，直接生成目标漏洞的严重等级
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

    # 计算token
    chat_tokenizer_dir = "./deepseek_v3_tokenizer"  # 本地 tokenizer 路径
    tokenizer = transformers.AutoTokenizer.from_pretrained(chat_tokenizer_dir, trust_remote_code=True)
    system_content = "You are an expert in code vulnerability assessment, and you will rate the vulnerabilities based on the following scoring criteria:\n0.1-3.9: LOW, 4.0-6.9: MEDIUM, 7.0-8.9: HIGH, 9.0-10.0: CRITICAL."
    user_content = prompt
    system_tokens = tokenizer.encode(system_content)
    user_tokens = tokenizer.encode(user_content)
    total_tokens = len(system_tokens) + len(user_tokens)
    print("Total tokens:", total_tokens)

    messages = [
            {"role": "system",
             "content": "You are an expert in code vulnerability assessment, and you will rate the vulnerabilities based on the following scoring criteria:\n0.1-3.9: LOW, 4.0-6.9: MEDIUM, 7.0-8.9: HIGH, 9.0-10.0: CRITICAL."},
            {"role": "user", "content": prompt},
    ]
    off = _chat_official(messages)
    if off is not None:
        return (off.choices[0].message.content if off and off.choices else "")
    raw = _chat_raw(messages)
    if raw is not None:
        return (raw.choices[0]["message"]["content"] if raw and getattr(raw, "choices", None) else "")
    # Fallback: use OpenAI client if DeepseekClient is not available
    if deepseek_client is not None:
        resp = deepseek_client.chat(messages)
        return resp.get("text", "")
    else:
        # Final fallback: use OpenAI client directly
        client = OpenAI(api_key=_API_KEY, base_url=_BASE_URL)
        resp = client.chat.completions.create(
            model=_MODEL,
            messages=messages,
            temperature=0.0,
            max_tokens=512,
            stream=False,
        )
        return resp.choices[0].message.content if resp and resp.choices else ""

# ================== 两次调用LLM ==================
def generate_explanatory_knowledge(query_code, query_desc, topk_samples):
    """
    第一轮 LLM：先分析相似漏洞样本，在结合分析直接生成目标漏洞的结构化解释性知识
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

    # 计算token
    chat_tokenizer_dir = "./deepseek_v3_tokenizer"  # 本地 tokenizer 路径
    tokenizer = transformers.AutoTokenizer.from_pretrained(chat_tokenizer_dir, trust_remote_code=True)
    system_content = "You are an expert in code vulnerability assessment."
    user_content = prompt
    system_tokens = tokenizer.encode(system_content)
    user_tokens = tokenizer.encode(user_content)
    total_tokens = len(system_tokens) + len(user_tokens)
    print("Total tokens:", total_tokens)

    messages = [
            {"role": "system",
             "content": "You are an expert in code vulnerability assessment."},
            {"role": "user", "content": prompt}
    ]
    off = _chat_official(messages)
    if off is not None:
        explanatory_knowledge = off.choices[0].message.content if off and off.choices else ""
    else:
        raw = _chat_raw(messages)
        if raw is not None:
            explanatory_knowledge = raw.choices[0]["message"]["content"] if raw and getattr(raw, "choices", None) else ""
        else:
            # Fallback: use OpenAI client if DeepseekClient is not available
            if deepseek_client is not None:
                resp = deepseek_client.chat(messages)
                explanatory_knowledge = resp.get("text", "")
            else:
                # Final fallback: use OpenAI client directly
                client = OpenAI(api_key=_API_KEY, base_url=_BASE_URL)
                resp = client.chat.completions.create(
                    model=_MODEL,
                    messages=messages,
                    temperature=0.0,
                    max_tokens=512,
                    stream=False,
                )
                explanatory_knowledge = resp.choices[0].message.content if resp and resp.choices else ""
    print(explanatory_knowledge)
    return explanatory_knowledge

def predict_vuln_level_with_knowledge(query_code, query_desc, topk_samples):
    """
    第二轮 LLM：结合第一轮生成的解释性知识，预测目标漏洞等级
    """
    explanatory_knowledge = generate_explanatory_knowledge(query_code, query_desc, topk_samples)

    prompt = "Below is explanatory knowledge extracted from similar vulnerabilities:\n"
    prompt += f"{explanatory_knowledge}\n\n"

    prompt += "Target Vulnerability:\n"
    prompt += f"- Code: {query_code}\n"
    prompt += f"- Description: {query_desc}\n\n"

    prompt = "Based on the explanatory knowledge above, determine the severity level of the target vulnerability.\n"
    prompt += "Please only output one of the following: LOW, MEDIUM, HIGH, CRITICAL, without any explanation."

    # 计算token
    chat_tokenizer_dir = "./deepseek_v3_tokenizer"  # 本地 tokenizer 路径
    tokenizer = transformers.AutoTokenizer.from_pretrained(chat_tokenizer_dir, trust_remote_code=True)
    system_content = "You are an expert in code vulnerability assessment, and you will rate the vulnerabilities based on the following scoring criteria:\n0.1-3.9: LOW, 4.0-6.9: MEDIUM, 7.0-8.9: HIGH, 9.0-10.0: CRITICAL."
    user_content = prompt
    system_tokens = tokenizer.encode(system_content)
    user_tokens = tokenizer.encode(user_content)
    total_tokens = len(system_tokens) + len(user_tokens)
    print("Total tokens:", total_tokens)

    messages = [
            {"role": "system",
             "content": "You are an expert in code vulnerability assessment, and you will rate the vulnerabilities based on the following scoring criteria:\n0.1-3.9: LOW, 4.0-6.9: MEDIUM, 7.0-8.9: HIGH, 9.0-10.0: CRITICAL"},
            {"role": "user", "content": prompt},
    ]
    off = _chat_official(messages)
    if off is not None:
        level = off.choices[0].message.content if off and off.choices else ""
    else:
        raw = _chat_raw(messages)
        if raw is not None:
            level = raw.choices[0]["message"]["content"] if raw and getattr(raw, "choices", None) else ""
        else:
            # Fallback: use OpenAI client if DeepseekClient is not available
            if deepseek_client is not None:
                resp = deepseek_client.chat(messages)
                level = resp.get("text", "")
            else:
                # Final fallback: use OpenAI client directly
                client = OpenAI(api_key=_API_KEY, base_url=_BASE_URL)
                resp = client.chat.completions.create(
                    model=_MODEL,
                    messages=messages,
                    temperature=0.0,
                    max_tokens=512,
                    stream=False,
                )
                level = resp.choices[0].message.content if resp and resp.choices else ""
    return level

# ================== 少样本COT ==================
def predict_vuln_level_fewshot_cot(query_code, query_desc, topk_samples):
    """
    少样本COT 先分析相似漏洞样本，在结合分析直接生成目标漏洞的结构化解释性知识，最后生成漏洞等级
    """
    prompt = "Your task is to analyze vulnerabilities step by step and finally output only the severity of the target vulnerability.\n\n"

    # Step1: 分析示例
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

    # Step2: 分析目标漏洞
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

    # Step3: 输出严重等级（保留新版本的格式要求）
    prompt += "Step 3: Based on Step 1 and Step 2, output the severity level of the target vulnerability.\n"
    prompt += "Do not output any explanation, reasoning process, or the severity levels of the previous sample examples.\n"
    prompt += "Output exactly one line in the format:\n"
    prompt += "SEVERITY: <LOW|MEDIUM|HIGH|CRITICAL>\n"

    # 计算 token
    chat_tokenizer_dir = "./deepseek_v3_tokenizer"  # 本地 tokenizer 路径
    tokenizer = transformers.AutoTokenizer.from_pretrained(
        chat_tokenizer_dir, trust_remote_code=True
    )
    system_content = "You are an expert in code vulnerability assessment, and you will rate the vulnerabilities based on the following scoring criteria:\n0.1-3.9: LOW, 4.0-6.9: MEDIUM, 7.0-8.9: HIGH, 9.0-10.0: CRITICAL."
    system_tokens = tokenizer.encode(system_content)
    user_tokens = tokenizer.encode(prompt)
    total_tokens = len(system_tokens) + len(user_tokens)
    print("Total tokens:", total_tokens)

    messages = [
            {"role": "system", "content": system_content},
            {"role": "user", "content": prompt}
    ]
    off = _chat_official(messages)
    if off is not None:
        level = off.choices[0].message.content if off and off.choices else ""
    else:
        raw = _chat_raw(messages)
        if raw is not None:
            level = raw.choices[0]["message"]["content"] if raw and getattr(raw, "choices", None) else ""
        else:
            # Fallback: use OpenAI client if DeepseekClient is not available
            if deepseek_client is not None:
                resp = deepseek_client.chat(messages)
                level = resp.get("text", "")
            else:
                # Final fallback: use OpenAI client directly
                client = OpenAI(api_key=_API_KEY, base_url=_BASE_URL)
                resp = client.chat.completions.create(
                    model=_MODEL,
                    messages=messages,
                    temperature=0.0,
                    max_tokens=512,
                    stream=False,
                )
                level = resp.choices[0].message.content if resp and resp.choices else ""
    return level

# ================== 主调用函数 ==================
def predict_vuln_level_rag_llm(query_code, query_desc):
    # 1. RAG 多模态检索 topK 样本
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
    """RAG 检索出更大候选池或使用 NO_RAG 全局采样，再用策略选择（默认 beam）组合出 k 个示例。"""
    # PING_ONLY: 极简连通性测试，不构造长提示
    try:
        if os.getenv("PING_ONLY", "0").strip() == "1":
            resp = deepseek_client.chat([
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Hello"},
            ])
            return resp.get("text", "")
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
    if select_topk is None:
        demos = pool[:k]
    else:
        demos = select_topk(
            candidates=pool,
            k=k,
            strategy=strategy,
            query_true_sev=true_severity or "",
            beam_width=beam_width,
            max_pool=pool_size,
            w_sim=w_sim,
            w_sev=w_sev,
            diversity_lambda=diversity_lambda,
        )
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

    # 可选：对 query / demos 执行标识符重命名（演示攻击）
    try:
        if os.getenv("APPLY_REWRITE", "0").strip() == "1":
            target = os.getenv("REWRITE_TARGET", "demos").strip().lower()  # demos|query|both
            max_ids = int(os.getenv("REWRITE_MAX_IDS", "2"))
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

    # DRY_RUN: 跳过 LLM，仅输出选样信息
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


# ================== 运行 ==================
if __name__ == "__main__":
    """
    运行
    """
    # 读取 Excel 文件
    input_file = os.getenv("INPUT_FILE", "datasets/test/test_all.xlsx")
    output_file = os.getenv("OUTPUT_FILE", "test_all_predicted2.xlsx")
    temp_file = os.getenv("TEMP_FILE", os.path.splitext(output_file)[0] + "_temp.xlsx")

    VALID_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    # 判断是否已经有预测文件
    if os.path.exists(output_file):
        df = pd.read_excel(output_file)
        print(f"继续运行：已加载 {output_file}")
    else:
        df = pd.read_excel(input_file)
        df["Predicted"] = ""  # 初始化预测列
        print(f"新运行：加载 {input_file}")

    # 记录当前评测 DF 以供 NO_RAG 候选池使用
    try:
        CURRENT_EVAL_DF = df
    except Exception:
        pass

    # 找到 Predicted 不在有效等级集合的行
    rows_to_predict = df[~df["Predicted"].astype(str).str.strip().isin(VALID_LEVELS)].index
    # 可选：随机打乱顺序
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

    # 小范围实验参数
    STRATEGY = os.getenv("STRATEGY", "beam").strip().lower()
    # 统一通过 selector 路径，便于 DUMP_DEMOS 与对齐对比
    USE_BEAM = STRATEGY in ("beam", "adversarial", "baseline")
    MAX_RUN = int(os.getenv("SMALL_RUN_MAX", "20"))
    # beam params
    TOPK_RUN = int(os.getenv("TOPK", str(TOPK)))
    POOL_SIZE = int(os.getenv("POOL_SIZE", "30"))
    BEAM_WIDTH = int(os.getenv("BEAM_WIDTH", "8"))
    W_SIM = float(os.getenv("W_SIM", "0.7"))
    W_SEV = float(os.getenv("W_SEV", "0.3"))
    DIVERSITY = float(os.getenv("DIVERSITY_LAMBDA", "0.1"))

    if len(rows_to_predict) == 0:
        print("所有行都已经预测完成！")
    else:
        processed = 0
        for idx in rows_to_predict:
            row = df.loc[idx]
            query_code = row['func_before']
            query_desc = row['description']

            try:
                # 预测漏洞等级（通过策略选择器）
                if USE_BEAM:
                    true_sev = str(row.get('Base Severity', '')).strip().upper()
                    level = predict_vuln_level_rag_llm_beam(
                        query_code=query_code,
                        query_desc=query_desc,
                        true_severity=true_sev,
                        k=TOPK_RUN,
                        pool_size=POOL_SIZE,
                        strategy=STRATEGY,
                        beam_width=BEAM_WIDTH,
                        w_sim=W_SIM,
                        w_sev=W_SEV,
                        diversity_lambda=DIVERSITY,
                    )
                else:
                    level = predict_vuln_level_rag_llm(query_code, query_desc)
                print(f"Row {idx}: {level} (Base Severity: {row['Base Severity']})")
            except Exception as e:
                print(f"Error at row {idx}: {e}")
                level = ""

            # 写入预测结果
            df.at[idx, "Predicted"] = level

            # 保存到临时文件，再覆盖
            df.to_excel(temp_file, index=False)
            os.replace(temp_file, output_file)

            processed += 1
            if processed >= MAX_RUN:
                print(f"小范围实验达到上限 MAX_RUN={MAX_RUN}，提前退出。")
                break

        print(f"预测完成，结果已保存到 {output_file}")

def _generate_new_name_pool(existing: set, seed: int):
    import random
    rnd = random.Random(seed)
    pool = list(_RENAME_DICT)
    rnd.shuffle(pool)
    # 确保不与已存在冲突
    for p in list(pool):
        if p in existing:
            pool.remove(p)
    # 兜底扩展
    i = 0
    while len(pool) < 256 and i < 1000:
        cand = f"var{i}"
        if cand not in existing:
            pool.append(cand)
        i += 1
    return pool

def rename_identifiers_safe(code: str, max_ids: int = 2, seed: int = 42, use_ast: bool = True) -> str:
    """
    变量重命名函数，优先使用AST方法，失败时降级到词法分析
    
    Args:
        code: C/C++代码
        max_ids: 最多改写的变量数
        seed: 随机种子
        use_ast: 是否优先尝试AST方法（默认True）
    
    Returns:
        改写后的代码
    """
    # 优先尝试AST方法
    if use_ast:
        try:
            from rename_ast import rename_identifiers_ast
            result = rename_identifiers_ast(code, max_ids=max_ids, seed=seed, enable_ast=True)
            # 如果AST方法成功（返回了不同的代码），使用它
            if result != code:
                return result
        except Exception:
            # AST方法失败，降级到词法分析
            pass
    
    # 降级到词法分析方法（使用安全的fallback）
    try:
        from retrieval_fallback_safe import rename_identifiers_fallback_safe
        result = rename_identifiers_fallback_safe(code, max_ids=max_ids, seed=seed)
        
        # 设置fallback模式的重命名映射（用于诊断和日志）
        try:
            import rename_ast
            rename_ast.LAST_RENAME_MODE = "fallback"
        except:
            pass
        
        return result
    except (ImportError, Exception) as e:
        # 如果新模块不可用，使用旧的fallback逻辑（不推荐）
        print(f"[fallback] Warning: Using legacy fallback (less safe): {e}", flush=True)
        # 降级到词法分析方法（原有逻辑 - 仅作为最后备选）
        counts = _collect_identifiers_c_like(code)
        if not counts:
            return code
        # 过滤不可改名的"疑似类型/宏"（启发式）：全大写且含下划线；或长度<=1
        renameables = [ident for ident, c in counts.items() if len(ident) > 1 and not (ident.isupper() and '_' in ident)]
        if not renameables:
            return code
        # 选择出现次数多的优先
        renameables.sort(key=lambda x: counts[x], reverse=True)
        picked = renameables[:max(1, max_ids)]
        # 生成新名
        existing = set(counts.keys())
        pool = _generate_new_name_pool(existing, seed)
        id_map = {}
        pi = 0
        for old in picked:
            # 跳过已在映射
            if old in id_map:
                continue
            # 选择一个未冲突的新名
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

# ================== NO-RAG 候选池（全局随机采样） ==================
def _build_no_rag_pool(
    exclude_code: str,
    exclude_desc: str,
    pool_size: int,
    seed: int = 42,
):
    import random
    rnd = random.Random(seed)

    # 优先使用外部指定 CSV
    df_pool = None
    csv_path = os.getenv("FALLBACK_NO_RAG_CSV", "")
    if csv_path and os.path.exists(csv_path):
        try:
            df_pool = pd.read_csv(csv_path)
        except Exception:
            df_pool = None

    # 其次使用 fallback CSV 加载
    if df_pool is None:
        df_pool = _load_fallback_df()

    # 最后退化为当前评测 DF（避免抽到自身样本）
    if df_pool is None:
        df_pool = CURRENT_EVAL_DF

    results = []
    if df_pool is None or df_pool.empty:
        return results

    # 规范列名映射
    code_col = 'func_before' if 'func_before' in df_pool.columns else ('code' if 'code' in df_pool.columns else None)
    desc_col = 'description' if 'description' in df_pool.columns else None
    sev_col = 'Base Severity' if 'Base Severity' in df_pool.columns else ('base_severity' if 'base_severity' in df_pool.columns else None)

    # 候选索引
    idxs = list(range(len(df_pool)))
    rnd.shuffle(idxs)

    for i in idxs:
        if len(results) >= pool_size:
            break
        r = df_pool.iloc[i]
        code = str(r.get(code_col, "")) if code_col else ""
        desc = str(r.get(desc_col, "")) if desc_col else ""

        # 跳过与目标完全相同的条目
        if code and desc and code == exclude_code and desc == exclude_desc:
            continue

        sev = str(r.get(sev_col, "")).strip().upper() if sev_col else ""
        # 随机相似度分数以驱动选择器排序
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

    # 保持按 score 降序
    results.sort(key=lambda x: x.get("score", 0.0), reverse=True)
    return results

# ================== 一次调用LLM（无COT） ==================
def predict_vuln_level(query_code, query_desc, topk_samples):
    """
    一轮LLM（无COT）: 根据相似漏洞样本，直接生成目标漏洞的严重等级
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

    # 计算token
    chat_tokenizer_dir = "./deepseek_v3_tokenizer"  # 本地 tokenizer 路径
    tokenizer = transformers.AutoTokenizer.from_pretrained(chat_tokenizer_dir, trust_remote_code=True)
    system_content = "You are an expert in code vulnerability assessment, and you will rate the vulnerabilities based on the following scoring criteria:\n0.1-3.9: LOW, 4.0-6.9: MEDIUM, 7.0-8.9: HIGH, 9.0-10.0: CRITICAL."
    user_content = prompt
    system_tokens = tokenizer.encode(system_content)
    user_tokens = tokenizer.encode(user_content)
    total_tokens = len(system_tokens) + len(user_tokens)
    print("Total tokens:", total_tokens)

    messages = [
            {"role": "system",
             "content": "You are an expert in code vulnerability assessment, and you will rate the vulnerabilities based on the following scoring criteria:\n0.1-3.9: LOW, 4.0-6.9: MEDIUM, 7.0-8.9: HIGH, 9.0-10.0: CRITICAL."},
            {"role": "user", "content": prompt},
    ]
    off = _chat_official(messages)
    if off is not None:
        return (off.choices[0].message.content if off and off.choices else "")
    raw = _chat_raw(messages)
    if raw is not None:
        return (raw.choices[0]["message"]["content"] if raw and getattr(raw, "choices", None) else "")
    # Fallback: use OpenAI client if DeepseekClient is not available
    if deepseek_client is not None:
        resp = deepseek_client.chat(messages)
        return resp.get("text", "")
    else:
        # Final fallback: use OpenAI client directly
        client = OpenAI(api_key=_API_KEY, base_url=_BASE_URL)
        resp = client.chat.completions.create(
            model=_MODEL,
            messages=messages,
            temperature=0.0,
            max_tokens=512,
            stream=False,
        )
        return resp.choices[0].message.content if resp and resp.choices else ""

# ================== 两次调用LLM ==================
def generate_explanatory_knowledge(query_code, query_desc, topk_samples):
    """
    第一轮 LLM：先分析相似漏洞样本，在结合分析直接生成目标漏洞的结构化解释性知识
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

    # 计算token
    chat_tokenizer_dir = "./deepseek_v3_tokenizer"  # 本地 tokenizer 路径
    tokenizer = transformers.AutoTokenizer.from_pretrained(chat_tokenizer_dir, trust_remote_code=True)
    system_content = "You are an expert in code vulnerability assessment."
    user_content = prompt
    system_tokens = tokenizer.encode(system_content)
    user_tokens = tokenizer.encode(user_content)
    total_tokens = len(system_tokens) + len(user_tokens)
    print("Total tokens:", total_tokens)

    messages = [
            {"role": "system",
             "content": "You are an expert in code vulnerability assessment."},
            {"role": "user", "content": prompt}
    ]
    off = _chat_official(messages)
    if off is not None:
        explanatory_knowledge = off.choices[0].message.content if off and off.choices else ""
    else:
        raw = _chat_raw(messages)
        if raw is not None:
            explanatory_knowledge = raw.choices[0]["message"]["content"] if raw and getattr(raw, "choices", None) else ""
        else:
            # Fallback: use OpenAI client if DeepseekClient is not available
            if deepseek_client is not None:
                resp = deepseek_client.chat(messages)
                explanatory_knowledge = resp.get("text", "")
            else:
                # Final fallback: use OpenAI client directly
                client = OpenAI(api_key=_API_KEY, base_url=_BASE_URL)
                resp = client.chat.completions.create(
                    model=_MODEL,
                    messages=messages,
                    temperature=0.0,
                    max_tokens=512,
                    stream=False,
                )
                explanatory_knowledge = resp.choices[0].message.content if resp and resp.choices else ""
    print(explanatory_knowledge)
    return explanatory_knowledge

def predict_vuln_level_with_knowledge(query_code, query_desc, topk_samples):
    """
    第二轮 LLM：结合第一轮生成的解释性知识，预测目标漏洞等级
    """
    explanatory_knowledge = generate_explanatory_knowledge(query_code, query_desc, topk_samples)

    prompt = "Below is explanatory knowledge extracted from similar vulnerabilities:\n"
    prompt += f"{explanatory_knowledge}\n\n"

    prompt += "Target Vulnerability:\n"
    prompt += f"- Code: {query_code}\n"
    prompt += f"- Description: {query_desc}\n\n"

    prompt = "Based on the explanatory knowledge above, determine the severity level of the target vulnerability.\n"
    prompt += "Please only output one of the following: LOW, MEDIUM, HIGH, CRITICAL, without any explanation."

    # 计算token
    chat_tokenizer_dir = "./deepseek_v3_tokenizer"  # 本地 tokenizer 路径
    tokenizer = transformers.AutoTokenizer.from_pretrained(chat_tokenizer_dir, trust_remote_code=True)
    system_content = "You are an expert in code vulnerability assessment, and you will rate the vulnerabilities based on the following scoring criteria:\n0.1-3.9: LOW, 4.0-6.9: MEDIUM, 7.0-8.9: HIGH, 9.0-10.0: CRITICAL."
    user_content = prompt
    system_tokens = tokenizer.encode(system_content)
    user_tokens = tokenizer.encode(user_content)
    total_tokens = len(system_tokens) + len(user_tokens)
    print("Total tokens:", total_tokens)

    messages = [
            {"role": "system",
             "content": "You are an expert in code vulnerability assessment, and you will rate the vulnerabilities based on the following scoring criteria:\n0.1-3.9: LOW, 4.0-6.9: MEDIUM, 7.0-8.9: HIGH, 9.0-10.0: CRITICAL"},
            {"role": "user", "content": prompt},
    ]
    off = _chat_official(messages)
    if off is not None:
        level = off.choices[0].message.content if off and off.choices else ""
    else:
        raw = _chat_raw(messages)
        if raw is not None:
            level = raw.choices[0]["message"]["content"] if raw and getattr(raw, "choices", None) else ""
        else:
            # Fallback: use OpenAI client if DeepseekClient is not available
            if deepseek_client is not None:
                resp = deepseek_client.chat(messages)
                level = resp.get("text", "")
            else:
                # Final fallback: use OpenAI client directly
                client = OpenAI(api_key=_API_KEY, base_url=_BASE_URL)
                resp = client.chat.completions.create(
                    model=_MODEL,
                    messages=messages,
                    temperature=0.0,
                    max_tokens=512,
                    stream=False,
                )
                level = resp.choices[0].message.content if resp and resp.choices else ""
    return level

# ================== 少样本COT ==================
def predict_vuln_level_fewshot_cot(query_code, query_desc, topk_samples):
    """
    少样本COT 先分析相似漏洞样本，在结合分析直接生成目标漏洞的结构化解释性知识，最后生成漏洞等级
    """
    prompt = "Your task is to analyze vulnerabilities step by step and finally output only the severity of the target vulnerability.\n\n"

    # Step1: 分析示例
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
        # prompt += f"- Similarity Score: {item['score']}\n\n"

    # Step2: 分析目标漏洞
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

    # Step3: 输出严重等级
    prompt += "Step 3: Based on Step 1 and Step 2, You only need to output the severity level of the target vulnerability.\n"
    prompt += "Do not output any explanation, reasoning process, or the severity levels of the previous sample examples.\n"

    # 计算token
    chat_tokenizer_dir = "./deepseek_v3_tokenizer"  # 本地 tokenizer 路径
    tokenizer = transformers.AutoTokenizer.from_pretrained(chat_tokenizer_dir, trust_remote_code=True)
    system_content = "You are an expert in code vulnerability assessment, and you will rate the vulnerabilities based on the following scoring criteria:\n0.1-3.9: LOW, 4.0-6.9: MEDIUM, 7.0-8.9: HIGH, 9.0-10.0: CRITICAL."
    user_content = prompt
    system_tokens = tokenizer.encode(system_content)
    user_tokens = tokenizer.encode(user_content)
    total_tokens = len(system_tokens) + len(user_tokens)
    print("Total tokens:", total_tokens)

    messages = [
            {"role": "system", "content": "You are an expert in code vulnerability assessment, and you will rate the vulnerabilities based on the following scoring criteria:\n0.1-3.9: LOW, 4.0-6.9: MEDIUM, 7.0-8.9: HIGH, 9.0-10.0: CRITICAL."},
            {"role": "user", "content": prompt}
    ]
    off = _chat_official(messages)
    if off is not None:
        level = off.choices[0].message.content if off and off.choices else ""
    else:
        raw = _chat_raw(messages)
        if raw is not None:
            level = raw.choices[0]["message"]["content"] if raw and getattr(raw, "choices", None) else ""
        else:
            # Fallback: use OpenAI client if DeepseekClient is not available
            if deepseek_client is not None:
                resp = deepseek_client.chat(messages)
                level = resp.get("text", "")
            else:
                # Final fallback: use OpenAI client directly
                client = OpenAI(api_key=_API_KEY, base_url=_BASE_URL)
                resp = client.chat.completions.create(
                    model=_MODEL,
                    messages=messages,
                    temperature=0.0,
                    max_tokens=512,
                    stream=False,
                )
                level = resp.choices[0].message.content if resp and resp.choices else ""
    return level

# ================== 主调用函数 ==================
def predict_vuln_level_rag_llm(query_code, query_desc):
    # 1. RAG 多模态检索 topK 样本
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
    """RAG 检索出更大候选池或使用 NO_RAG 全局采样，再用策略选择（默认 beam）组合出 k 个示例。"""
    # PING_ONLY: 极简连通性测试，不构造长提示
    try:
        if os.getenv("PING_ONLY", "0").strip() == "1":
            resp = deepseek_client.chat([
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Hello"},
            ])
            return resp.get("text", "")
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
    if select_topk is None:
        demos = pool[:k]
    else:
        demos = select_topk(
            candidates=pool,
            k=k,
            strategy=strategy,
            query_true_sev=true_severity or "",
            beam_width=beam_width,
            max_pool=pool_size,
            w_sim=w_sim,
            w_sev=w_sev,
            diversity_lambda=diversity_lambda,
        )
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

    # 可选：对 query / demos 执行标识符重命名（演示攻击）
    try:
        if os.getenv("APPLY_REWRITE", "0").strip() == "1":
            target = os.getenv("REWRITE_TARGET", "demos").strip().lower()  # demos|query|both
            max_ids = int(os.getenv("REWRITE_MAX_IDS", "2"))
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

    # DRY_RUN: 跳过 LLM，仅输出选样信息
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


# ================== 运行 ==================
if __name__ == "__main__":
    """
    运行
    """
    # 读取 Excel 文件
    input_file = os.getenv("INPUT_FILE", "datasets/test/test_all.xlsx")
    output_file = os.getenv("OUTPUT_FILE", "test_all_predicted2.xlsx")
    temp_file = os.getenv("TEMP_FILE", os.path.splitext(output_file)[0] + "_temp.xlsx")

    VALID_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    # 判断是否已经有预测文件
    if os.path.exists(output_file):
        df = pd.read_excel(output_file)
        print(f"继续运行：已加载 {output_file}")
    else:
        df = pd.read_excel(input_file)
        df["Predicted"] = ""  # 初始化预测列
        print(f"新运行：加载 {input_file}")

    # 记录当前评测 DF 以供 NO_RAG 候选池使用
    try:
        CURRENT_EVAL_DF = df
    except Exception:
        pass

    # 找到 Predicted 不在有效等级集合的行
    rows_to_predict = df[~df["Predicted"].astype(str).str.strip().isin(VALID_LEVELS)].index
    # 可选：随机打乱顺序
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

    # 小范围实验参数
    STRATEGY = os.getenv("STRATEGY", "beam").strip().lower()
    # 统一通过 selector 路径，便于 DUMP_DEMOS 与对齐对比
    USE_BEAM = STRATEGY in ("beam", "adversarial", "baseline")
    MAX_RUN = int(os.getenv("SMALL_RUN_MAX", "20"))
    # beam params
    TOPK_RUN = int(os.getenv("TOPK", str(TOPK)))
    POOL_SIZE = int(os.getenv("POOL_SIZE", "30"))
    BEAM_WIDTH = int(os.getenv("BEAM_WIDTH", "8"))
    W_SIM = float(os.getenv("W_SIM", "0.7"))
    W_SEV = float(os.getenv("W_SEV", "0.3"))
    DIVERSITY = float(os.getenv("DIVERSITY_LAMBDA", "0.1"))

    if len(rows_to_predict) == 0:
        print("所有行都已经预测完成！")
    else:
        processed = 0
        for idx in rows_to_predict:
            row = df.loc[idx]
            query_code = row['func_before']
            query_desc = row['description']

            try:
                # 预测漏洞等级（通过策略选择器）
                if USE_BEAM:
                    true_sev = str(row.get('Base Severity', '')).strip().upper()
                    level = predict_vuln_level_rag_llm_beam(
                        query_code=query_code,
                        query_desc=query_desc,
                        true_severity=true_sev,
                        k=TOPK_RUN,
                        pool_size=POOL_SIZE,
                        strategy=STRATEGY,
                        beam_width=BEAM_WIDTH,
                        w_sim=W_SIM,
                        w_sev=W_SEV,
                        diversity_lambda=DIVERSITY,
                    )
                else:
                    level = predict_vuln_level_rag_llm(query_code, query_desc)
                print(f"Row {idx}: {level} (Base Severity: {row['Base Severity']})")
            except Exception as e:
                print(f"Error at row {idx}: {e}")
                level = ""

            # 写入预测结果
            df.at[idx, "Predicted"] = level

            # 保存到临时文件，再覆盖
            df.to_excel(temp_file, index=False)
            os.replace(temp_file, output_file)

            processed += 1
            if processed >= MAX_RUN:
                print(f"小范围实验达到上限 MAX_RUN={MAX_RUN}，提前退出。")
                break

        print(f"预测完成，结果已保存到 {output_file}")
