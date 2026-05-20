# coding:utf-8
"""
基于AST的变量重命名模块
使用tree-sitter解析C/C++代码，实现语义化的变量重命名
"""
import os
import re
import math
import random
from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Optional, Set, Tuple
import tree_sitter
from tree_sitter import Language, Parser

# ================== 枚举定义 ==================

class VariableRole(Enum):
    """变量角色"""
    PARAMETER = "parameter"      # 函数参数
    RESOURCE = "resource"        # 资源/指针 (FILE*, void*, etc.)
    LOCAL = "local"              # 普通局部变量
    LOOP_INDEX = "loop_index"    # 循环索引 (for/while)
    FIELD = "field"              # 结构体字段

class SemanticFamily(Enum):
    """语义家族"""
    COUNTER = "counter"          # count, total, num, cnt, etc.
    BUFFER = "buffer"            # buf, buffer, data, ptr, etc.
    INDEX = "index"              # idx, index, i, j, pos, etc.
    FLAG = "flag"                # flag, is_*, has_*, enable, etc.
    GENERIC = "generic"          # 其他通用变量

# ================== Semantic Family 词典 ==================

SEMANTIC_FAMILIES = {
    SemanticFamily.COUNTER: [
        'count', 'counter', 'total', 'num', 'cnt', 'number', 'n',
        'size', 'length', 'len', 'amount', 'sum', 'acc', 'accumulator'
    ],
    SemanticFamily.BUFFER: [
        'buf', 'buffer', 'data', 'ptr', 'pointer', 'p', 'mem', 'memory',
        'array', 'arr', 'list', 'vec', 'vector', 'storage', 'storage'
    ],
    SemanticFamily.INDEX: [
        'idx', 'index', 'i', 'j', 'k', 'pos', 'position', 'offset',
        'ind', 'cursor', 'iter', 'iterator', 'it'
    ],
    SemanticFamily.FLAG: [
        'flag', 'is_*', 'has_*', 'enable', 'disable', 'active', 'valid',
        'ok', 'success', 'error', 'err', 'status', 'state'
    ],
    SemanticFamily.GENERIC: [
        'value', 'val', 'item', 'obj', 'object', 'entry', 'node',
        'result', 'res', 'ret', 'return', 'tmp', 'temp', 'var'
    ]
}

# ================== 角色配额 ==================

ROLE_QUOTAS = {
    VariableRole.PARAMETER: (0, 3),      # 最少0个，最多3个
    VariableRole.RESOURCE: (0, 2),       # 最少0个，最多2个
    VariableRole.LOCAL: (0, 5),         # 最少0个，最多5个
    VariableRole.LOOP_INDEX: (0, 1),     # 最少0个，最多1个
    VariableRole.FIELD: (0, 2),         # 最少0个，最多2个
}

# ================== 数据结构 ==================

@dataclass
class VariableInfo:
    """变量信息"""
    name: str                    # 变量名
    role: VariableRole          # 角色
    family: SemanticFamily      # 语义家族
    type_hint: Optional[str]    # 类型提示 (如 "int*", "FILE*")
    scope_level: int            # 作用域层级 (0=参数, 1=函数内, 2=块内)
    usage_count: int            # 使用次数
    is_pointer: bool            # 是否为指针
    importance_score: float     # 重要性分数 (计算得出)
    node: Optional[any] = None  # AST节点（用于替换）

# ================== Tree-sitter 初始化 ==================

_TS_LANGUAGE = None
_TS_PARSER = None
_TS_INIT_FAILED = False
LAST_RENAME_MODE = "unknown"
LAST_RENAME_ID_MAP: Dict[str, str] = {}

def _init_tree_sitter():
    """初始化tree-sitter解析器"""
    global _TS_LANGUAGE, _TS_PARSER, _TS_INIT_FAILED
    
    if _TS_INIT_FAILED:
        print("[AST] init skip (previous failure)", flush=True)
        return None, None
    
    if _TS_LANGUAGE is not None and _TS_PARSER is not None:
        return _TS_LANGUAGE, _TS_PARSER
    
    last_error: Optional[Exception] = None
    last_context: str = ""
    
    # 策略1: 尝试加载已编译的语言库（多个可能路径）
    possible_paths = [
        'build/my-languages.so',
        'build1/my-languages.so',
        'build/my-languages.dll',  # Windows
        'build1/my-languages.dll',  # Windows
    ]
    
    for lib_path in possible_paths:
        if os.path.exists(lib_path):
            try:
                _TS_LANGUAGE = Language(lib_path, 'c')
                _TS_PARSER = Parser()
                _TS_PARSER.set_language(_TS_LANGUAGE)
                print(f"[AST] init OK ({lib_path})", flush=True)
                return _TS_LANGUAGE, _TS_PARSER
            except Exception as exc:
                last_error = exc
                last_context = f"load {lib_path}"
    
    # 策略2: 尝试从源码构建（需要tree-sitter-c仓库）
    try:
        # 检查是否有tree-sitter-c目录
        ts_c_paths = [
            'vendor/tree-sitter-c',
            'tree-sitter-c',
            os.path.join(os.path.expanduser('~'), 'tree-sitter-c'),
        ]
        
        ts_c_path = None
        for path in ts_c_paths:
            if os.path.exists(path) and os.path.isdir(path):
                ts_c_path = path
                break
        
        if ts_c_path:
            # 创建build目录
            os.makedirs('build', exist_ok=True)
            lib_path = 'build/my-languages.so' if os.name != 'nt' else 'build/my-languages.dll'
            
            # 构建语言库
            Language.build_library(lib_path, [ts_c_path])
            _TS_LANGUAGE = Language(lib_path, 'c')
            _TS_PARSER = Parser()
            _TS_PARSER.set_language(_TS_LANGUAGE)
            print(f"[AST] init OK (build from {ts_c_path})", flush=True)
            return _TS_LANGUAGE, _TS_PARSER
    except Exception as exc:
        if last_error is None:
            last_error = exc
            last_context = f"build from {ts_c_path or 'unknown'}"
    
    # 策略3: 尝试使用tree-sitter-languages包（推荐方式）
    # 注意：tree-sitter-languages 1.10.2 与 tree-sitter 0.22.3 存在兼容性问题
    # 暂时禁用此策略，等待包更新或使用其他方式
    try:
        import tree_sitter_languages
        # 尝试新API（如果可用）
        try:
            _TS_LANGUAGE = tree_sitter_languages.get_language("c")
            _TS_PARSER = Parser()
            _TS_PARSER.set_language(_TS_LANGUAGE)
            print("[AST] init OK (tree_sitter_languages package)", flush=True)
            return _TS_LANGUAGE, _TS_PARSER
        except TypeError:
            # 如果新API失败，尝试旧API（需要降级tree-sitter）
            raise
    except Exception as exc:
        if last_error is None:
            last_error = exc
            last_context = f"tree_sitter_languages package: {type(exc).__name__}: {str(exc)}"
    
    # 策略4: 尝试从GitHub克隆tree-sitter-c（如果网络可用且目录不存在）
    # 注意：这需要git和网络连接
    try:
        import subprocess
        ts_c_path = 'tree-sitter-c'
        if not os.path.exists(ts_c_path):
            # 尝试克隆
            try:
                subprocess.run(['git', 'clone', '--depth', '1', 
                               'https://github.com/tree-sitter/tree-sitter-c.git', 
                               ts_c_path], 
                              check=True, capture_output=True, timeout=30)
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                pass  # 克隆失败，继续尝试其他方式
        
        if os.path.exists(ts_c_path) and os.path.isdir(ts_c_path):
            # 构建库
            os.makedirs('build', exist_ok=True)
            lib_path = 'build/my-languages.so' if os.name != 'nt' else 'build/my-languages.dll'
            Language.build_library(lib_path, [ts_c_path])
            _TS_LANGUAGE = Language(lib_path, 'c')
            _TS_PARSER = Parser()
            _TS_PARSER.set_language(_TS_LANGUAGE)
            print(f"[AST] init OK (cloned and built from GitHub)", flush=True)
            return _TS_LANGUAGE, _TS_PARSER
    except Exception as exc:
        if last_error is None:
            last_error = exc
            last_context = "clone from GitHub"
    
    # 所有策略都失败，标记为失败并返回None
    _TS_INIT_FAILED = True
    msg = f"[AST] init FAIL ({last_context})"
    if last_error is not None:
        msg += f": {type(last_error).__name__}: {str(last_error)}"
    print(msg, flush=True)
    print("[AST] 注意: AST初始化失败，将自动使用词法分析fallback模式（功能正常）", flush=True)
    print("[AST] 提示: 要启用AST功能，请执行以下步骤之一:", flush=True)
    print("  1. 降级tree-sitter: pip install 'tree-sitter<0.22.0'", flush=True)
    print("  2. 克隆tree-sitter-c: git clone https://github.com/tree-sitter/tree-sitter-c.git", flush=True)
    print("  3. 或将已编译的库放在 build/my-languages.dll (Windows) 或 build/my-languages.so (Linux)", flush=True)
    return None, None

# ================== Semantic Family 分配 ==================

def assign_semantic_family(name: str) -> SemanticFamily:
    """基于变量名特征分配语义家族"""
    name_lower = name.lower()
    
    # 1. 精确匹配
    for family, names in SEMANTIC_FAMILIES.items():
        if name_lower in [n.lower() for n in names]:
            return family
    
    # 2. 前缀匹配 (is_*, has_*)
    if name_lower.startswith('is_') or name_lower.startswith('has_'):
        return SemanticFamily.FLAG
    
    # 3. 后缀匹配
    if any(name_lower.endswith(suffix) for suffix in ['_count', '_cnt', '_num', '_total']):
        return SemanticFamily.COUNTER
    if any(name_lower.endswith(suffix) for suffix in ['_buf', '_buffer', '_ptr', '_data']):
        return SemanticFamily.BUFFER
    if any(name_lower.endswith(suffix) for suffix in ['_idx', '_index', '_pos', '_offset']):
        return SemanticFamily.INDEX
    if any(name_lower.endswith(suffix) for suffix in ['_flag', '_status', '_state']):
        return SemanticFamily.FLAG
    
    # 4. 单字符模式 (通常是索引)
    if len(name) == 1 and name.lower() in ['i', 'j', 'k', 'm', 'n']:
        return SemanticFamily.INDEX
    
    # 5. 默认: GENERIC
    return SemanticFamily.GENERIC

# ================== AST解析和变量提取 ==================

def parse_c_code(code: str) -> Optional[any]:
    """解析C代码，返回AST根节点"""
    lang, parser = _init_tree_sitter()
    if lang is None or parser is None:
        return None
    
    try:
        # Parser已经设置了language，直接使用
        tree = parser.parse(bytes(code, 'utf8'))
        if tree is None:
            return None
        return tree.root_node
    except Exception as e:
        # 静默失败，返回None（将降级到词法分析）
        return None

def extract_type_hint(node) -> Optional[str]:
    """从AST节点提取类型提示"""
    try:
        # 查找类型节点
        type_node = None
        for child in node.children:
            if child.type in ['primitive_type', 'type_identifier', 'sized_type_specifier']:
                type_node = child
                break
        
        if type_node is None:
            return None
        
        type_text = type_node.text.decode('utf8')
        
        # 检查是否为指针
        is_ptr = False
        for child in node.children:
            if child.type == 'pointer_declarator' or '*' in child.text.decode('utf8'):
                is_ptr = True
                break
        
        return f"{type_text}*" if is_ptr else type_text
    except Exception:
        return None

def is_pointer_type(type_hint: Optional[str]) -> bool:
    """判断类型是否为指针"""
    if type_hint is None:
        return False
    return '*' in type_hint or 'ptr' in type_hint.lower()

def is_resource_type(type_hint: Optional[str]) -> bool:
    """判断类型是否为资源类型（FILE*, HANDLE等）"""
    if type_hint is None:
        return False
    resource_keywords = ['file', 'handle', 'socket', 'fd', 'stream']
    return any(kw in type_hint.lower() for kw in resource_keywords)

def identify_variable_role(
    var_name: str,
    node: any,
    ast_root: any,
    type_hint: Optional[str]
) -> VariableRole:
    """识别变量角色"""
    # 1. 检查是否为函数参数
    parent = node.parent
    while parent is not None:
        if parent.type == 'parameter_list':
            return VariableRole.PARAMETER
        if parent.type == 'function_definition':
            break
        parent = parent.parent
    
    # 2. 检查是否为资源/指针
    if is_resource_type(type_hint) or (is_pointer_type(type_hint) and 'buf' in var_name.lower()):
        return VariableRole.RESOURCE
    
    # 3. 检查是否为循环索引
    parent = node.parent
    while parent is not None:
        if parent.type in ['for_statement', 'while_statement']:
            # 检查是否在循环初始化或条件中
            for child in parent.children:
                if child.type in ['init_declarator', 'condition']:
                    if var_name in child.text.decode('utf8'):
                        return VariableRole.LOOP_INDEX
        if parent.type == 'function_definition':
            break
        parent = parent.parent
    
    # 4. 检查是否为字段（结构体成员）
    parent = node.parent
    while parent is not None:
        if parent.type in ['field_declaration', 'field_declaration_list']:
            return VariableRole.FIELD
        if parent.type == 'function_definition':
            break
        parent = parent.parent
    
    # 5. 默认: 局部变量
    return VariableRole.LOCAL

def count_variable_usage(var_name: str, ast_root: any) -> int:
    """统计变量使用次数"""
    count = 0
    if ast_root is None:
        return 0
    
    def traverse(node):
        nonlocal count
        if node.type == 'identifier' and node.text.decode('utf8') == var_name:
            count += 1
        for child in node.children:
            traverse(child)
    
    try:
        traverse(ast_root)
    except Exception:
        pass
    
    return count

def extract_variables(ast_root: any) -> List[VariableInfo]:
    """从AST提取变量信息"""
    if ast_root is None:
        return []
    
    variables: Dict[str, VariableInfo] = {}
    
    # 收集所有函数调用名，避免误识别为变量
    function_calls = set()
    
    def collect_function_calls(node):
        """收集函数调用名"""
        if node.type == 'call_expression':
            for child in node.children:
                if child.type == 'identifier':
                    func_name = child.text.decode('utf8')
                    function_calls.add(func_name)
        for child in node.children:
            collect_function_calls(child)
    
    def traverse(node):
        # 查找变量声明
        if node.type in ['init_declarator', 'declarator', 'parameter_declaration']:
            # 提取变量名
            for child in node.children:
                if child.type == 'identifier':
                    var_name = child.text.decode('utf8')
                    
                    # 跳过函数调用名
                    if var_name in function_calls:
                        continue
                    
                    # 跳过关键字和单字符（除非是常见索引）
                    if len(var_name) <= 1 and var_name.lower() not in ['i', 'j', 'k']:
                        continue
                    if var_name.isupper() and '_' in var_name:  # 可能是宏
                        continue
                    
                    # 检查父节点，确保是变量声明而不是函数定义
                    parent = node.parent
                    is_function_def = False
                    while parent is not None:
                        if parent.type == 'function_definition':
                            # 检查是否是函数名本身
                            for pchild in parent.children:
                                if pchild.type == 'function_declarator' and child in pchild.children:
                                    is_function_def = True
                                    break
                            break
                        parent = parent.parent
                    
                    if is_function_def:
                        continue
                    
                    # 提取类型信息
                    type_hint = extract_type_hint(node)
                    is_ptr = is_pointer_type(type_hint)
                    
                    # 识别角色
                    role = identify_variable_role(var_name, child, ast_root, type_hint)
                    
                    # 分配语义家族
                    family = assign_semantic_family(var_name)
                    
                    # 统计使用次数
                    usage_count = count_variable_usage(var_name, ast_root)
                    
                    # 计算作用域层级（简化版）
                    scope_level = 0
                    parent = node.parent
                    depth = 0
                    while parent is not None:
                        if parent.type in ['compound_statement', 'function_definition']:
                            depth += 1
                        parent = parent.parent
                    scope_level = depth
                    
                    # 创建或更新变量信息
                    if var_name not in variables:
                        variables[var_name] = VariableInfo(
                            name=var_name,
                            role=role,
                            family=family,
                            type_hint=type_hint,
                            scope_level=scope_level,
                            usage_count=usage_count,
                            is_pointer=is_ptr,
                            importance_score=0.0,
                            node=child
                        )
        
        for child in node.children:
            traverse(child)
    
    try:
        # 先收集函数调用
        collect_function_calls(ast_root)
        # 再提取变量
        traverse(ast_root)
    except Exception:
        pass
    
    return list(variables.values())

# ================== 重要性评分 ==================

def calculate_importance_score(var: VariableInfo) -> float:
    """计算变量重要性分数"""
    base_scores = {
        VariableRole.PARAMETER: 100.0,
        VariableRole.RESOURCE: 80.0,
        VariableRole.FIELD: 70.0,
        VariableRole.LOCAL: 50.0,
        VariableRole.LOOP_INDEX: 30.0,
    }
    
    base = base_scores.get(var.role, 50.0)
    
    # 使用频率加成 (log scale)
    usage_bonus = 10.0 * math.log(1 + var.usage_count)
    
    # 指针加成
    pointer_bonus = 5.0 if var.is_pointer else 0.0
    
    return base + usage_bonus + pointer_bonus

# ================== 配额选择 ==================

def select_variables_with_quota(
    variables: List[VariableInfo],
    max_ids: int
) -> List[VariableInfo]:
    """基于配额选择变量"""
    if not variables:
        return []
    
    # 1. 计算重要性分数
    for var in variables:
        var.importance_score = calculate_importance_score(var)
    
    # 2. 按重要性排序
    sorted_vars = sorted(variables, key=lambda v: v.importance_score, reverse=True)
    
    # 3. 贪心选择，满足配额
    selected = []
    role_counts = {role: 0 for role in VariableRole}
    
    for var in sorted_vars:
        role = var.role
        min_q, max_q = ROLE_QUOTAS[role]
        
        if role_counts[role] < max_q and len(selected) < max_ids:
            selected.append(var)
            role_counts[role] += 1
    
    # 4. 如果还没选满，继续按重要性选择（忽略配额）
    if len(selected) < max_ids:
        for var in sorted_vars:
            if var not in selected and len(selected) < max_ids:
                selected.append(var)
    
    return selected

# ================== 新名生成 ==================

def generate_new_name(
    old_name: str,
    family: SemanticFamily,
    existing: Set[str],
    seed: int
) -> Optional[str]:
    """在指定family内生成新名"""
    rnd = random.Random(seed)
    
    candidates = SEMANTIC_FAMILIES[family].copy()
    rnd.shuffle(candidates)
    
    # 优先选择与旧名不同的
    for cand in candidates:
        if cand.lower() != old_name.lower() and cand not in existing:
            return cand
    
    # 如果都不行，尝试添加后缀
    for base in candidates[:5]:  # 只尝试前5个
        for suffix in ['', '_val', '_var', '_tmp']:
            cand = base + suffix
            if cand not in existing:
                return cand
    
    # 最后兜底：使用varX
    i = 0
    while i < 1000:
        cand = f"var{i}"
        if cand not in existing:
            return cand
        i += 1
    
    return None

# ================== AST-based替换 ==================

def apply_ast_renaming(code: str, id_map: Dict[str, str]) -> str:
    """基于AST的精确替换（如果AST可用）"""
    # 由于tree-sitter的替换比较复杂，这里先使用词法替换
    # 后续可以改进为基于AST节点的精确替换
    return _apply_lexical_renaming(code, id_map)

def _apply_lexical_renaming(code: str, id_map: Dict[str, str]) -> str:
    """词法替换（降级方案）- 复用retrieval.py中的安全替换逻辑"""
    if not id_map:
        return code
    
    # 导入retrieval中的安全替换函数
    try:
        from retrieval import _apply_identifier_mapping
        return _apply_identifier_mapping(code, id_map)
    except ImportError:
        # 如果无法导入，使用简单的词法替换（不推荐，但作为兜底）
        # 使用正则表达式进行安全替换
        pattern = r'\b(' + '|'.join(re.escape(k) for k in id_map.keys()) + r')\b'
        
        def replacer(match):
            return id_map.get(match.group(1), match.group(1))
        
        return re.sub(pattern, replacer, code)

# ================== 主函数 ==================

def rename_identifiers_ast(
    code: str,
    max_ids: int = 2,
    seed: int = 42,
    enable_ast: bool = True
) -> str:
    """
    基于AST的变量重命名
    
    Args:
        code: C/C++代码
        max_ids: 最多改写的变量数
        seed: 随机种子
        enable_ast: 是否启用AST解析（失败时自动降级）
    
    Returns:
        改写后的代码
    """
    global LAST_RENAME_MODE, LAST_RENAME_ID_MAP

    if not code or not code.strip():
        LAST_RENAME_MODE = "noop"
        LAST_RENAME_ID_MAP = {}
        return code
    
    ast_used = False
    
    # 尝试AST解析
    ast_root = None
    variables = []
    
    if enable_ast:
        ast_root = parse_c_code(code)
        if ast_root is not None:
            variables = extract_variables(ast_root)
            if variables:
                ast_used = True
    
    # 如果AST解析失败或没有变量，降级到词法分析
    if not variables:
        from retrieval import rename_identifiers_safe
        LAST_RENAME_MODE = "fallback"
        LAST_RENAME_ID_MAP = {}
        print("[fallback] lexical (no variables extracted)", flush=True)
        return rename_identifiers_safe(code, max_ids, seed, use_ast=False)
    
    # 打印AST解析到的变量信息（调试日志）
    if ast_used:
        print(f"[AST] extracted {len(variables)} variables:", flush=True)
        for var in variables[:10]:  # 只打印前10个
            print(f"  {var.name:12} role={var.role.value:12} family={var.family.value:10} "
                  f"usage={var.usage_count:2} ptr={var.is_pointer}", flush=True)
        if len(variables) > 10:
            print(f"  ... and {len(variables) - 10} more", flush=True)
    
    # 选择要改写的变量
    selected = select_variables_with_quota(variables, max_ids)
    if not selected:
        from retrieval import rename_identifiers_safe
        LAST_RENAME_MODE = "fallback"
        LAST_RENAME_ID_MAP = {}
        print("[fallback] lexical (no selectable vars)", flush=True)
        return rename_identifiers_safe(code, max_ids, seed, use_ast=False)
    
    # 打印选中的变量
    if ast_used:
        print(f"[AST] selected {len(selected)} variables for renaming:", flush=True)
        for var in selected:
            print(f"  {var.name:12} role={var.role.value:12} family={var.family.value:10}", flush=True)
    
    # 生成新名映射
    existing = {v.name for v in variables}
    id_map = {}
    
    for var in selected:
        new_name = generate_new_name(var.name, var.family, existing, seed + hash(var.name))
        if new_name:
            id_map[var.name] = new_name
            existing.add(new_name)
    
    if not id_map:
        from retrieval import rename_identifiers_safe
        LAST_RENAME_MODE = "fallback"
        LAST_RENAME_ID_MAP = {}
        print("[fallback] lexical (empty id_map)", flush=True)
        return rename_identifiers_safe(code, max_ids, seed, use_ast=False)
    
    if ast_used:
        LAST_RENAME_MODE = "ast"
        LAST_RENAME_ID_MAP = dict(id_map)
        print(f"[AST] used -> {id_map}", flush=True)
    else:
        LAST_RENAME_MODE = "fallback"
        LAST_RENAME_ID_MAP = {}
        print("[fallback] lexical (no ast root)", flush=True)
        from retrieval import rename_identifiers_safe
        return rename_identifiers_safe(code, max_ids, seed, use_ast=False)
    
    # 应用替换
    return apply_ast_renaming(code, id_map)





























































