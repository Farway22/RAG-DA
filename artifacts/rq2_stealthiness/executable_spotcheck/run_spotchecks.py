"""Generate, compile, and compare clean/adversarial C/C++ spot checks.

The transformation snippets are read verbatim from the frozen review subset.
Only the shared includes, minimal dependency stubs, and identical test driver are
added around each snippet.  Clean and adversarial variants are compiled into
separate executables and run with the same inputs.
"""

from __future__ import annotations

import json
import argparse
import os
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SUBSET = ROOT.parent / "validation_subset_review" / "validation_subset_candidates.jsonl"
SOURCES = ROOT / "sources"
BUILD = ROOT / "build"
RESULTS_JSON = ROOT / "spotcheck_results.json"
RESULTS_MD = ROOT / "spotcheck_results.md"


CASES = {
    (366, 7): {
        "name": "intset_resize",
        "prefix": r'''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    uint32_t encoding;
    unsigned char contents[];
} intset;

static uint32_t intrev32ifbe(uint32_t value) { return value; }
static void *zrealloc(void *ptr, size_t size) { return realloc(ptr, size); }

''',
        "suffix": r'''

int main(void) {
    const uint32_t lengths[] = {0, 1, 8, 31};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        intset *set = (intset *)malloc(sizeof(intset));
        if (!set) return 2;
        set->encoding = 4;
        set = intsetResize(set, lengths[i]);
        if (!set) return 3;
        unsigned long checksum = 0;
        for (uint32_t j = 0; j < lengths[i] * set->encoding; ++j) {
            set->contents[j] = (unsigned char)(j + i);
            checksum += set->contents[j];
        }
        printf("%u:%u:%lu\n", lengths[i], set->encoding, checksum);
        free(set);
    }
    return 0;
}
''',
    },
    (330, 23): {
        "name": "read_u32",
        "prefix": """#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\n\n""",
        "suffix": r'''

int main(void) {
    const uint8_t a[] = {0x00, 0x00, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78};
    const uint8_t b[] = {0xff, 0xee, 0xdd, 0xcc, 0xbb};
    printf("%u\n", (unsigned)readU32(a, 0));
    printf("%u\n", (unsigned)readU32(a, 4));
    printf("%u\n", (unsigned)readU32(b, 1));
    return 0;
}
''',
    },
    (525, 21): {
        "name": "xmalloc",
        "prefix": """#include <stdio.h>\n#include <stdlib.h>\n#include <stddef.h>\n\n""",
        "suffix": r'''

int main(void) {
    const size_t sizes[] = {1, 16, 257};
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
        unsigned char *p = (unsigned char *)xmalloc(sizes[i]);
        unsigned long checksum = 0;
        for (size_t j = 0; j < sizes[i]; ++j) {
            p[j] = (unsigned char)((j * 17u + i) & 0xffu);
            checksum += p[j];
        }
        printf("%zu:%lu\n", sizes[i], checksum);
        free(p);
    }
    return 0;
}
''',
    },
    (79, 22): {
        "name": "could_recur",
        "language": "cpp",
        "prefix": r'''#include <iostream>

class Variant {
public:
    explicit Variant(bool referenced) : referenced_(referenced) {}
    bool isReferenced() const { return referenced_; }
private:
    bool referenced_;
};

class ArrayData {
public:
    enum Kind { kNormalKind, kGlobalsKind, kProxyKind };
    explicit ArrayData(Kind kind) : kind_(kind) {}
    Kind kind() const { return kind_; }
private:
    Kind kind_;
};

class Array {
public:
    explicit Array(const ArrayData *data) : data_(data) {}
    const ArrayData *get() const { return data_; }
private:
    const ArrayData *data_;
};

''',
        "suffix": r'''

int main() {
    const ArrayData normal(ArrayData::kNormalKind);
    const ArrayData globals(ArrayData::kGlobalsKind);
    const ArrayData proxy(ArrayData::kProxyKind);
    std::cout << couldRecur(Variant(false), Array(&normal)) << '\n';
    std::cout << couldRecur(Variant(true), Array(&normal)) << '\n';
    std::cout << couldRecur(Variant(false), Array(&globals)) << '\n';
    std::cout << couldRecur(Variant(false), Array(&proxy)) << '\n';
    return 0;
}
''',
    },
    (1154, 29): {
        "name": "nlm_destroy",
        "prefix": r'''#include <stdio.h>
#include <stdlib.h>

typedef void *gpointer;
typedef struct {
    void *cookie;
} nlm_msg_res_unmatched_data;

static int free_calls = 0;
static void g_free(void *ptr) {
    ++free_calls;
    free(ptr);
}

''',
        "suffix": r'''

int main(void) {
    nlm_msg_res_unmatched_data *data =
        (nlm_msg_res_unmatched_data *)malloc(sizeof(*data));
    if (!data) return 2;
    data->cookie = malloc(8);
    if (!data->cookie) return 3;
    nlm_msg_res_unmatched_value_destroy(data);
    printf("free_calls=%d\n", free_calls);
    return 0;
}
''',
    },
    (926, 13): {
        "name": "read_uint32",
        "prefix": r'''#include <stdio.h>
#include <stdlib.h>

static unsigned long readUInt8(FILE *f) {
    int c = fgetc(f);
    return c == EOF ? 0u : (unsigned long)(unsigned char)c;
}

''',
        "suffix": r'''

int main(void) {
    const unsigned char inputs[][4] = {
        {0x01, 0x00, 0x00, 0x00},
        {0x78, 0x56, 0x34, 0x12},
        {0xff, 0xee, 0xdd, 0xcc}
    };
    for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); ++i) {
        FILE *f = tmpfile();
        if (!f) return 2;
        if (fwrite(inputs[i], 1, 4, f) != 4) return 3;
        rewind(f);
        printf("%lu\n", readUInt32(f));
        fclose(f);
    }
    return 0;
}
''',
    },
    (107, 9): {
        "name": "sk_auto_stmalloc",
        "language": "cpp",
        "prefix": r'''#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <new>

enum { SK_MALLOC_THROW = 1, SK_MALLOC_TEMP = 2 };
static void *sk_malloc_flags(size_t size, int) {
    void *ptr = std::malloc(size);
    if (!ptr) throw std::bad_alloc();
    return ptr;
}

template <typename T, size_t kCount>
class SkAutoSTMalloc {
    alignas(T) unsigned char storage_[sizeof(T) * kCount];
    T *fTStorage = reinterpret_cast<T *>(storage_);
    T *fPtr = nullptr;
public:
''',
        "suffix": r'''

    ~SkAutoSTMalloc() {
        if (fPtr && fPtr != fTStorage) std::free(fPtr);
    }
    bool has_data() const { return fPtr != nullptr; }
    bool uses_inline_storage() const { return fPtr == fTStorage; }
};

int main() {
    SkAutoSTMalloc<int, 4> zero(0);
    SkAutoSTMalloc<int, 4> small(3);
    SkAutoSTMalloc<int, 4> large(9);
    std::cout << zero.has_data() << ':' << zero.uses_inline_storage() << '\n';
    std::cout << small.has_data() << ':' << small.uses_inline_storage() << '\n';
    std::cout << large.has_data() << ':' << large.uses_inline_storage() << '\n';
    return 0;
}
''',
    },
    (1051, 0): {
        "name": "option_persist",
        "prefix": r'''#include <stdio.h>
#include <string.h>

typedef int gboolean;
typedef char gchar;
typedef void *gpointer;
typedef struct { int unused; } GError;
typedef struct { char persistent[64]; } FlatpakContext;
#define TRUE 1

static void flatpak_context_set_persistent(FlatpakContext *context, const char *value) {
    snprintf(context->persistent, sizeof(context->persistent), "%s", value);
}

''',
        "suffix": r'''

int main(void) {
    FlatpakContext context = {{0}};
    GError *error = NULL;
    int rc = option_persist_cb("persist", "cache-dir", &context, &error);
    printf("%d:%s:%d\n", rc, context.persistent, error == NULL);
    return 0;
}
''',
    },
    (164, 13): {
        "name": "jas_stream_read",
        "prefix": r'''#include <stdio.h>
#include <stddef.h>

typedef struct {
    const unsigned char *data;
    size_t size;
    size_t pos;
} jas_stream_t;

static int jas_stream_getc(jas_stream_t *stream) {
    if (stream->pos >= stream->size) return EOF;
    return stream->data[stream->pos++];
}

''',
        "suffix": r'''

static void print_bytes(const unsigned char *buf, int n) {
    printf("%d:", n);
    for (int i = 0; i < n; ++i) printf("%02x", (unsigned)buf[i]);
    putchar('\n');
}

int main(void) {
    const unsigned char data[] = {0x10, 0x20, 0x30, 0x40, 0x50};
    jas_stream_t stream = {data, sizeof(data), 0};
    unsigned char first[3] = {0};
    unsigned char second[5] = {0};
    int n1 = jas_stream_read(&stream, first, 3);
    int n2 = jas_stream_read(&stream, second, 5);
    print_bytes(first, n1);
    print_bytes(second, n2);
    return 0;
}
''',
    },
    (405, 15): {
        "name": "assignment_map",
        "prefix": r'''#include <stdio.h>

typedef int gint;
typedef struct { int unused; } tvbuff_t;
typedef struct { int unused; } packet_info;
typedef struct { int unused; } proto_tree;
typedef struct { int unused; } wccp_address_table;
static int noted_length = -1;
#define NOTE_EATEN_LENGTH(value) do { noted_length = (value); } while (0)

static int dissect_wccp2_mask_value_set_list(
    tvbuff_t *tvb, int offset, int length, packet_info *pinfo,
    proto_tree *tree, wccp_address_table *table) {
    (void)tvb; (void)pinfo; (void)tree; (void)table;
    return offset + length;
}

''',
        "suffix": r'''

int main(void) {
    tvbuff_t tvb = {0}; packet_info pinfo = {0};
    proto_tree tree = {0}; wccp_address_table table = {0};
    const int lengths[] = {0, 7, 31};
    for (int i = 0; i < 3; ++i) {
        int result = dissect_wccp2_assignment_map(
            &tvb, 5, lengths[i], &pinfo, &tree, &table);
        printf("%d:%d\n", result, noted_length);
    }
    return 0;
}
''',
    },
    (888, 26): {
        "name": "ssl_status",
        "prefix": r'''#include <stdio.h>

typedef int pj_status_t;
typedef struct { unsigned long last_err; } pj_ssl_sock_t;
#define SSL_ERROR_SSL 1ul
#define ERROR_LOG(action, err, ssock) ((void)(action), (void)(err), (void)(ssock))
#define GET_STATUS_FROM_SSL_ERR(err) ((pj_status_t)((err) + 1000ul))
static unsigned long ERR_get_error(void) { return 42ul; }

''',
        "suffix": r'''

int main(void) {
    const unsigned long errors[] = {SSL_ERROR_SSL, 7ul, 99ul};
    for (int i = 0; i < 3; ++i) {
        pj_ssl_sock_t socket = {0};
        pj_status_t status = STATUS_FROM_SSL_ERR("test", &socket, errors[i]);
        printf("%d:%lu\n", status, socket.last_err);
    }
    return 0;
}
''',
    },
    (124, 6): {
        "name": "snmp_exceptions",
        "prefix": r'''#include <stdio.h>

#define TSRMLS_DC
#define SUCCESS 0
#define IS_LONG 1
typedef struct { int type; long lval; } zval;
typedef struct { long exceptions_enabled; } php_snmp_object;
#define Z_TYPE_P(value) ((value)->type)
#define Z_LVAL_P(value) ((value)->lval)
static void zval_copy_ctor(zval *value) { (void)value; }
static void convert_to_long(zval *value) { value->type = IS_LONG; }
static void zval_dtor(zval *value) { (void)value; }

''',
        "suffix": r'''

int main(void) {
    php_snmp_object object = {0};
    zval direct = {IS_LONG, 5};
    zval converted = {0, 9};
    int first = php_snmp_write_exceptions_enabled(&object, &direct);
    printf("%d:%ld\n", first, object.exceptions_enabled);
    int second = php_snmp_write_exceptions_enabled(&object, &converted);
    printf("%d:%ld\n", second, object.exceptions_enabled);
    return 0;
}
''',
    },
    (33, 19): {
        "name": "unzigzag32",
        "prefix": """#include <stdint.h>\n#include <stdio.h>\n\n""",
        "suffix": r'''

int main(void) {
    const uint32_t values[] = {0u, 1u, 2u, 3u, 0xfffffffeu, 0xffffffffu};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i)
        printf("%d\n", unzigzag32(values[i]));
    return 0;
}
''',
    },
    (888, 13): {
        "name": "h2o_on_read",
        "prefix": r'''#include <stdio.h>

typedef struct h2o_socket_t { void *data; } h2o_socket_t;
typedef struct { int timeout_entry; } write_state_t;
typedef struct h2o_http2_conn_t {
    h2o_socket_t *sock;
    write_state_t _write;
} h2o_http2_conn_t;

static int stopped, closed, updated, parsed, unlinked, emitted;
static void h2o_socket_read_stop(h2o_socket_t *sock) { (void)sock; ++stopped; }
static void close_connection(h2o_http2_conn_t *conn) { (void)conn; ++closed; }
static void update_idle_timeout(h2o_http2_conn_t *conn) { (void)conn; ++updated; }
static void parse_input(h2o_http2_conn_t *conn) { (void)conn; ++parsed; }
static int h2o_timeout_is_linked(int *entry) { return *entry != 0; }
static void h2o_timeout_unlink(int *entry) { *entry = 0; ++unlinked; }
static void do_emit_writereq(h2o_http2_conn_t *conn) { (void)conn; ++emitted; }

''',
        "suffix": r'''

static void run_case(int status) {
    h2o_socket_t socket = {0};
    h2o_http2_conn_t conn = {&socket, {1}};
    socket.data = &conn;
    stopped = closed = updated = parsed = unlinked = emitted = 0;
    on_read(&socket, status);
    printf("%d%d%d%d%d%d\n", stopped, closed, updated, parsed, unlinked, emitted);
}

int main(void) {
    run_case(0);
    run_case(1);
    return 0;
}
''',
    },
    (172, 19): {
        "name": "svg_load_page",
        "prefix": r'''#include <stdio.h>
#include <stdlib.h>

typedef struct { int unused; } fz_context;
typedef struct { int unused; } fz_document;
typedef struct { int marker; } svg_document;
typedef struct fz_page {
    void (*bound_page)(void);
    void (*run_page_contents)(void);
    void (*drop_page)(void);
} fz_page;
typedef struct svg_page {
    fz_page super;
    svg_document *doc;
} svg_page;
static void svg_bound_page(void) {}
static void svg_run_page(void) {}
static void svg_drop_page(void) {}
#define fz_new_derived_page(ctx, type) ((void)(ctx), (type *)calloc(1, sizeof(type)))

''',
        "suffix": r'''

int main(void) {
    fz_context context = {0};
    svg_document document = {77};
    fz_page *first = svg_load_page(&context, (fz_document *)&document, 0);
    fz_page *second = svg_load_page(&context, (fz_document *)&document, 1);
    svg_page *page = (svg_page *)first;
    printf("%d:%d:%d\n", first != NULL, second == NULL, page && page->doc == &document);
    free(first);
    return 0;
}
''',
    },
    (401, 19): {
        "name": "count_extensions",
        "prefix": r'''#include <stdio.h>
#include <string.h>

typedef struct {
    const char *name;
    unsigned int nlines;
    char **lines;
} XpmExtension;

''',
        "suffix": r'''

static void run_case(unsigned int count) {
    char *first_lines[] = {"alpha", "beta"};
    char *second_lines[] = {"gamma"};
    XpmExtension extensions[] = {
        {"first", 2, first_lines},
        {"second", 1, second_lines}
    };
    unsigned int size = 0, lines = 0;
    CountExtensions(extensions, count, &size, &lines);
    printf("%u:%u:%u\n", count, size, lines);
}

int main(void) {
    run_case(0);
    run_case(1);
    run_case(2);
    return 0;
}
''',
    },
}


def load_subset(subset_path: Path) -> dict[tuple[int, int], dict]:
    records: dict[tuple[int, int], dict] = {}
    with subset_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            item = json.loads(line)
            records[(int(item["sample_id"]), int(item["demo_index"]))] = item
    return records


def generate_sources(subset_path: Path, sources_dir: Path) -> list[dict]:
    records = load_subset(subset_path)
    sources_dir.mkdir(parents=True, exist_ok=True)
    generated_cases = []
    for key, spec in CASES.items():
        if key not in records:
            continue
        item = records[key]
        paths = {}
        extension = ".cpp" if spec.get("language", "c") == "cpp" else ".c"
        for variant, field in (("clean", "clean_code"), ("adversarial", "adversarial_code")):
            path = sources_dir / f"{spec['name']}_{variant}{extension}"
            path.write_text(
                spec["prefix"] + item[field].strip() + spec["suffix"],
                encoding="utf-8",
            )
            paths[variant] = path
        generated_cases.append({"key": key, "spec": spec, "item": item, "paths": paths})
    generated_keys = {case["key"] for case in generated_cases}
    missing_harnesses = set(records) - generated_keys
    if missing_harnesses:
        raise RuntimeError(f"No executable harness for subset pairs: {sorted(missing_harnesses)}")
    return generated_cases


def find_msvc() -> tuple[Path, Path] | None:
    program_files = os.environ.get("ProgramFiles(x86)") or os.environ.get("ProgramFiles")
    if not program_files:
        return None
    vswhere = Path(program_files) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if not vswhere.exists():
        return None
    query = subprocess.run(
        [
            str(vswhere), "-latest", "-products", "*",
            "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property", "installationPath",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    installation = Path(query.stdout.strip())
    vcvars = installation / "VC" / "Auxiliary" / "Build" / "vcvars64.bat"
    versions = sorted((installation / "VC" / "Tools" / "MSVC").glob("*"), reverse=True)
    if not vcvars.exists() or not versions:
        return None
    compiler = versions[0] / "bin" / "Hostx64" / "x64" / "cl.exe"
    return (vcvars, compiler) if compiler.exists() else None


def msvc_environment(vcvars: Path, build_dir: Path) -> dict[str, str]:
    build_dir.mkdir(parents=True, exist_ok=True)
    setup_batch = build_dir / "capture_msvc_environment.bat"
    setup_batch.write_text(
        f'@call "{vcvars}" >nul\n@set\n',
        encoding="ascii",
    )
    result = subprocess.run(
        ["cmd.exe", "/d", "/c", str(setup_batch)],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    env = os.environ.copy()
    for line in result.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            env[key] = value
    return env


def compile_source(
    source: Path,
    executable: Path,
    compiler: Path,
    env: dict[str, str],
    language: str,
) -> dict:
    language_flags = ["/TP", "/std:c++17", "/EHsc"] if language == "cpp" else ["/TC", "/std:c11"]
    command = [
        str(compiler), "/nologo", *language_flags, "/W4", "/WX-",
        str(source), f"/Fe:{executable}", f"/Fo:{executable.with_suffix('.obj')}",
    ]
    result = subprocess.run(command, env=env, capture_output=True, text=True)
    return {
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def run_executable(path: Path) -> dict:
    result = subprocess.run([str(path)], capture_output=True, text=True, timeout=10)
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def compiler_version(compiler: Path, env: dict[str, str]) -> str:
    result = subprocess.run([str(compiler)], env=env, capture_output=True, text=True)
    combined = result.stdout + "\n" + result.stderr
    match = re.search(r"\b(\d+\.\d+\.\d+(?:\.\d+)?)\b", combined)
    return match.group(1) if match else "unknown"


def diagnostic_codes(compilation: dict) -> list[str]:
    text = compilation["stdout"] + "\n" + compilation["stderr"]
    return sorted(set(re.findall(r"\b(?:warning|error) C\d+\b", text, flags=re.IGNORECASE)))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subset", type=Path, default=SUBSET)
    parser.add_argument("--sources-dir", type=Path, default=SOURCES)
    parser.add_argument("--build-dir", type=Path, default=BUILD)
    parser.add_argument("--results-json", type=Path, default=RESULTS_JSON)
    parser.add_argument("--results-md", type=Path, default=RESULTS_MD)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    subset_path = args.subset.resolve()
    sources_dir = args.sources_dir.resolve()
    build_dir = args.build_dir.resolve()
    results_json = args.results_json.resolve()
    results_md = args.results_md.resolve()
    results_json.parent.mkdir(parents=True, exist_ok=True)
    results_md.parent.mkdir(parents=True, exist_ok=True)

    generated_cases = generate_sources(subset_path, sources_dir)
    msvc = find_msvc()
    if msvc is None:
        raise RuntimeError("Visual Studio C compiler was not found")
    vcvars, compiler = msvc
    env = msvc_environment(vcvars, build_dir)

    results = []
    for case in generated_cases:
        variant_results = {}
        language = case["spec"].get("language", "c")
        for variant, source in case["paths"].items():
            executable = build_dir / f"{case['spec']['name']}_{variant}.exe"
            compilation = compile_source(source, executable, compiler, env, language)
            execution = run_executable(executable) if compilation["returncode"] == 0 else None
            variant_results[variant] = {"compilation": compilation, "execution": execution}

        clean = variant_results["clean"]
        adversarial = variant_results["adversarial"]
        both_compile = (
            clean["compilation"]["returncode"] == 0
            and adversarial["compilation"]["returncode"] == 0
        )
        outputs_equal = bool(
            both_compile
            and clean["execution"]["returncode"] == adversarial["execution"]["returncode"]
            and clean["execution"]["stdout"] == adversarial["execution"]["stdout"]
            and clean["execution"]["stderr"] == adversarial["execution"]["stderr"]
        )
        clean_codes = diagnostic_codes(clean["compilation"])
        adversarial_codes = diagnostic_codes(adversarial["compilation"])
        results.append(
            {
                "name": case["spec"]["name"],
                "sample_id": case["key"][0],
                "demo_index": case["key"][1],
                "mapping": f"{case['item']['old_identifier']} -> {case['item']['new_identifier']}",
                "language": language,
                "clean_compiled": clean["compilation"]["returncode"] == 0,
                "adversarial_compiled": adversarial["compilation"]["returncode"] == 0,
                "outputs_equal": outputs_equal,
                "clean_output": clean["execution"]["stdout"] if clean["execution"] else "",
                "diagnostic_codes": clean_codes,
                "diagnostics_equal": clean_codes == adversarial_codes,
            }
        )

    summary = {
        "compiler_family": "Microsoft Visual C/C++",
        "compiler_version": compiler_version(compiler, env),
        "cases": results,
        "all_clean_compiled": all(item["clean_compiled"] for item in results),
        "all_adversarial_compiled": all(item["adversarial_compiled"] for item in results),
        "all_outputs_equal": all(item["outputs_equal"] for item in results),
        "all_diagnostics_equal": all(item["diagnostics_equal"] for item in results),
    }
    results_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        "# Executable Paired-Transformation Spot Check",
        "",
        "Clean and adversarial snippets were compiled as separate C/C++ executables. "
        "Each pair used identical dependency stubs and identical test inputs.",
        "",
        f"Compiler: `Microsoft Visual C/C++ {summary['compiler_version']}`",
        "",
        "| Case | Source pair | Mapping | Clean compile | Adv compile | Identical execution |",
        "|---|---|---|---|---|---|",
    ]
    for item in results:
        lines.append(
            f"| {item['name']} | `{item['sample_id']}/{item['demo_index']}` | "
            f"`{item['mapping']}` | {'pass' if item['clean_compiled'] else 'fail'} | "
            f"{'pass' if item['adversarial_compiled'] else 'fail'} | "
            f"{'pass' if item['outputs_equal'] else 'fail'} |"
        )
    lines.extend(
        [
            "",
            f"The evidence scope is these {len(results)} selected, self-contained or "
            "minimally stubbed transformations; project-level validation uses the "
            "corresponding upstream projects and full experiment artifacts.",
            "",
            "Some original snippets emit compiler warnings under MSVC. Within every "
            "evaluated pair, clean and adversarial variants emit the same diagnostic "
            "categories; identifier renaming introduces no additional category.",
            "",
        ]
    )
    results_md.write_text("\n".join(lines), encoding="utf-8")

    print(json.dumps({key: summary[key] for key in (
        "all_clean_compiled", "all_adversarial_compiled", "all_outputs_equal"
    )}, indent=2))
    for item in results:
        print(
            f"{item['name']}: clean={item['clean_compiled']} "
            f"adv={item['adversarial_compiled']} equal={item['outputs_equal']}"
        )
    if not (
        summary["all_clean_compiled"]
        and summary["all_adversarial_compiled"]
        and summary["all_outputs_equal"]
        and summary["all_diagnostics_equal"]
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
