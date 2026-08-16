# High-Confidence Paired Transformation Subset

This is a 15-pair high-confidence candidate subset extracted from the existing full `full1208_ast_demos.jsonl` artifact. These pairs are the inputs to the companion executable spot-check suite.

This historical subset is independent of the paper-facing candidate generator. It tests compilation and observed behavior of concrete token-consistent substitutions; it is not a golden-output or reachability test for the core-preserving templates in `src/rag_da.py`.

Automated exclusions cover type/class/function/member renaming, multiple simultaneous mappings, destination-name collisions, unbalanced delimiters, and transformations without a detected parameter/local declaration. Each retained pair received a preliminary visual check for consistent uses.

The stored family labels record the historical screening run and are not presented as output from the current canonical generator. The subset uses each source identifier at most once, avoiding duplicate-name/different-target ambiguity. Identifier cue changes are lexical; they are not, by themselves, evidence of changed runtime behavior.

Current candidate-generation conformance is tested separately in `tests/test_rag_da_algorithm.py` and `../canonical_generator_review/`, whose examples are regenerated through the canonical Snake/Camel and AST-context path.

A final reviewer-facing alias constraint keeps only immediately interpretable mappings such as `result/res/ret`, `size/length/len`, and `idx/index`; broad-family edge cases such as `error/success` are excluded from this illustrative release subset.

| ID | Source | Mapping | Historical family screen | Uses | Clean chars | Status |
|---:|---|---|---|---:|---:|---|
| 1 | `366/7` | `len -> length` | counter -> counter | 2 | 155 | included in executable validation |
| 2 | `330/23` | `offset -> cursor` | index -> index | 5 | 158 | included in executable validation |
| 3 | `525/21` | `size -> length` | counter -> counter | 3 | 165 | included in executable validation |
| 4 | `79/22` | `arr -> vec` | buffer -> buffer | 3 | 181 | included in executable validation |
| 5 | `1154/29` | `value -> var` | generic -> generic | 2 | 182 | included in executable validation |
| 6 | `926/13` | `result -> res` | generic -> generic | 6 | 192 | included in executable validation |
| 7 | `107/9` | `count -> counter` | counter -> counter | 4 | 200 | included in executable validation |
| 8 | `1051/0` | `data -> memory` | buffer -> buffer | 2 | 217 | included in executable validation |
| 9 | `164/13` | `cnt -> total` | counter -> counter | 2 | 220 | included in executable validation |
| 10 | `405/15` | `length -> size` | counter -> counter | 3 | 318 | included in executable validation |
| 11 | `888/26` | `err -> error` | flag -> flag | 7 | 340 | included in executable validation |
| 12 | `124/6` | `ret -> res` | generic -> generic | 2 | 356 | included in executable validation |
| 13 | `888/13` | `status -> flag` | flag -> flag | 2 | 358 | included in executable validation |
| 14 | `172/19` | `number -> counter` | counter -> counter | 2 | 378 | included in executable validation |
| 15 | `401/19` | `num -> total` | counter -> counter | 2 | 426 | included in executable validation |

## 01. sample 366, demo 7 (`len -> length`)

Clean:

```cpp
static intset *intsetResize(intset *is, uint32_t len) { uint32_t size = len*intrev32ifbe(is->encoding); is = zrealloc(is,sizeof(intset)+size); return is; }
```

Adversarial:

```cpp
static intset *intsetResize(intset *is, uint32_t length) { uint32_t size = length*intrev32ifbe(is->encoding); is = zrealloc(is,sizeof(intset)+size); return is; }
```

## 02. sample 330, demo 23 (`offset -> cursor`)

Clean:

```cpp
static uint32_t readU32(const uint8_t* data, size_t offset) { return data[offset] << 24 | data[offset + 1] << 16 | data[offset + 2] << 8 | data[offset + 3]; }
```

Adversarial:

```cpp
static uint32_t readU32(const uint8_t* data, size_t cursor) { return data[cursor] << 24 | data[cursor + 1] << 16 | data[cursor + 2] << 8 | data[cursor + 3]; }
```

## 03. sample 525, demo 21 (`size -> length`)

Clean:

```cpp
void* xmalloc (size_t size) { void *ptr = malloc (size); if (!ptr  && (size != 0))          { perror ("xmalloc: Memory allocation failure"); abort(); } return ptr; }
```

Adversarial:

```cpp
void* xmalloc (size_t length) { void *ptr = malloc (length); if (!ptr  && (length != 0))          { perror ("xmalloc: Memory allocation failure"); abort(); } return ptr; }
```

## 04. sample 79, demo 22 (`arr -> vec`)

Clean:

```cpp
static bool couldRecur(const Variant& v, const Array& arr) { return v.isReferenced() || arr.get()->kind() == ArrayData::kGlobalsKind || arr.get()->kind() == ArrayData::kProxyKind; }
```

Adversarial:

```cpp
static bool couldRecur(const Variant& v, const Array& vec) { return v.isReferenced() || vec.get()->kind() == ArrayData::kGlobalsKind || vec.get()->kind() == ArrayData::kProxyKind; }
```

## 05. sample 1154, demo 29 (`value -> var`)

Clean:

```cpp
static void nlm_msg_res_unmatched_value_destroy(gpointer value) { nlm_msg_res_unmatched_data *umd = (nlm_msg_res_unmatched_data *)value; g_free((gpointer)umd->cookie); g_free(umd); }
```

Adversarial:

```cpp
static void nlm_msg_res_unmatched_value_destroy(gpointer var) { nlm_msg_res_unmatched_data *umd = (nlm_msg_res_unmatched_data *)var; g_free((gpointer)umd->cookie); g_free(umd); }
```

## 06. sample 926, demo 13 (`result -> res`)

Clean:

```cpp
unsigned long readUInt32(FILE *f) { unsigned long result = 0u; result |= readUInt8(f); result |= readUInt8(f) << 8; result |= readUInt8(f) << 16; result |= readUInt8(f) << 24; return result; }
```

Adversarial:

```cpp
unsigned long readUInt32(FILE *f) { unsigned long res = 0u; res |= readUInt8(f); res |= readUInt8(f) << 8; res |= readUInt8(f) << 16; res |= readUInt8(f) << 24; return res; }
```

## 07. sample 107, demo 9 (`count -> counter`)

Clean:

```cpp
SkAutoSTMalloc(size_t count) { if (count > kCount) { fPtr = (T*)sk_malloc_flags(count * sizeof(T), SK_MALLOC_THROW | SK_MALLOC_TEMP); } else if (count) { fPtr = fTStorage; } else { fPtr = nullptr; } }
```

Adversarial:

```cpp
SkAutoSTMalloc(size_t counter) { if (counter > kCount) { fPtr = (T*)sk_malloc_flags(counter * sizeof(T), SK_MALLOC_THROW | SK_MALLOC_TEMP); } else if (counter) { fPtr = fTStorage; } else { fPtr = nullptr; } }
```

## 08. sample 1051, demo 0 (`data -> memory`)

Clean:

```cpp
static gboolean option_persist_cb (const gchar *option_name, const gchar *value, gpointer     data, GError     **error) { FlatpakContext *context = data; flatpak_context_set_persistent (context, value); return TRUE; }
```

Adversarial:

```cpp
static gboolean option_persist_cb (const gchar *option_name, const gchar *value, gpointer     memory, GError     **error) { FlatpakContext *context = memory; flatpak_context_set_persistent (context, value); return TRUE; }
```

## 09. sample 164, demo 13 (`cnt -> total`)

Clean:

```cpp
int jas_stream_read(jas_stream_t *stream, void *buf, int cnt) { int n; int c; char *bufptr; bufptr = buf; n = 0; while (n < cnt) { if ((c = jas_stream_getc(stream)) == EOF) { return n; } *bufptr++ = c; ++n; } return n; }
```

Adversarial:

```cpp
int jas_stream_read(jas_stream_t *stream, void *buf, int total) { int n; int c; char *bufptr; bufptr = buf; n = 0; while (n < total) { if ((c = jas_stream_getc(stream)) == EOF) { return n; } *bufptr++ = c; ++n; } return n; }
```

## 10. sample 405, demo 15 (`length -> size`)

Clean:

```cpp
static gint dissect_wccp2_assignment_map(tvbuff_t *tvb, int offset, int length, packet_info *pinfo, proto_tree *info_tree, wccp_address_table* addr_table) { gint new_length; new_length=dissect_wccp2_mask_value_set_list(tvb, offset, length, pinfo, info_tree, addr_table); NOTE_EATEN_LENGTH(new_length); return length; }
```

Adversarial:

```cpp
static gint dissect_wccp2_assignment_map(tvbuff_t *tvb, int offset, int size, packet_info *pinfo, proto_tree *info_tree, wccp_address_table* addr_table) { gint new_length; new_length=dissect_wccp2_mask_value_set_list(tvb, offset, size, pinfo, info_tree, addr_table); NOTE_EATEN_LENGTH(new_length); return size; }
```

## 11. sample 888, demo 26 (`err -> error`)

Clean:

```cpp
static pj_status_t STATUS_FROM_SSL_ERR(char *action, pj_ssl_sock_t *ssock, unsigned long err) { int level = 0; int len = 0;  ERROR_LOG("STATUS_FROM_SSL_ERR", err, ssock); level++; if (err == SSL_ERROR_SSL) { err = ERR_get_error(); ERROR_LOG("STATUS_FROM_SSL_ERR", err, ssock); } ssock->last_err = err; return GET_STATUS_FROM_SSL_ERR(err); }
```

Adversarial:

```cpp
static pj_status_t STATUS_FROM_SSL_ERR(char *action, pj_ssl_sock_t *ssock, unsigned long error) { int level = 0; int len = 0;  ERROR_LOG("STATUS_FROM_SSL_ERR", error, ssock); level++; if (error == SSL_ERROR_SSL) { error = ERR_get_error(); ERROR_LOG("STATUS_FROM_SSL_ERR", error, ssock); } ssock->last_err = error; return GET_STATUS_FROM_SSL_ERR(error); }
```

## 12. sample 124, demo 6 (`ret -> res`)

Clean:

```cpp
static int php_snmp_write_exceptions_enabled(php_snmp_object *snmp_object, zval *newval TSRMLS_DC) { zval ztmp; int ret = SUCCESS; if (Z_TYPE_P(newval) != IS_LONG) { ztmp = *newval; zval_copy_ctor(&ztmp); convert_to_long(&ztmp); newval = &ztmp; } snmp_object->exceptions_enabled = Z_LVAL_P(newval); if (newval == &ztmp) { zval_dtor(newval); } return ret; }
```

Adversarial:

```cpp
static int php_snmp_write_exceptions_enabled(php_snmp_object *snmp_object, zval *newval TSRMLS_DC) { zval ztmp; int res = SUCCESS; if (Z_TYPE_P(newval) != IS_LONG) { ztmp = *newval; zval_copy_ctor(&ztmp); convert_to_long(&ztmp); newval = &ztmp; } snmp_object->exceptions_enabled = Z_LVAL_P(newval); if (newval == &ztmp) { zval_dtor(newval); } return res; }
```

## 13. sample 888, demo 13 (`status -> flag`)

Clean:

```cpp
static void on_read(h2o_socket_t *sock, int status) { h2o_http2_conn_t *conn = sock->data; if (status != 0) { h2o_socket_read_stop(conn->sock); close_connection(conn); return; } update_idle_timeout(conn); parse_input(conn); if (h2o_timeout_is_linked(&conn->_write.timeout_entry)) { h2o_timeout_unlink(&conn->_write.timeout_entry); do_emit_writereq(conn); } }
```

Adversarial:

```cpp
static void on_read(h2o_socket_t *sock, int flag) { h2o_http2_conn_t *conn = sock->data; if (flag != 0) { h2o_socket_read_stop(conn->sock); close_connection(conn); return; } update_idle_timeout(conn); parse_input(conn); if (h2o_timeout_is_linked(&conn->_write.timeout_entry)) { h2o_timeout_unlink(&conn->_write.timeout_entry); do_emit_writereq(conn); } }
```

## 14. sample 172, demo 19 (`number -> counter`)

Clean:

```cpp
static fz_page * svg_load_page(fz_context *ctx, fz_document *doc_, int number) { svg_document *doc = (svg_document*)doc_; svg_page *page; if (number != 0) return NULL; page = fz_new_derived_page(ctx, svg_page); page->super.bound_page = svg_bound_page; page->super.run_page_contents = svg_run_page; page->super.drop_page = svg_drop_page; page->doc = doc; return (fz_page*)page; }
```

Adversarial:

```cpp
static fz_page * svg_load_page(fz_context *ctx, fz_document *doc_, int counter) { svg_document *doc = (svg_document*)doc_; svg_page *page; if (counter != 0) return NULL; page = fz_new_derived_page(ctx, svg_page); page->super.bound_page = svg_bound_page; page->super.run_page_contents = svg_run_page; page->super.drop_page = svg_drop_page; page->doc = doc; return (fz_page*)page; }
```

## 15. sample 401, demo 19 (`num -> total`)

Clean:

```cpp
static void CountExtensions( XpmExtension*ext, unsigned int num, unsigned int*ext_size, unsigned int*ext_nlines) { unsigned int x, y, a, size, nlines; char **line; size = 0; nlines = 0; for (x = 0; x < num; x++, ext++) { nlines += ext->nlines + 1; size += strlen(ext->name) + 8; a = ext->nlines; for (y = 0, line = ext->lines; y < a; y++, line++) size += strlen(*line) + 1; } *ext_size = size + 10; *ext_nlines = nlines + 1; }
```

Adversarial:

```cpp
static void CountExtensions( XpmExtension*ext, unsigned int total, unsigned int*ext_size, unsigned int*ext_nlines) { unsigned int x, y, a, size, nlines; char **line; size = 0; nlines = 0; for (x = 0; x < total; x++, ext++) { nlines += ext->nlines + 1; size += strlen(ext->name) + 8; a = ext->nlines; for (y = 0, line = ext->lines; y < a; y++, line++) size += strlen(*line) + 1; } *ext_size = size + 10; *ext_nlines = nlines + 1; }
```
