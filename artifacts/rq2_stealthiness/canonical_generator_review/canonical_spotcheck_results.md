# Executable Paired-Transformation Spot Check

Clean and adversarial snippets were compiled as separate C/C++ executables. Each pair used identical dependency stubs and identical test inputs.

Compiler: `Microsoft Visual C/C++ 19.44.35219`

| Case | Source pair | Mapping | Clean compile | Adv compile | Identical execution |
|---|---|---|---|---|---|
| intset_resize | `366/7` | `is -> is_status` | pass | pass | pass |
| read_u32 | `330/23` | `data -> data_payload` | pass | pass | pass |
| xmalloc | `525/21` | `size -> size_limit` | pass | pass | pass |
| could_recur | `79/22` | `arr -> arr_ptr` | pass | pass | pass |
| nlm_destroy | `1154/29` | `value -> src_value` | pass | pass | pass |
| read_uint32 | `926/13` | `f -> src_f` | pass | pass | pass |
| sk_auto_stmalloc | `107/9` | `count -> max_count` | pass | pass | pass |
| option_persist | `1051/0` | `value -> value_data` | pass | pass | pass |
| jas_stream_read | `164/13` | `stream -> valid_stream` | pass | pass | pass |
| assignment_map | `405/15` | `length -> length_count` | pass | pass | pass |
| ssl_status | `888/26` | `err -> valid_err` | pass | pass | pass |
| unzigzag32 | `33/19` | `v -> v_payload` | pass | pass | pass |
| h2o_on_read | `888/13` | `sock -> raw_sock_data` | pass | pass | pass |
| svg_load_page | `172/19` | `ctx -> input_ctx` | pass | pass | pass |
| count_extensions | `401/19` | `ext -> ext_idx` | pass | pass | pass |

The evidence scope is these 15 selected, self-contained or minimally stubbed transformations; project-level validation uses the corresponding upstream projects and full experiment artifacts.

Some original snippets emit compiler warnings under MSVC. Within every evaluated pair, clean and adversarial variants emit the same diagnostic categories; identifier renaming introduces no additional category.
