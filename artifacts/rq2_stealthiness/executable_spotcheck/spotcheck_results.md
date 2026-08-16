# Executable Paired-Transformation Spot Check

Clean and adversarial snippets were compiled as separate C/C++ executables. Each pair used identical dependency stubs and identical test inputs.

Compiler: `Microsoft Visual C/C++ 19.44.35219`

| Case | Source pair | Mapping | Clean compile | Adv compile | Identical execution |
|---|---|---|---|---|---|
| intset_resize | `366/7` | `len -> length` | pass | pass | pass |
| read_u32 | `330/23` | `offset -> cursor` | pass | pass | pass |
| xmalloc | `525/21` | `size -> length` | pass | pass | pass |
| could_recur | `79/22` | `arr -> vec` | pass | pass | pass |
| nlm_destroy | `1154/29` | `value -> var` | pass | pass | pass |
| read_uint32 | `926/13` | `result -> res` | pass | pass | pass |
| sk_auto_stmalloc | `107/9` | `count -> counter` | pass | pass | pass |
| option_persist | `1051/0` | `data -> memory` | pass | pass | pass |
| jas_stream_read | `164/13` | `cnt -> total` | pass | pass | pass |
| assignment_map | `405/15` | `length -> size` | pass | pass | pass |
| ssl_status | `888/26` | `err -> error` | pass | pass | pass |
| snmp_exceptions | `124/6` | `ret -> res` | pass | pass | pass |
| h2o_on_read | `888/13` | `status -> flag` | pass | pass | pass |
| svg_load_page | `172/19` | `number -> counter` | pass | pass | pass |
| count_extensions | `401/19` | `num -> total` | pass | pass | pass |

This is an executable spot check on 15 selected, self-contained or minimally stubbed transformations. It does not establish project-level compilability or behavioral equivalence for the full dataset.

Some original snippets emit compiler warnings under MSVC. Within every evaluated pair, clean and adversarial variants emit the same diagnostic categories; identifier renaming introduces no additional category.
