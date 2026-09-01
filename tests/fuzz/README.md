# Parser fuzz harnesses

libFuzzer harnesses for the parsers that consume external input. Most target the
pure string→struct parsers that read what a component produced — `src/capture.c`
for the tagged wire records, `src/meta.c` for the metadata a component declares
about itself, `src/orchestrator.c` for the disposition line. Each consumes
attacker-influenced input (component stdout, ELF section payload, dmesg) in the
privileged orchestrator process, so a bug there is a real exposure surface.

`fuzz_btf` walks the binary BTF type info in
`src/components/btf_struct_page_size.c`: kernel-provided input rather than an
attacker surface, but the most intricate binary parser in the tree, so it is
fuzzed for over-read / overflow / unbounded-loop safety. `fuzz_render` picks up
where the parsers stop, building the report model from a script of constraints
the engine could actually have applied and reading every field a format draws
from.

| Harness | Target | Wire format |
|---|---|---|
| `fuzz_parse_hex` | `parse_hex(s, *out)` | `0x` + hex digits |
| `fuzz_capture_result` | `capture_result(line, method, origin)` | `<P\|V> <region>[:<name>] pos=<pos> conf=<conf> [lo=...] [hi=...\|sz=...] [sample=...] [base_align=...]` |
| `fuzz_capture_scalar` | `capture_scalar(line, origin)` | `S <fact> conf=<c> value=0x<hex>` |
| `fuzz_parse_meta` | `parse_meta(raw, *m)` | newline-delimited `key:value` pairs |
| `fuzz_parse_disposition` | `parse_disposition(s, *d)` | `cat=<category> [gate=<token>] [msg="<text>"]` (the `R`-line body) |
| `fuzz_btf` | `btf_struct_size(buf, len, name)` | BTF blob: header + type / string sections |
| `fuzz_render` | `kasld_report_build()` + every field a format reads | a script of constraints applied through `estimate_meet()` |

## Table of Contents

- [Build and run](#build-and-run)
- [Seed corpus](#seed-corpus)
- [What a finding looks like](#what-a-finding-looks-like)
- [Scope](#scope)
- [CI](#ci)

## Build and run

Optional `make fuzz` target — not in the default build graph. Requires
clang with libFuzzer (the bundled `-fsanitize=fuzzer` runtime):

```sh
make fuzz FUZZ_CC=clang
```

Each harness lands in `build/fuzz/`:

```sh
build/fuzz/fuzz_capture_result tests/fuzz/corpus/capture_result/ \
    -timeout=10 -max_len=4096
```

Standard libFuzzer flags apply (`-jobs=N`, `-workers=N`, `-runs=N`).
A new finding lands as a `crash-<hash>` file in the current directory.

## Seed corpus

Generated from the fixture tree by
[seed-from-fixtures.sh](seed-from-fixtures.sh):

```sh
tests/fuzz/seed-from-fixtures.sh
```

The script is idempotent — seed files are hash-named, so rerunning
does not duplicate. Run it after capturing new fixtures to widen the
seed set for `capture_result` (the only harness whose corpus benefits
from real-world examples; the others use constructed cover sets).

## What a finding looks like

A crash, hang, or sanitizer trip. libFuzzer writes:

```
==12345==ERROR: AddressSanitizer: heap-buffer-overflow ...
Test unit written to ./crash-deadbeef...
```

The `crash-<hash>` file holds the minimised input that triggered the
fault. Reproduce by feeding it back:

```sh
build/fuzz/fuzz_capture_result crash-deadbeef
```

## Scope

This is a parser audit, not a full-engine fuzz. The harnesses do not
drive the inference engine or the renderers — they exercise only the
input-acceptance boundary. The engine is exercised by
`make check` over synthetic constraint sets; the renderers are
exercised by `tests/replay` over captured trees.

## CI

Not wired into CI. The runtime budget (corpus-guided fuzz wants hours,
not seconds) makes it a local / on-demand harness. The `make fuzz`
target only builds the binaries; running them is up to the operator.
