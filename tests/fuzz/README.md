#Parser fuzz harnesses

libFuzzer harnesses for the four pure string→struct parsers in
`src/orchestrator.c`. Each parser consumes attacker-influenced input
(component stdout, ELF section payload, dmesg) and runs in the
privileged orchestrator process, so a parser bug is a real exposure
surface.

| Harness | Target | Wire format |
|---|---|---|
| `fuzz_parse_hex` | `parse_hex(s, *out)` | `0x` + hex digits |
| `fuzz_capture_result` | `capture_result(line, method, origin)` | `<P|V> <region>[:<name>] pos=<pos> conf=<conf> [lo=...] [hi=...|sz=...] [sample=...] [base_align=...]` |
| `fuzz_capture_scalar` | `capture_scalar(line, origin)` | `S <fact> conf=<c> value=0x<hex>` |
| `fuzz_parse_meta` | `parse_meta(raw, *m)` | newline-delimited `key:value` pairs |

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
`make check` over synthetic constraint sets;
the renderers are exercised by `tests /
        replay` over captured trees
            .

        ##CI

            Not wired into CI.The runtime
            budget(corpus - guided fuzz wants hours,
                   not seconds) makes it a local
        / on
    - demand harness.The `make fuzz` target only builds the binaries;
running them is up to the operator.
