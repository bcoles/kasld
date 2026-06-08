# Testing

KASLD has six test layers, in increasing order of setup cost:

1. **Host unit + integration tests** — pure C over synthetic evidence. No deps
   beyond a C compiler. This is the primary safety net.
2. **End-to-end replay** — runs the real `kasld` binary over captured filesystem
   trees. Native (no qemu) for the host arch; qemu-user for foreign arches.
3. **Cross-arch engine tests** — the unit tests run on each architecture under
   qemu-user, so arch-gated rule bodies execute their real path.
4. **Coverage reports** — optional, gcov-based.
5. **Bundle soundness check** (`extra/validate-bundle`) — runs the arch-correct
   `kasld` over a captured bundle's sysroot and asserts every engine-resolved
   range contains the ground truth read from the bundle's own kallsyms /
   `/proc/iomem`.
6. **Parser fuzz harnesses** (`tests/fuzz/`) — libFuzzer harnesses for the four
   pure string→struct parsers in `src/orchestrator.c`. Opt-in (`make fuzz`),
   not part of CI.

Quick start (everything that needs no cross toolchain or qemu):

```sh
make check          # build + run the full host unit/integration suite
KASLD_NATIVE=1 tests/replay tests/fixtures/x86_64/* tests/fixtures/x86_32/*
```

---

## 1. Host unit + integration tests

```sh
make check          # runs `make test` then prints "OK: host test suite passed."
make test           # build + run all five drivers
```

Each driver is a standalone binary in `build/tests/`. Test binaries (this
layer) and fuzz harnesses (layer 6 below) live in `build/tests/` and
`build/fuzz/` respectively — both are siblings of the per-arch deploy tree
`build/<arch>/`, so neither is reachable by `make install` (which copies
only the orchestrator binary and the `components/` subdirectory).

| Driver | Covers | Links |
|--------|--------|-------|
| `test_estimate` | lattice meet, bottom test, the greedy priority resolver | `estimate.c` + `quantities.c` |
| `test_evidence` | observation store + verdict application | `evidence.c` |
| `test_engine` | every rule in `src/rules/` over synthetic evidence | engine core + all rules |
| `test_engine_integration` | the full production rule registry against leak-bearing evidence | engine core + `engine_rules.c` + all rules |
| `test_kasld` | orchestrator internals (parse, merge, anchor select), the engine→layout projection, region_info, renderers | `orchestrator.c` / `render.c` / `region_info.c` under `-DKASLD_TESTING` |

Run one driver in isolation:

```sh
make test-estimate
make test-evidence
make test-engine
make test-integration
```

`test_kasld` is built with `-DKASLD_TESTING`, which compiles out `main()`, the
`engine_build_evidence` bridge, and the live engine run. Those — the real
collect → bridge → resolve → render path — are exercised only by replay (layer 2).

Compiler / flags: `make test CC=clang`, `CFLAGS=...` as usual. pthread is used
when available (`HAVE_PTHREAD`), matching the normal build.

---

## 2. End-to-end replay (`tests/replay`)

Reconstructs a scratch sysroot from each fixture under
`tests/fixtures/<arch>/<host>/` and runs the real `kasld -v` over it, checking
it parses, resolves, and renders a summary without crashing. There is no golden
master — a crash (signal) is the only failure; "no results" is informational.

### Native mode (no qemu) — host arch only

```sh
make                                   # build the x86_64 binary + components
KASLD_NATIVE=1 tests/replay tests/fixtures/x86_64/* tests/fixtures/x86_32/*
```

Native mode runs only fixtures the host can execute directly (an x86_64 host
also runs 32-bit x86); foreign-arch fixtures are skipped, never failed. The
binary is taken from `build/<arch>-*/` (any triple). For the x86_32 fixture,
build a 32-bit binary first, e.g. `make build CC=i686-linux-gnu-gcc`
(auto-static when cross). This is what CI runs.

### Full mode (qemu-user) — all arches

```sh
# musl-cross toolchains on PATH, qemu-user binaries in QEMU_DIR:
make cross                             # build every arch's binary + components
tests/replay                           # all fixtures, foreign arches under qemu
```

Foreign-arch component children do not exec under nested qemu-user, so those
fixtures legitimately yield no results — still a pass as long as nothing
crashes.

Env:

| Var | Default | Meaning |
|-----|---------|---------|
| `KASLD_NATIVE` | unset | `1` = run host-arch fixtures directly, no qemu |
| `QEMU_DIR` | (user-specific; see `tests/replay`) | location of `qemu-<arch>` user binaries |
| `BUILD_DIR` | `./build` | where the per-arch binaries live |
| `KEEP` | `0` | `1` = keep the last scratch sysroot for inspection |

Set `QEMU_DIR` to whatever directory holds your `qemu-<arch>` binaries —
distribution-installed qemu-user is typically already on `PATH`, but a
self-built qemu can live anywhere.

---

## 3. Cross-arch engine tests (`make test-cross`)

```sh
# musl-cross toolchains on PATH, qemu-user binaries in QEMU_DIR:
make test-cross        # or: tests/test-cross
```

Compiles `test_engine` + `test_engine_integration` with each cross toolchain
and runs them under qemu-user, so arch-gated rule bodies
(`#if defined(__aarch64__)` …) execute on their own architecture instead of
compiling to no-ops on the host. The engine tests are pure, syscall-free C, so
this is sound under emulation.

Covers 13 targets: the nine 64-bit arches (aarch64, riscv64, s390x, mips64,
mips64el, ppc64, ppc64le, loongarch64, x86_64) plus four 32-bit (i686, armv7,
mips, mipsel). 64-bit-only tests are `#if __SIZEOF_LONG__ >= 8`-guarded and
skip on the 32-bit targets. Targets whose toolchain or qemu binary is absent
are skipped; exit status is non-zero only if a present target fails.

ppc32's active path is not automated here (only a little-endian musl toolchain
is generally available and there is no 32-bit-LE `qemu-user` binary); it is
validated manually on real hardware or a full ppc32-BE VM.

---

## 4. Coverage (optional)

Optional, gcov-based — the normal build/test never use `--coverage`, so
coverage adds no dependency to them. The text summary needs only the
compiler's own gcov; HTML appears only if `lcov` + `genhtml` are installed.

```sh
make coverage          # host unit tests -> build/coverage/
make coverage-e2e      # real binary over x86 fixtures -> build/coverage-e2e/
```

- `coverage` instruments the engine core + every rule + the `test_kasld` TU
  and reports per-file + total line coverage from the host unit tests.
- `coverage-e2e` instruments the real binary (no `-DKASLD_TESTING`) and runs
  it live + over the x86_64/i686 fixtures, so it is the only report that
  reaches `main()`, the engine bridge, and the renderers. x86_64 host only
  (runs the binary natively).

For a clang toolchain, point at its gcov shim:

```sh
make coverage CC=clang GCOV="llvm-cov gcov"
```

Env: `CC` (default `cc`), `GCOV` (default `gcov`), `CFLAGS_EXTRA`.

---

## 5. Bundle soundness check (`extra/validate-bundle`)

```sh
extra/collect --kallsyms             # capture a bundle on the target
extra/validate-bundle kasld-bundle-* # run kasld over it, check the truth
```

Runs the arch-correct `kasld` binary (under qemu-user for foreign arches)
over the bundle's `sysroot/`, then asserts the engine-resolved range for
every reported quantity contains the ground truth captured in the same
bundle — virtual text base from `proc/kallsyms` (when the bundle was
captured with `--kallsyms`), physical text base from `proc/iomem`. Reports
PASS / FAIL / N/A per quantity.

A FAIL is a soundness violation — the engine's resolved window excluded
the truth. The only legitimate outcomes are PASS (range admits the truth,
possibly wide) or N/A (no truth available, e.g. an `--anonymize`-stripped
bundle). Tightness is a separate concern.

Complements the per-leak validator `extra/check-results`, which runs on
the live system as root and compares each emitted record against live
`/proc/{kallsyms,iomem,modules}`. `validate-bundle` validates the
engine's *resolved windows*; `check-results` validates each component's
*emitted records*.

Dependencies: `jq`, plus the cross toolchain + qemu-user binaries for
foreign-arch bundles (same setup as layers 2–3).

---

## 6. Parser fuzz harnesses (`tests/fuzz/`)

```sh
make fuzz                                    # build the harnesses (clang)
tests/fuzz/seed-from-fixtures.sh             # populate the seed corpus
build/fuzz/fuzz_capture_result \
    tests/fuzz/corpus/capture_result/        # run the parser fuzzer
```

libFuzzer harnesses (with AddressSanitizer + UndefinedBehaviorSanitizer)
for the four pure string→struct parsers the orchestrator runs against
attacker-influenced input: `parse_hex`, `capture_result`, `capture_scalar`,
`parse_meta`. See `tests/fuzz/README.md` for the contract details and
crash-reproduction workflow.

Opt-in: `make fuzz` requires clang with `-fsanitize=fuzzer` and is not
part of the default build graph. The harnesses are not exercised by CI —
corpus-guided fuzzing wants hours of runtime per harness, which doesn't
fit a per-commit CI budget. The harness binaries land in `build/fuzz/`
and are not installed by `make install` (the install glob covers only
`build/<arch>/` per-arch artifacts).

---

## Prerequisites

- **Layer 1** (`make check`): a C compiler (`cc` / gcc / clang) and `make`.
  Nothing else.
- **Layers 2–3** (qemu paths): musl-cross toolchains on `PATH` (any source —
  [musl.cc](https://musl.cc/) prebuilt sets, distribution packages, or a local
  build all work; KASLD targets the standard `<arch>-linux-musl-gcc` triples),
  and qemu-user binaries in `$QEMU_DIR`. Native replay (layer 2) needs neither.
- **Layer 4**: gcc + `gcov`, or clang + `llvm-cov gcov`; `lcov` + `genhtml`
  optional for HTML.
- **Layer 5**: `jq`. Foreign-arch bundles additionally need the cross
  toolchains and qemu-user binaries from layers 2–3.
- **Layer 6**: clang (or any toolchain shipping `-fsanitize=fuzzer`).
  The `make fuzz` target builds against libFuzzer directly; no further
  dependencies.

## CI

`.github/workflows/build.yml`:

- **build** job: `make` → `make check` (layer 1) → build i686 → native replay
  over the x86_64 + x86_32 fixtures (layer 2, no qemu).
- **cross-compile** job: `make cross` — build-only across the gnu cross
  toolchains (no execution, no qemu).

`.github/workflows/clang-format.yml` runs the style check. CI does not use
qemu, so `make test-cross` and full (qemu) replay are local / manual only.
