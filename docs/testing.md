# Testing

KASLD has six test layers, in increasing order of setup cost:

1. **Host unit + integration tests + static guards** — pure C over synthetic
   evidence, plus grep/shellcheck source-invariant guards (`make lint`). No deps
   beyond a C compiler. This is the primary safety net.
2. **End-to-end replay** — runs the real `kasld` binary over captured filesystem
   trees. Native (no qemu) for the host arch; qemu-user for foreign arches.
3. **Cross-arch engine tests** — the unit tests run on each architecture under
   qemu-user, so arch-gated rule bodies execute their real path.
4. **Coverage reports** — optional, gcov-based.
5. **Live cross-architecture validation** (`tests/vm/run`) — boots real
   publicly-fetchable kernels under `qemu-system` and checks the inferred range
   contains the live kernel's true base, across arches and privilege profiles.
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
make test           # build + run all ten test drivers, then the lint guards
make lint           # just the static guards (no test-binary build)
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
| `test_kasld` | orchestrator internals (parse, merge, anchor select), the engine→layout projection, region_info | `orchestrator.c` / `region_info.c` under `-DKASLD_TESTING` |
| `test_render` | the renderers (text / json / markdown / oneline / hardening) — split out of `test_kasld` | `render.c` / `render/*.c` under `-DKASLD_TESTING` |
| `test_align` | the text-base floor helpers (`kasld_floor_aligned_suboffset` / `kasld_floor_text_base`) | `api.h` (header-only) |
| `test_text_order` | the kernel-text ordering classifier (`classify_text_order`) | `text_order.h` (header-only) |
| `test_dmesg_layout` | the riscv `print_vm_layout` dump parser | `components/dmesg_mem_init_kernel_layout.c` (`#include`d, `main` renamed) |
| `test_btf` | the BTF struct-size reader behind `btf_struct_page_size` | `components/btf_struct_page_size.c` (`#include`d, `main` renamed) |

Run one driver in isolation:

```sh
make test-estimate
make test-evidence
make test-engine
make test-integration
make test-dmesg-layout
make test-btf
```

`test_kasld` is built with `-DKASLD_TESTING`, which compiles out `main()`, the
`engine_build_evidence` bridge, and the live engine run. Those — the real
collect → bridge → resolve → render path — are exercised only by replay (layer 2).

Compiler / flags: `make test CC=clang`, `CFLAGS=...` as usual. pthread is used
when available (`HAVE_PTHREAD`), matching the normal build.

### Static guards (`make lint`)

`make test` finishes by running `make lint` — static-analysis guards that assert
source invariants the unit tests can't, with no compiled test binary. Run them
alone with `make lint` (fast; no driver build). Each exits non-zero on failure,
and `make` halts on the first.

| Guard | Asserts |
|-------|---------|
| `check-self-edges` | no engine rule reads `est[Q]` and writes `Q` (a "self-edge") outside the reviewed allowlist — each such rule needs a soundness test |
| `check-extent-callers` | only reviewed whole-map components call `kasld_result_extent` (the covering-completeness contract; a partial map would carve a false gap) |
| `check-truncation` | no silent 64-bit→word narrowing when compiled for 32-bit (compiles a TU with `i686-linux-gnu-gcc`) |
| `check-component-output` | components write only wire lines to stdout (stdout is the machine channel; diagnostics go to stderr) |
| `check-component-meta` | every component declares `KASLD_META` with a `method:` key |
| `check-text-floor` | no component rolls its own text-base floor — they must use the `api.h` helper |
| `check-shellcheck` | shellcheck over the `extra/` helper scripts |

`check-truncation` needs `i686-linux-gnu-gcc` and `check-shellcheck` needs
`shellcheck`; both **skip cleanly** (exit 0) when their tool is absent, so
`make lint` works with just a host compiler. CI installs both, so there they run
for real.

---

## 2. End-to-end replay (`tests/replay`)

Reconstructs a scratch sysroot from each fixture under
`tests/fixtures/<arch>/<host>/` and runs the real `kasld` over it in every output
mode — verbose text (`-v`), oneline (`-1`), and the hardening report in
text / markdown / json (`-H`, `-H -m`, `-H -j`) — checking each parses, resolves,
and renders without crashing. There is no golden master — a crash (signal) is the
only failure; "no results" is informational. The multi-mode sweep is per-arch
crash coverage of every renderer, which the host-only render unit tests cannot
reach.

Fixtures are **real `extra/collect` captures** from real kernels (validated with
`extra/validate-bundle` on ingest), not hand-authored inputs — the corpus
exercises KASLD against reality. Synthetic inputs live in the unit tests
(layer 1).

This is a **structural / regression** check, not a soundness check: it confirms
KASLD survives real captured kernel state across many architectures and versions,
but it does not verify the inferred range against a ground truth (a static
fixture carries none). Soundness on a *captured* system is checked by
`extra/validate-bundle` when the bundle is ingested; soundness on a *live* kernel
is layer 5 (`tests/vm/run`). Replay overlaps those in architecture breadth but answers a
different question — *does the binary run cleanly?* rather than *is the result
sound?*

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
# musl-cross toolchains + qemu-user binaries on PATH:
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
| `QEMU_DIR` | search `PATH` | directory of `qemu-<arch>` user binaries (override only if not on `PATH`) |
| `BUILD_DIR` | `./build` | where the per-arch binaries live |
| `KEEP` | `0` | `1` = keep the last scratch sysroot for inspection |

The `qemu-<arch>` user binaries are resolved from `PATH` by default
(distribution qemu-user installs there). Set `QEMU_DIR` only when they live
elsewhere, such as a self-built qemu in a non-standard prefix.

---

## 3. Cross-arch engine tests (`make test-cross`)

```sh
# musl-cross toolchains + qemu-user binaries on PATH:
make test-cross        # or: tests/test-cross
```

Compiles `test_engine`, `test_engine_integration`, `test_kasld` and
`test_render` with each cross toolchain and runs them under qemu-user, so
arch-gated rule bodies
(`#if defined(__aarch64__)` …) execute on their own architecture instead of
compiling to no-ops on the host. The engine tests are pure, syscall-free C, so
this is sound under emulation.

Covers 17 targets: nine 64-bit (aarch64, riscv64, s390x, mips64, mips64el,
ppc64, ppc64le, loongarch64, x86_64) and eight 32-bit (i686, arm, armv7, armeb,
mips, mipsel, riscv32, powerpc — ppc32 big-endian). 64-bit-only tests are
`#if __SIZEOF_LONG__ >= 8`-guarded and skip on the 32-bit targets. Targets whose
toolchain or qemu-user binary is absent are skipped; exit status is non-zero only
if a present target fails.

The one variant not automated here is **ppc32 little-endian**: the `powerpcle`
musl toolchain exists, but there is no 32-bit-LE `qemu-user` binary to run it
under, so it is validated manually on real hardware or a full ppc32-LE VM.

This runs **per-push in CI**: the cross-compile matrix (`build.yml` →
`_cross-build.yml` with `run_test_cross`) invokes `tests/test-cross <triple>` for
each arch under qemu-user, so a broken arch-gated assertion fails the push that
introduces it — the cross-*compile* job alone would not catch it. With no
arguments `tests/test-cross` runs the full local set; with triples it runs just
those (one per CI matrix job).

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

## Validating captured bundles

`extra/validate-bundle` is not a test layer — it is the validation step for
*ingesting* a bundle. When a bundle is captured from a real system (a bug report,
an external VM), this confirms KASLD is sound on it and decides whether it earns
a place as a replay fixture (layer 2, which is what then exercises it on every
run). It is a one-shot ingest check, not part of the recurring suite or CI.

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

Bundles are captured from real systems — the machine under test, a
system attached to a bug report, or an external test VM — so a PASS is
evidence KASLD was sound on a real kernel. The data's provenance is the
point: a validated bundle can be committed under `tests/fixtures/` as a
replay fixture (layer 2), so the fixture corpus is **real captures only**.
Synthetic inputs belong in the unit tests (layer 1, e.g. `test_engine`
for rules, `test_dmesg_layout` / `test_btf` for component parsers), never
in a bundle or fixture — keeping "this ran on a real kernel" meaningful.

Complements the per-leak validator `extra/check-results`, which runs on
the live system as root and compares each emitted record against live
`/proc/{kallsyms,iomem,modules}`. `validate-bundle` validates the
engine's *resolved windows*; `check-results` validates each component's
*emitted records*.

Dependencies: `jq`, plus the cross toolchain + qemu-user binaries for
foreign-arch bundles (same setup as layers 2–3).

---

## 5. Live cross-architecture validation (`tests/vm/run`)

```sh
make cross                 # build the per-arch binaries
tests/vm/run               # boot each supported arch, default profile
tests/vm/run all hardened  # repeat under the unprivileged floor
```

Boots a real, publicly-fetchable kernel per architecture under
`qemu-system` (with KVM where the guest matches the host), runs the
cross-built `kasld` against the running kernel, and checks that the
inferred range contains the kernel's true text base. Where
`extra/validate-bundle` validates a single captured system offline, this
validates live kernels
across architectures and reader-privilege profiles
(`default` / `hide` / `hardened` / `nokaslr`).

Unlike replay (layer 2) — which runs offline over captured fixtures and
only checks that KASLD parses and runs — this boots a real kernel, so it
*knows* the true base and checks soundness: that the inferred range
contains it.

Needs `qemu-system-<arch>` and the cross toolchains on PATH; an arch is
skipped (not failed) when either is missing. After running the scenarios,
`tests/vm/run table` renders the `arch × scenario → recovered / residual bits /
sound` matrix from the boot logs; the published snapshot is in
[reproducibility.md](reproducibility.md). See
[tests/vm/README.md](../tests/vm/README.md) for the full arch list and options.

Architectures Alpine does not port (`mips`, `mipsel`, `riscv32`, `ppc32`) are
built from a pinned kernel.org source by `tests/vm/build-kernel` — a stock
upstream defconfig plus a fixed endianness/devtmpfs overlay — then booted by
`tests/vm/run` the same way:

```sh
tests/vm/build-kernel mipsel   # download source + cross-build -> cache (slow)
tests/vm/run mipsel            # boot it, verdict
```

This is manual and slow; the arch-gated rule *logic* is covered per-push by
`make test-cross`. `armeb` is not validated: the only
big-endian arm toolchain in the cross set is ARMv5 BE32, which can neither run on
an ARMv7 BE8 kernel nor boot a BE32 kernel under qemu.

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
  Nothing else for the unit tests. The `make lint` guards optionally use
  `i686-linux-gnu-gcc` (`check-truncation`) and `shellcheck`
  (`check-shellcheck`); both skip cleanly when absent.
- **Layers 2–3** (qemu paths): musl-cross toolchains on `PATH` (any source —
  [musl.cc](https://musl.cc/) prebuilt sets, distribution packages, or a local
  build all work; KASLD targets the standard `<arch>-linux-musl-gcc` triples),
  and `qemu-<arch>` user binaries on `PATH` (or in `$QEMU_DIR`). Native replay
  (layer 2) needs neither.
- **Layer 4**: gcc + `gcov`, or clang + `llvm-cov gcov`; `lcov` + `genhtml`
  optional for HTML.
- **Layer 5**: `qemu-system-<arch>` for the guest arches, plus the cross
  toolchains, `curl`, `cpio`. The guest *kernels* are fetched from Alpine
  automatically by `tests/vm/run`; the Debian/Ubuntu names are only the **host**
  package to install qemu itself (`apt install qemu-system-x86 qemu-system-arm
  qemu-system-misc`). Uses KVM automatically when the guest matches the host.
- **Layer 6**: clang (or any toolchain shipping `-fsanitize=fuzzer`).
  The `make fuzz` target builds against libFuzzer directly; no further
  dependencies.
- **`extra/validate-bundle`** (bundle-validation tool, not a layer): `jq`;
  foreign-arch bundles also need the cross toolchains + qemu-user from
  layers 2–3.

## CI

Per-push, `.github/workflows/build.yml`:

- **build** job: `make` → `make check` (layer 1, including the `make lint`
  guards) → build i686 → native replay over the x86_64 + x86_32 fixtures
  (layer 2, no qemu). The job installs `gcc-i686-linux-gnu` and `shellcheck`, so
  `check-truncation` and `check-shellcheck` run for real rather than skipping.
- **cross-compile** job: calls the reusable `_cross-build.yml` — one job per
  arch, fetching the cross-tools/musl-cross toolchain, running `make build` with
  a static-linkage check, then (`run_test_cross`) installing `qemu-user` and
  running the engine tests for that arch (`tests/test-cross <triple>`, layer 3)
  under emulation. So every push *verifies* arch-gated rule bodies, not just that
  they compile.

Manual, `.github/workflows/replay.yml`:

- Reuses `_cross-build.yml` with `run_replay: true`, so each per-arch job
  installs `qemu-user` and runs `tests/replay` right after building — extending
  the native x86 replay to every foreign arch under emulation (layer 2, full).
  Manual because cross-compiling every arch and emulating it is minutes, not a
  per-push cost.

`.github/workflows/clang-format.yml` runs the style check.

Every layer's CI status, for completeness:

| layer | in CI? | where / why not |
|-------|--------|-----------------|
| 1 — host unit + integration + lint | ✅ per-push | `build` job (`make check`) |
| 2 — end-to-end replay | ✅ partial | native x86 per-push (`build` job); full qemu-user is manual (`replay.yml`) |
| 3 — cross-arch engine tests | ✅ per-push | `cross-compile` matrix runs `tests/test-cross` per arch under qemu-user |
| 4 — coverage | ❌ | local, on-demand (`make coverage`); a report, not a gate |
| 5 — live VM matrix | ❌ | full-system qemu with kernels outside the repo (no `/dev/kvm` on hosted runners); local/manual |
| 6 — parser fuzz | ❌ | opt-in `make fuzz`; bounded fuzzing is a scheduled/local task, not a per-push gate |

