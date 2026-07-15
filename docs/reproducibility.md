# Reproducibility

KASLD's results can be checked, not just trusted. The core property to verify is
that the range KASLD infers for the kernel image base contains the real value:

```
truth ∈ [virt_image_base_min, virt_image_base_max]
```

The same property holds on the physical axis — `phys_truth ∈ [phys_kaslr_text_min,
phys_kaslr_text_max]` — on architectures that place the kernel image independently
in physical memory (x86-64, arm64, riscv64, s390); elsewhere the physical base is
a fixed projection of the virtual one and is covered by the check above.

A range that excludes the truth is a bug; a range that is wider than necessary is
not (it just means less was recovered). There are three ways to verify this, in
increasing order of how close they run to a real system. All are runnable from a
clean checkout.

These overlap in breadth — several run KASLD across many architectures — but each
answers a different question, so they are complementary, not redundant:

| check | runs against | answers | cost |
|-------|--------------|---------|------|
| [`tests/replay`](#3-offline-over-a-captured-corpus) | captured fixtures, offline | *does KASLD parse and run cleanly over real kernel state?* (no ground truth — a regression / robustness check) | seconds |
| [`extra/validate-bundle`](#1-on-the-local-kernel) | one captured bundle, offline | *does the inferred range contain that system's truth?* | seconds |
| [`tests/vm/run`](#2-live-across-architectures) | a live kernel booted under qemu | *does the inferred range contain a live kernel's truth, across arches and privilege levels?* | minutes |

The key distinction is **structural vs. soundness**: `tests/replay` confirms the
binary survives the messy reality of many captured kernels but cannot judge
soundness — a static fixture carries no independently-established truth to compare
against. `tests/vm/run` boots the kernel, so it *knows* the real base and checks
that the inferred range contains it. Replay is cheap and continuous; the VM check
is slower and run periodically.

## 1. On the local kernel

Capture the running system's state and confirm the inferred ranges contain the
truth:

```sh
extra/collect --kallsyms              # capture a self-contained bundle
extra/validate-bundle kasld-bundle-*  # run kasld over it, check the truth
```

`collect` writes a path-preserving copy of the files KASLD reads plus the
kernel's real symbol addresses. `validate-bundle` runs the matching `kasld` binary
over that bundle offline and checks every inferred range against the captured
ground truth. It exits non-zero if any range excludes the truth. No root needed.

`--kallsyms` can only record the ground truth when kallsyms is readable
(`kptr_restrict=0`, or root). Without it the bundle carries no truth and the
checks report `N/A` rather than `PASS` — still not a failure, just nothing to
compare against.

## 2. Live, across architectures

[`tests/vm/run`](../tests/vm) boots real, publicly-fetchable kernels under
`qemu-system`, runs KASLD against the running kernel, and applies the same check
across architectures and attacker profiles:

```sh
make cross            # build the per-arch binaries
tests/vm/run          # boot each supported arch, default profile
tests/vm/run all hardened   # repeat under the unprivileged floor
```

It needs `qemu-system-<arch>` and the cross toolchains on PATH; an architecture
is skipped (not failed) when either is missing. The reader profiles (the
`scenario` column of the matrix) escalate how little KASLD is allowed to read:

- `default` — root, `kptr_restrict=0`: kallsyms and everything else readable.
- `hidden` — root, but `kptr_restrict=2`: kernel pointers are *hidden*, so
  kallsyms is unusable and the base must come from inference or other leaks
  (e.g. dmesg), not the symbol table.
- `hardened` — unprivileged (uid 1000) with `kptr_restrict=2`,
  `dmesg_restrict=1`, `perf_event_paranoid=3`: the realistic attacker floor,
  where only file-derived facts survive.

Under the tighter profiles the window may widen but must still contain the truth.
See [tests/vm/README.md](../tests/vm/README.md) for the full arch list and options.

Every architecture is booted on mainline kernel.org kernels — the LTS lines 5.15
and 6.6 and current 7.0 — cross-built from pinned source by `tests/vm/build-kernel`
(a stock upstream defconfig plus a fixed endianness/devtmpfs overlay). Eight of
them additionally boot a publicly-fetchable Alpine distro kernel; the other six —
`mips`, `mipsel`, `mips64el`, `powerpc64`, `ppc32`, `riscv32` — have no Alpine
port, so mainline is their only source. Cells are named `<arch>-<distro>-<line>`;
for a mainline cell the version in the name is a label and `LINUX_VERSION` sets
the source:

```sh
LINUX_VERSION=5.15.211 tests/vm/build-kernel ppc32-mainline-5.15  # cross-build -> cache (slow)
tests/vm/run ppc32-mainline-5.15                                  # boot it, verdict
```

`armeb` is not covered: the only big-endian arm toolchain in the cross set emits
ARMv5 BE32 code, which can neither run on an ARMv7 BE8 kernel nor boot a BE32
kernel under qemu.

### Results matrix

The snapshot below is generated by `tests/vm/run all <scenario>` followed by
`tests/vm/run table`. Every cell is sound — the true base lies inside the
**guaranteed** window (the one resolved at the sound floor), on *both* the
virtual and the physical axis.

`source` is the kernel: `alpine` (a distro kernel) or `mainline` (a vanilla
kernel.org build via `tests/vm/build-kernel`). `virt residual` and `phys
residual` say how much KASLR entropy KASLD could *not* strip from the virtual
text base and the physical image base — i.e. how effectively KASLR was defeated
on each axis:

- `exact` — the base was recovered and KASLR is defeated. This covers both a
  byte-exact pin and a window narrower than one KASLR slot: either way the
  randomized slot is known, so 0 bits of KASLR entropy remain.
- `<n> bits` — KASLR is still randomized, with n bits of the slot unrecovered
  (2^n candidate positions).
- `—` — KASLR is off, so there is no randomization to defeat; or, in the `phys
  residual` column, the physical base is not randomized independently of the
  virtual text base (a *coupled* architecture: x86-32, arm32, MIPS, PPC,
  RISC-V 32, LoongArch), so it carries no separate physical result. The
  physical column scores only the *decoupled* arches — x86-64, arm64, riscv64,
  s390 — where the kernel image is placed independently in physical memory.

Soundness is gated on both axes: a cell whose physical window excludes the true
physical base is withheld exactly like a virtual violation, never published.

The axes are architecture × kernel line × reader profile: each architecture is
booted on the mainline LTS lines 5.15 and 6.6 and on current 7.0 — plus an Alpine
distro kernel where a port exists — under each of the three reader profiles
(`default`, `hidden`, `hardened`). An architecture predating a line carries no
cell there (LoongArch, mainlined in 6.1, has no 5.15 row). A kernel-config axis
is out of scope (see Scope below).

| arch | release | source | scenario | KASLR | virt residual | phys residual |
|------|---------|--------|----------|-------|---------------|---------------|
| x86_64 | 6.12.81-0-virt | alpine | default | on | exact | exact |
| x86_64 | 6.12.81-0-virt | alpine | hidden | on | exact | exact |
| x86_64 | 6.12.81-0-virt | alpine | hardened | on | 6 bits | 6 bits |
| i686 | 6.12.81-0-lts | alpine | default | on | exact | — |
| i686 | 6.12.81-0-lts | alpine | hidden | on | exact | — |
| i686 | 6.12.81-0-lts | alpine | hardened | on | 5 bits | — |
| aarch64 | 6.12.81-0-virt | alpine | default | on | exact | exact |
| aarch64 | 6.12.81-0-virt | alpine | hidden | on | 27 bits | exact |
| aarch64 | 6.12.81-0-virt | alpine | hardened | on | 31 bits | 14 bits |
| armv7 | 6.12.81-0-lts | alpine | default | off | — | — |
| armv7 | 6.12.81-0-lts | alpine | hidden | off | — | — |
| armv7 | 6.12.81-0-lts | alpine | hardened | off | — | — |
| riscv64 | 6.18.35-0-lts | alpine | default | off | — | — |
| riscv64 | 6.18.35-0-lts | alpine | hidden | off | — | — |
| riscv64 | 6.18.35-0-lts | alpine | hardened | off | — | — |
| loongarch64 | 6.18.35-0-lts | alpine | default | on | exact | — |
| loongarch64 | 6.18.35-0-lts | alpine | hidden | on | 3 bits | — |
| loongarch64 | 6.18.35-0-lts | alpine | hardened | on | 14 bits | — |
| ppc64le | 6.12.81-0-lts | alpine | default | off | — | — |
| ppc64le | 6.12.81-0-lts | alpine | hidden | off | — | — |
| ppc64le | 6.12.81-0-lts | alpine | hardened | off | — | — |
| s390x | 6.12.81-0-lts | alpine | default | on | exact | exact |
| s390x | 6.12.81-0-lts | alpine | hidden | on | 22 bits | exact |
| s390x | 6.12.81-0-lts | alpine | hardened | on | 39 bits | 10 bits |
| x86_64 | 5.15.211 | mainline | default | on | exact | exact |
| x86_64 | 5.15.211 | mainline | hidden | on | 5 bits | exact |
| x86_64 | 5.15.211 | mainline | hardened | on | 9 bits | 9 bits |
| x86_64 | 6.6.144 | mainline | default | on | exact | exact |
| x86_64 | 6.6.144 | mainline | hidden | on | 5 bits | exact |
| x86_64 | 6.6.144 | mainline | hardened | on | 9 bits | 9 bits |
| x86_64 | 7.0.0 | mainline | default | on | exact | exact |
| x86_64 | 7.0.0 | mainline | hidden | on | 5 bits | exact |
| x86_64 | 7.0.0 | mainline | hardened | on | 9 bits | 9 bits |
| i686 | 5.15.211 | mainline | default | on | exact | — |
| i686 | 5.15.211 | mainline | hidden | on | exact | — |
| i686 | 5.15.211 | mainline | hardened | on | 8 bits | — |
| i686 | 6.6.144 | mainline | default | on | exact | — |
| i686 | 6.6.144 | mainline | hidden | on | exact | — |
| i686 | 6.6.144 | mainline | hardened | on | 8 bits | — |
| i686 | 7.0.0 | mainline | default | on | exact | — |
| i686 | 7.0.0 | mainline | hidden | on | exact | — |
| i686 | 7.0.0 | mainline | hardened | on | 8 bits | — |
| aarch64 | 5.15.211 | mainline | default | on | 5 bits | exact |
| aarch64 | 5.15.211 | mainline | hidden | on | 5 bits | exact |
| aarch64 | 5.15.211 | mainline | hardened | on | 31 bits | 14 bits |
| aarch64 | 6.6.144 | mainline | default | on | 5 bits | exact |
| aarch64 | 6.6.144 | mainline | hidden | on | 5 bits | exact |
| aarch64 | 6.6.144 | mainline | hardened | on | 31 bits | 14 bits |
| aarch64 | 7.0.0 | mainline | default | on | exact | exact |
| aarch64 | 7.0.0 | mainline | hidden | on | 5 bits | exact |
| aarch64 | 7.0.0 | mainline | hardened | on | 31 bits | 14 bits |
| armv7 | 5.15.211 | mainline | default | off | — | — |
| armv7 | 5.15.211 | mainline | hidden | off | — | — |
| armv7 | 5.15.211 | mainline | hardened | off | — | — |
| armv7 | 6.6.144 | mainline | default | off | — | — |
| armv7 | 6.6.144 | mainline | hidden | off | — | — |
| armv7 | 6.6.144 | mainline | hardened | off | — | — |
| armv7 | 7.0.0 | mainline | default | off | — | — |
| armv7 | 7.0.0 | mainline | hidden | off | — | — |
| armv7 | 7.0.0 | mainline | hardened | off | — | — |
| riscv64 | 5.15.211 | mainline | default | off | — | — |
| riscv64 | 5.15.211 | mainline | hidden | off | — | — |
| riscv64 | 5.15.211 | mainline | hardened | off | — | — |
| riscv64 | 6.6.144 | mainline | default | off | — | — |
| riscv64 | 6.6.144 | mainline | hidden | off | — | — |
| riscv64 | 6.6.144 | mainline | hardened | off | — | — |
| riscv64 | 7.0.0 | mainline | default | off | — | — |
| riscv64 | 7.0.0 | mainline | hidden | off | — | — |
| riscv64 | 7.0.0 | mainline | hardened | off | — | — |
| loongarch64 | 6.6.144 | mainline | default | on | exact | — |
| loongarch64 | 6.6.144 | mainline | hidden | on | 3 bits | — |
| loongarch64 | 6.6.144 | mainline | hardened | on | 14 bits | — |
| loongarch64 | 7.0.0 | mainline | default | on | exact | — |
| loongarch64 | 7.0.0 | mainline | hidden | on | 3 bits | — |
| loongarch64 | 7.0.0 | mainline | hardened | on | 14 bits | — |
| ppc64le | 5.15.211 | mainline | default | off | — | — |
| ppc64le | 5.15.211 | mainline | hidden | off | — | — |
| ppc64le | 5.15.211 | mainline | hardened | off | — | — |
| ppc64le | 6.6.144 | mainline | default | off | — | — |
| ppc64le | 6.6.144 | mainline | hidden | off | — | — |
| ppc64le | 6.6.144 | mainline | hardened | off | — | — |
| ppc64le | 7.0.0 | mainline | default | off | — | — |
| ppc64le | 7.0.0 | mainline | hidden | off | — | — |
| ppc64le | 7.0.0 | mainline | hardened | off | — | — |
| s390x | 5.15.211 | mainline | default | on | exact | exact |
| s390x | 5.15.211 | mainline | hidden | on | exact | exact |
| s390x | 5.15.211 | mainline | hardened | on | 39 bits | 10 bits |
| s390x | 6.6.144 | mainline | default | on | exact | exact |
| s390x | 6.6.144 | mainline | hidden | on | exact | exact |
| s390x | 6.6.144 | mainline | hardened | on | 39 bits | 10 bits |
| s390x | 7.0.0 | mainline | default | on | exact | exact |
| s390x | 7.0.0 | mainline | hidden | on | 22 bits | exact |
| s390x | 7.0.0 | mainline | hardened | on | 39 bits | 10 bits |
| mips | 5.15.211 | mainline | default | on | exact | — |
| mips | 5.15.211 | mainline | hidden | on | exact | — |
| mips | 5.15.211 | mainline | hardened | on | 11 bits | — |
| mips | 6.6.144 | mainline | default | on | exact | — |
| mips | 6.6.144 | mainline | hidden | on | exact | — |
| mips | 6.6.144 | mainline | hardened | on | 11 bits | — |
| mips | 7.0.0 | mainline | default | on | exact | — |
| mips | 7.0.0 | mainline | hidden | on | exact | — |
| mips | 7.0.0 | mainline | hardened | on | 11 bits | — |
| mipsel | 5.15.211 | mainline | default | on | exact | — |
| mipsel | 5.15.211 | mainline | hidden | on | exact | — |
| mipsel | 5.15.211 | mainline | hardened | on | 11 bits | — |
| mipsel | 6.6.144 | mainline | default | on | exact | — |
| mipsel | 6.6.144 | mainline | hidden | on | exact | — |
| mipsel | 6.6.144 | mainline | hardened | on | 11 bits | — |
| mipsel | 7.0.0 | mainline | default | on | exact | — |
| mipsel | 7.0.0 | mainline | hidden | on | exact | — |
| mipsel | 7.0.0 | mainline | hardened | on | 11 bits | — |
| mips64el | 5.15.211 | mainline | default | on | exact | — |
| mips64el | 5.15.211 | mainline | hidden | on | exact | — |
| mips64el | 5.15.211 | mainline | hardened | on | 14 bits | — |
| mips64el | 6.6.144 | mainline | default | on | exact | — |
| mips64el | 6.6.144 | mainline | hidden | on | exact | — |
| mips64el | 6.6.144 | mainline | hardened | on | 14 bits | — |
| mips64el | 7.0.0 | mainline | default | on | exact | — |
| mips64el | 7.0.0 | mainline | hidden | on | exact | — |
| mips64el | 7.0.0 | mainline | hardened | on | 14 bits | — |
| riscv32 | 5.15.211 | mainline | default | off | — | — |
| riscv32 | 5.15.211 | mainline | hidden | off | — | — |
| riscv32 | 5.15.211 | mainline | hardened | off | — | — |
| riscv32 | 6.6.144 | mainline | default | off | — | — |
| riscv32 | 6.6.144 | mainline | hidden | off | — | — |
| riscv32 | 6.6.144 | mainline | hardened | off | — | — |
| riscv32 | 7.0.0 | mainline | default | off | — | — |
| riscv32 | 7.0.0 | mainline | hidden | off | — | — |
| riscv32 | 7.0.0 | mainline | hardened | off | — | — |
| ppc32 | 5.15.211 | mainline | default | on | exact | — |
| ppc32 | 5.15.211 | mainline | hidden | on | 2 bits | — |
| ppc32 | 5.15.211 | mainline | hardened | on | 15 bits | — |
| ppc32 | 6.6.144 | mainline | default | on | exact | — |
| ppc32 | 6.6.144 | mainline | hidden | on | 2 bits | — |
| ppc32 | 6.6.144 | mainline | hardened | on | 15 bits | — |
| ppc32 | 7.0.0 | mainline | default | on | exact | — |
| ppc32 | 7.0.0 | mainline | hidden | on | 2 bits | — |
| ppc32 | 7.0.0 | mainline | hardened | on | 15 bits | — |
| powerpc64 | 5.15.211 | mainline | default | off | — | — |
| powerpc64 | 5.15.211 | mainline | hidden | off | — | — |
| powerpc64 | 5.15.211 | mainline | hardened | off | — | — |
| powerpc64 | 6.6.144 | mainline | default | off | — | — |
| powerpc64 | 6.6.144 | mainline | hidden | off | — | — |
| powerpc64 | 6.6.144 | mainline | hardened | off | — | — |
| powerpc64 | 7.0.0 | mainline | default | off | — | — |
| powerpc64 | 7.0.0 | mainline | hidden | off | — | — |
| powerpc64 | 7.0.0 | mainline | hardened | off | — | — |

Under `hidden`/`hardened`, `residual` usually widens to `<n> bits`: kallsyms —
the pin the `default` column relies on — is gone, so the base stays `exact` only
where some other leak or fact still resolves it, and widens to a range where
nothing does. `hardened` strips more of those sources than `hidden` (an
unprivileged reader loses even the addresses files expose only to root), so some
cells that pin under `hidden` widen under `hardened`. The bits are how much of
the KASLR slot the surviving facts leave.

Several architectures show KASLR `off`: under the default qemu machine they
receive no KASLR seed (or the port has no text KASLR), so the kernel boots
unrandomized. `residual` is `—` for every `off` row — there is
no randomness to strip — but KASLD still bounds, and on seedless arches pins, the
fixed base soundly via the disabled-base path (e.g. `riscv64` under `-M virt`,
pinned from arch constants plus the world-readable device-tree). It simply is not
a KASLR-defeat result, so the column does not score it.

### Speculative narrowing (the likely window)

`residual` above is the **guaranteed** window — resolved only from signals at or
above the sound floor, and gate-checked to contain the truth. The engine also
resolves a **likely** window: the guaranteed window narrowed further by sub-floor
signals (timing side-channels, a single leaked pointer, config defaults). It is a
best-guess, always a subset of guaranteed, and — unlike guaranteed — it is *not*
gated to contain the truth. It surfaces in `-j` JSON as the `likely` /
`likely_physical` objects, emitted only when strictly tighter than guaranteed.

On the matrix boots, the likely window equals guaranteed on every cell except the
ten below, where a sub-floor signal narrows the base past the sound floor
(generated by `tests/vm/run spec-table`):

| arch | release | source | scenario | guaranteed | likely | via | method | truth ∈ likely |
|------|---------|--------|----------|------------|--------|-----|--------|:---:|
| x86_64 | 6.12.81-0-virt | alpine | hardened | 6 bits | exact | `prefetch` | timing | yes |
| x86_64 | 5.15.211 | mainline | hidden | 5 bits | exact | `perf_event_open` | parsed | yes |
| x86_64 | 5.15.211 | mainline | hardened | 9 bits | exact | `prefetch` | timing | yes |
| x86_64 | 6.6.144 | mainline | hidden | 5 bits | exact | `perf_event_open` | parsed | yes |
| x86_64 | 6.6.144 | mainline | hardened | 9 bits | exact | `prefetch` | timing | yes |
| x86_64 | 7.0.0 | mainline | hidden | 5 bits | exact | `perf_event_open` | parsed | yes |
| x86_64 | 7.0.0 | mainline | hardened | 9 bits | exact | `prefetch` | timing | yes |
| ppc32 | 5.15.211 | mainline | hardened | 15 bits | 11 bits | `proc_zoneinfo + sysfs_devicetree_memory` | parsed | yes |
| ppc32 | 6.6.144 | mainline | hardened | 15 bits | 11 bits | `proc_zoneinfo + sysfs_devicetree_memory` | parsed | yes |
| ppc32 | 7.0.0 | mainline | hardened | 15 bits | 11 bits | `proc_zoneinfo + sysfs_devicetree_memory` | parsed | yes |

The split follows the reader profile and the arch's surviving sub-floor signals.
Under `hidden`, `perf_event_open` is still permitted, so on `x86_64` it leaks a
symbol pointer — a parsed best-guess base — that collapses the likely window to
`exact`. Under `hardened`, `perf_event_paranoid=3` blocks it; where a timing
oracle survives that floor (`x86_64` `prefetch`) the base is still pinned, and
where none does the likely window collapses back onto guaranteed. `ppc32` uses
neither: under `hardened` its narrowing is a memory-map heuristic from
`/proc/zoneinfo` and the device-tree, trimming 15 bits to 11. Every other
KASLR-on cell leaves likely equal to guaranteed — including `x86_64` under Alpine
`hidden`, where a sound `bpf_verifier_ksym` leak already pins the guaranteed base
`exact`, so there is nothing left for a speculative signal to narrow.

Every likely window on this run contained the truth (10 / 10). That is a per-run
property for the four `timing` rows (`x86_64` `prefetch`, one Alpine plus three
mainline lines) — `prefetch` is a probabilistic oracle and can miss on another
boot, in which case the likely base is wrong while the guaranteed window still
holds. The six `parsed` rows (`perf_event_open` on `x86_64`, the `/proc/zoneinfo`
heuristic on `ppc32`) do not depend on timing. A likely miss is never a soundness
violation: the gate is on guaranteed, which contains the truth in every cell
regardless.

## 3. Offline, over a captured corpus

The repository ships captured snapshots from real kernels, so the engine can be
exercised across hardware that is not otherwise available:

```sh
make check            # unit + integration tests (the per-rule checks)
tests/replay          # run kasld over every captured fixture
```

`tests/replay` confirms KASLD parses and runs cleanly on each snapshot;
`make check` runs the per-rule unit tests, including the soundness checks. The
corpus spans 10 architecture families (Alpine, Debian, Ubuntu/Raspbian) and
kernels from 4.19 to 7.0:

| family | example kernels |
|--------|-----------------|
| x86_64, i686 | 5.15 – 7.0 (Alpine, Debian, Ubuntu) |
| aarch64, armv7 | 5.10 – 7.0 |
| ppc64, ppc32 | 6.1 – 6.19 |
| riscv64 | 6.6 – 6.18 |
| s390x | 5.15 – 6.19 |
| loongarch64 | 6.18 |
| mips32 | 4.19 – 5.10 |

## Scope

These checks cover soundness — whether the inferred range contains the truth —
across a broad set of architectures, kernel versions, and reader-privilege
levels. They use one stock kernel configuration per architecture; configuration
axes that require purpose-built kernels (VA-bits / paging mode, endianness,
VMSPLIT, individual `CONFIG_*` toggles) are not yet covered. Timing and
side-channel components are validated separately, as their behaviour depends on
hardware rather than configuration.
