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
not (it just means less was recovered). There are four ways to verify this, from a
boot-free structural check up to live-kernel soundness. All are runnable from a
clean checkout.

These overlap in breadth — several run KASLD across many architectures — but each
answers a different question, so they are complementary, not redundant:

| check | runs against | answers | cost |
|-------|--------------|---------|------|
| [`tests/replay`](#3-offline-over-a-captured-corpus) | captured fixtures, offline | *does KASLD parse and run cleanly over real kernel state?* (structural — a regression / robustness check, no truth compared) | seconds |
| [`tests/validate-fixtures`](#3-offline-over-a-captured-corpus) | the shipped truth-bearing captures, offline | *does the inferred range contain the real base across many captured kernels, without a VM?* | seconds |
| [`extra/validate-bundle`](#1-on-the-local-kernel) | one captured bundle, offline | *does the inferred range contain that system's truth?* | seconds |
| [`tests/vm/run`](#2-live-across-architectures) | a live kernel booted under qemu | *does the inferred range contain a live kernel's truth, across arches and privilege levels?* | minutes |

The key distinction is **structural vs. soundness**. `tests/replay` is structural
— it confirms the binary runs cleanly over many captured kernels but does not
compare against a truth. Soundness is checked directly: `tests/validate-fixtures`
does it offline over the captured kernels that carry ground truth — a real kallsyms
`_text`/`_stext` or an iomem "Kernel code" line — and `tests/vm/run` does it on a
freshly booted live kernel whose real base it knows directly. Many committed
captures keep that truth even though they are shared publicly: the anonymization
that prepares a fixture for sharing (`extra/collect --anonymize`, plus
`extra/anonymize-fdt` for device-tree boards) redacts host-identifying text —
hostname, CPU model, UUIDs, MACs, sensitive `cmdline` values — from
`cpuinfo`/`cmdline`/`version`/`dmesg`, but never touches `/proc/kallsyms` or the
iomem kernel line, so the base survives. The offline checks are cheap and
continuous; the VM check is slower and run periodically.

## Contents

- [1. On the local kernel](#1-on-the-local-kernel)
- [2. Live, across architectures](#2-live-across-architectures)
  - [Results matrix](#results-matrix)
  - [Speculative narrowing (the likely window)](#speculative-narrowing-the-likely-window)
- [3. Offline, over a captured corpus](#3-offline-over-a-captured-corpus)
- [Scope](#scope)

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
is skipped (not failed) when either is missing. The analysis always runs as an
unprivileged user (uid 1000) — KASLD's threat model is an unprivileged local
attacker, so every profile measures what such a user can leak, never what root
can. The profiles (the `scenario` column of the matrix) differ only in how much
the sysctl hardening lets that user read; the one privileged step is the
per-boot ground-truth capture the check compares against.

- `default` — `kptr_restrict=0`: permissive sysctls, so an unprivileged reader
  still sees kallsyms (kernel pointers exposed to everyone).
- `hidden` — `kptr_restrict=2`: kernel pointers are *hidden*, so kallsyms is
  unusable and the base must come from inference or other leaks (e.g. dmesg),
  not the symbol table.
- `hardened` — `kptr_restrict=2`, `dmesg_restrict=1`, `perf_event_paranoid=3`:
  the realistic attacker floor, where only file-derived facts survive.

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

The guaranteed window is resolved purely from signals at or above the sound floor
and **never depends on a timing or microarchitectural side channel** — that is
what makes these numbers reproducible run to run and machine to machine. They are
therefore a floor, not a ceiling: the residual bits are the *most* KASLR entropy
that survives sound, reproducible inference, and a microarchitectural oracle
(e.g. `prefetch`) can strip more on top — to `exact` when it succeeds — on capable
hardware. Those gains are real but hardware-dependent (whether the oracle fires
varies by CPU and by run), so they are reported separately in
[Speculative narrowing](#speculative-narrowing-the-likely-window) below rather
than scored here.

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
is out of scope (see [Scope](#scope) below).

| arch | release | source | scenario | KASLR | virt residual | phys residual |
|------|---------|--------|----------|-------|---------------|---------------|
| x86_64 | 6.12.81-0-virt | alpine | default | on | exact | 6 bits |
| x86_64 | 6.12.81-0-virt | alpine | hidden | on | 1 bit | 6 bits |
| x86_64 | 6.12.81-0-virt | alpine | hardened | on | 6 bits | 6 bits |
| i686 | 6.12.81-0-lts | alpine | default | on | exact | — |
| i686 | 6.12.81-0-lts | alpine | hidden | on | exact | — |
| i686 | 6.12.81-0-lts | alpine | hardened | on | 5 bits | — |
| aarch64 | 6.12.81-0-virt | alpine | default | on | exact | 9 bits |
| aarch64 | 6.12.81-0-virt | alpine | hidden | on | 15 bits | 14 bits |
| aarch64 | 6.12.81-0-virt | alpine | hardened | on | 31 bits | 14 bits |
| armv7 | 6.12.81-0-lts | alpine | default | off | — | — |
| armv7 | 6.12.81-0-lts | alpine | hidden | off | — | — |
| armv7 | 6.12.81-0-lts | alpine | hardened | off | — | — |
| riscv64 | 6.18.35-0-lts | alpine | default | off | — | — |
| riscv64 | 6.18.35-0-lts | alpine | hidden | off | — | — |
| riscv64 | 6.18.35-0-lts | alpine | hardened | off | — | — |
| loongarch64 | 6.18.35-0-lts | alpine | default | on | exact | — |
| loongarch64 | 6.18.35-0-lts | alpine | hidden | on | 10 bits | — |
| loongarch64 | 6.18.35-0-lts | alpine | hardened | on | 14 bits | — |
| ppc64le | 6.12.81-0-lts | alpine | default | off | — | — |
| ppc64le | 6.12.81-0-lts | alpine | hidden | off | — | — |
| ppc64le | 6.12.81-0-lts | alpine | hardened | off | — | — |
| s390x | 6.12.81-0-lts | alpine | default | on | exact | 10 bits |
| s390x | 6.12.81-0-lts | alpine | hidden | on | 28 bits | 10 bits |
| s390x | 6.12.81-0-lts | alpine | hardened | on | 39 bits | 10 bits |
| x86_64 | 5.15.211 | mainline | default | on | exact | 9 bits |
| x86_64 | 5.15.211 | mainline | hidden | on | 5 bits | 9 bits |
| x86_64 | 5.15.211 | mainline | hardened | on | 9 bits | 9 bits |
| x86_64 | 6.6.144 | mainline | default | on | exact | 9 bits |
| x86_64 | 6.6.144 | mainline | hidden | on | 5 bits | 9 bits |
| x86_64 | 6.6.144 | mainline | hardened | on | 9 bits | 9 bits |
| x86_64 | 7.0.0 | mainline | default | on | exact | 9 bits |
| x86_64 | 7.0.0 | mainline | hidden | on | 5 bits | 9 bits |
| x86_64 | 7.0.0 | mainline | hardened | on | 9 bits | 9 bits |
| i686 | 5.15.211 | mainline | default | on | exact | — |
| i686 | 5.15.211 | mainline | hidden | on | 4 bits | — |
| i686 | 5.15.211 | mainline | hardened | on | 8 bits | — |
| i686 | 6.6.144 | mainline | default | on | exact | — |
| i686 | 6.6.144 | mainline | hidden | on | 4 bits | — |
| i686 | 6.6.144 | mainline | hardened | on | 8 bits | — |
| i686 | 7.0.0 | mainline | default | on | exact | — |
| i686 | 7.0.0 | mainline | hidden | on | 4 bits | — |
| i686 | 7.0.0 | mainline | hardened | on | 8 bits | — |
| aarch64 | 5.15.211 | mainline | default | on | exact | 9 bits |
| aarch64 | 5.15.211 | mainline | hidden | on | 10 bits | 14 bits |
| aarch64 | 5.15.211 | mainline | hardened | on | 31 bits | 14 bits |
| aarch64 | 6.6.144 | mainline | default | on | exact | 9 bits |
| aarch64 | 6.6.144 | mainline | hidden | on | 10 bits | 14 bits |
| aarch64 | 6.6.144 | mainline | hardened | on | 31 bits | 14 bits |
| aarch64 | 7.0.0 | mainline | default | on | exact | 9 bits |
| aarch64 | 7.0.0 | mainline | hidden | on | 10 bits | 14 bits |
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
| loongarch64 | 6.6.144 | mainline | hidden | on | 10 bits | — |
| loongarch64 | 6.6.144 | mainline | hardened | on | 14 bits | — |
| loongarch64 | 7.0.0 | mainline | default | on | exact | — |
| loongarch64 | 7.0.0 | mainline | hidden | on | 10 bits | — |
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
| s390x | 5.15.211 | mainline | hidden | on | 7 bits | 10 bits |
| s390x | 5.15.211 | mainline | hardened | on | 39 bits | 10 bits |
| s390x | 6.6.144 | mainline | default | on | exact | exact |
| s390x | 6.6.144 | mainline | hidden | on | 7 bits | 10 bits |
| s390x | 6.6.144 | mainline | hardened | on | 39 bits | 10 bits |
| s390x | 7.0.0 | mainline | default | on | exact | 10 bits |
| s390x | 7.0.0 | mainline | hidden | on | 28 bits | 10 bits |
| s390x | 7.0.0 | mainline | hardened | on | 39 bits | 10 bits |
| mips | 5.15.211 | mainline | default | on | 11 bits | — |
| mips | 5.15.211 | mainline | hidden | on | 11 bits | — |
| mips | 5.15.211 | mainline | hardened | on | 11 bits | — |
| mips | 6.6.144 | mainline | default | on | 11 bits | — |
| mips | 6.6.144 | mainline | hidden | on | 11 bits | — |
| mips | 6.6.144 | mainline | hardened | on | 11 bits | — |
| mips | 7.0.0 | mainline | default | on | 11 bits | — |
| mips | 7.0.0 | mainline | hidden | on | 11 bits | — |
| mips | 7.0.0 | mainline | hardened | on | 11 bits | — |
| mipsel | 5.15.211 | mainline | default | on | 11 bits | — |
| mipsel | 5.15.211 | mainline | hidden | on | 11 bits | — |
| mipsel | 5.15.211 | mainline | hardened | on | 11 bits | — |
| mipsel | 6.6.144 | mainline | default | on | 11 bits | — |
| mipsel | 6.6.144 | mainline | hidden | on | 11 bits | — |
| mipsel | 6.6.144 | mainline | hardened | on | 11 bits | — |
| mipsel | 7.0.0 | mainline | default | on | 11 bits | — |
| mipsel | 7.0.0 | mainline | hidden | on | 11 bits | — |
| mipsel | 7.0.0 | mainline | hardened | on | 11 bits | — |
| mips64el | 5.15.211 | mainline | default | on | 14 bits | — |
| mips64el | 5.15.211 | mainline | hidden | on | 14 bits | — |
| mips64el | 5.15.211 | mainline | hardened | on | 14 bits | — |
| mips64el | 6.6.144 | mainline | default | on | 14 bits | — |
| mips64el | 6.6.144 | mainline | hidden | on | 14 bits | — |
| mips64el | 6.6.144 | mainline | hardened | on | 14 bits | — |
| mips64el | 7.0.0 | mainline | default | on | 14 bits | — |
| mips64el | 7.0.0 | mainline | hidden | on | 14 bits | — |
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

All three profiles run unprivileged, so `default` is not a guaranteed `exact`:
it pins the virtual base only where an unprivileged reader can still see
kallsyms. `kptr_restrict=0` exposes kallsyms on most arches, but some kernels
gate the symbol values behind `CAP_SYSLOG` even then, leaving e.g. `mips` at its
inference bound. The `phys residual` reflects the same reality — the physical
image base is read from `/proc/iomem`, whose addresses the kernel zeroes for a
non-root reader regardless of `kptr_restrict`, so several decoupled arches show
`<n> bits` on the physical axis under `default` where a *root* reader would have
pinned it exact (`s390x` still pins exact on some lines because another fact
resolves it).

Under `hidden`/`hardened`, the window widens further: `kptr_restrict=2` removes
kallsyms entirely, so the base stays `exact` only where some other unprivileged
leak or fact still resolves it. `hardened` strips more of those sources than
`hidden` (perf and dmesg go too), so some cells that pin under `hidden` widen
under `hardened`. The bits are how much of the KASLR slot the surviving facts
leave.

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
| x86_64 | 6.12.81-0-virt | alpine | hidden | 1 bit | exact | `perf_event_open` | parsed | yes |
| x86_64 | 5.15.211 | mainline | hidden | 5 bits | exact | `perf_event_open` | parsed | yes |
| x86_64 | 6.6.144 | mainline | hidden | 5 bits | exact | `perf_event_open` | parsed | yes |
| x86_64 | 7.0.0 | mainline | hidden | 5 bits | exact | `perf_event_open` | parsed | yes |
| i686 | 5.15.211 | mainline | hidden | 4 bits | exact | `perf_event_open` | parsed | yes |
| i686 | 6.6.144 | mainline | hidden | 4 bits | exact | `perf_event_open` | parsed | yes |
| i686 | 7.0.0 | mainline | hidden | 4 bits | exact | `perf_event_open` | parsed | yes |
| ppc32 | 5.15.211 | mainline | hardened | 15 bits | 11 bits | `proc_zoneinfo + sysfs_devicetree_memory` | parsed | yes |
| ppc32 | 6.6.144 | mainline | hardened | 15 bits | 11 bits | `proc_zoneinfo + sysfs_devicetree_memory` | parsed | yes |
| ppc32 | 7.0.0 | mainline | hardened | 15 bits | 11 bits | `proc_zoneinfo + sysfs_devicetree_memory` | parsed | yes |

The split follows the reader profile and the arch's surviving sub-floor signals.
Under `hidden`, `perf_event_open` is still permitted, so on `x86_64` and `i686`
it leaks a symbol pointer — a parsed best-guess base — that collapses the likely
window to `exact` (on Alpine `x86_64` this narrows the 1-bit guaranteed window
the rest of the way). Under `hardened`, `perf_event_paranoid=3` blocks it, so the
likely window collapses back onto guaranteed unless another surviving signal
narrows it. `ppc32` is the one such case here: under `hardened` its narrowing is a
memory-map heuristic from `/proc/zoneinfo` and the device-tree, trimming 15 bits
to 11. Every other KASLR-on cell leaves likely equal to guaranteed.

No cell appears under `default`, and that is not a gap: with `kptr_restrict=0` the
sound `proc_kallsyms` pin already resolves the *guaranteed* window to `exact`, so
the likely window has nothing left to narrow and the engine emits no divergence.
An absent row means the base was already recovered soundly, not that a
speculative signal was missing — `perf_event_open` runs under `default` too, it is
simply redundant there. A row therefore shows up only where a stricter profile has
removed the sound pin and a sub-floor signal fills the gap; it never means a
stricter profile recovered *more* than a looser one. Absolute recovery stays
monotonic (`default` ≥ `hidden` ≥ `hardened`) — read it off the guaranteed matrix
above, not this table.

All ten rows are `parsed` — deterministic leaks and a memory-map heuristic, not
timing — and every likely window on this run contained the truth (10 / 10). A
likely miss is never a soundness violation regardless: the gate is on guaranteed,
which contains the truth in every cell.

Timing side-channel narrowings are excluded from this table by default — but
they work, and they materially improve recovery. The likely window can also be
narrowed by a microarchitectural side channel: a cache or speculation timing
oracle such as `prefetch` or `entrybleed` that survives even
`perf_event_paranoid=3`, pinning the base where no parsed signal can. On the run
that generated this table, `prefetch` narrowed the `x86_64` `hardened` cell (7.0
mainline) from its 9-bit guaranteed window all the way to `exact` — a full KASLR
defeat on the profile that strips every file-derived leak. That result is omitted here **only** because a
timing oracle's success is a function of the host CPU and varies from run to run,
even on the same machine, so publishing it would make this table irreproducible —
not because the technique fails. On capable hardware these side channels routinely
strip more entropy than the guaranteed matrix shows. They are validated separately
(see [Scope](#scope)); `tests/vm/run spec-table --with-timing` regenerates the
table with them included.

## 3. Offline, over a captured corpus

The repository ships captured snapshots from real kernels, so the engine can be
exercised across hardware that is not otherwise available:

```sh
make check            # unit + integration tests (the per-rule checks)
tests/replay          # run kasld over every captured fixture (structural)
make test-fixtures    # assert the resolved window contains the truth, per capture
```

`tests/replay` confirms KASLD parses and runs cleanly on each snapshot;
`make check` runs the per-rule unit tests, including the soundness checks.
`make test-fixtures` (`tests/validate-fixtures`) is the boot-free soundness gate:
it runs `extra/validate-bundle` over every captured kernel that carries ground
truth and asserts `truth ∈ [min, max]`, catching the "window excludes the real
base" class of bug without a VM. Captures with no recorded truth report `N/A`
rather than pass. The corpus spans 10 architecture families (Alpine, Debian,
Ubuntu/Raspbian) and kernels from 4.19 to 7.0:

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

These are limits on what the checks here *verify*. For what a KASLD result means
when it is run against a target — in particular why a failure to recover the base
is not evidence the system is secure — see [limitations.md](limitations.md).
