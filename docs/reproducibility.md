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
can. Every profile is a declared sysctl vector — never a "default-config"
assumption; the one privileged step is the per-boot ground-truth capture the
check compares against.

`default` is each kernel's *own* compile-time sysctl posture, read back at boot
and left as booted: `kptr_restrict=0` and `perf_event_paranoid=2` upstream, with
`dmesg_restrict` taking whatever the kernel `.config` sets (`0` on the mainline
builds, `1` on Alpine). The other four profiles each move exactly one axis away
from that booted baseline.

- `default` — the booted compile-time defaults. `kptr_restrict=0` alone does
  *not* expose symbol values: at the upstream `perf_event_paranoid=2`,
  `/proc/kallsyms` zeroes every address for an unprivileged reader, because
  `kallsyms_show_value()` requires `perf_event_paranoid<=1` *or* `CAP_SYSLOG`
  (generic across architectures). On a stock kernel the symbol table therefore
  yields nothing, and the base comes from sound inference alone.
- `kptr-hidden` — `default` plus `kptr_restrict=2`: kernel pointers are *hidden*.
  On a stock kernel this changes little over `default` — perf already gates
  kallsyms — so it isolates the effect of `kptr_restrict` by itself.
- `perf-open` — `default` plus `perf_event_paranoid=0`. Dropping perf below 1
  unlocks two independent sound signals at once: `/proc/kallsyms` now shows real
  addresses, and `perf_event_open` text-poke records leak a symbol pointer.
  Either pins the base exactly.
- `dmesg-open` — `default` plus `dmesg_restrict=0`: the world-readable ring
  buffer. This differs from `default` only on kernels that ship
  `dmesg_restrict=1` (Alpine); on the mainline builds dmesg is already open.
- `hardened` — `kptr_restrict=2`, `dmesg_restrict=1`, `perf_event_paranoid=3`:
  the realistic attacker floor, where only file-derived facts survive.

Under the tighter profiles the window may widen but must still contain the truth.
See [tests/vm/README.md](../tests/vm/README.md) for the full arch list and options.

Every architecture is booted on mainline kernel.org kernels — the LTS lines 5.15
and 6.6 and current 7.0 — cross-built from pinned source by `tests/vm/build-kernel`
(a stock upstream defconfig plus fixed config overlays: endianness, devtmpfs, and
text KASLR for riscv64 and ppc32). Eight of
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
varies by CPU and by run), so they are discussed in
[Speculative narrowing](#speculative-narrowing-the-likely-window) below and
listed by `tests/vm/run spec-table --with-timing` — but, for the same
reproducibility reason, kept out of the default table there too, not scored here.

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
- `—` — KASLR is off, so there is no randomization to defeat (both columns).
- `coupled` (`phys residual` only) — the physical image base is not randomized
  independently of the virtual text base; it is a fixed projection of it
  (`phys = virt - <arch constant>`), so recovering the virtual base already
  determines the physical one and there is no separate physical quantity to
  score. This is every *coupled* architecture: x86-32, arm32, MIPS, PPC,
  RISC-V 32, LoongArch. The `phys residual` column carries an independent
  `exact` / `<n> bits` result only on the *decoupled* arches — x86-64, arm64,
  riscv64, s390 — where the kernel image is placed independently in physical
  memory. A coupled arch is thus distinguishable from a KASLR-off row (`—`) and
  from a decoupled arch (a bit count) at a glance.

Soundness is gated on both axes: a cell whose physical window excludes the true
physical base is withheld exactly like a virtual violation, never published.

The axes are architecture × kernel line × reader profile: each architecture is
booted on the mainline LTS lines 5.15 and 6.6 and on current 7.0 — plus an Alpine
distro kernel where a port exists — under each of the five reader profiles
(`default`, `kptr-hidden`, `perf-open`, `dmesg-open`, `hardened`). An architecture
predating a line carries no cell there (LoongArch, mainlined in 6.1, has no 5.15
row). A kernel-config axis is out of scope (see [Scope](#scope) below).

| arch | release | source | scenario | KASLR | virt residual | phys residual |
|------|---------|--------|----------|-------|---------------|---------------|
| aarch64 | 6.12.81-0-virt | alpine | default | on | 31 bits | 14 bits |
| aarch64 | 6.12.81-0-virt | alpine | kptr-hidden | on | 31 bits | 14 bits |
| aarch64 | 6.12.81-0-virt | alpine | perf-open | on | exact | 9 bits |
| aarch64 | 6.12.81-0-virt | alpine | dmesg-open | on | 31 bits | 14 bits |
| aarch64 | 6.12.81-0-virt | alpine | hardened | on | 31 bits | 14 bits |
| aarch64 | 5.15.211 | mainline | default | on | 31 bits | 14 bits |
| aarch64 | 5.15.211 | mainline | kptr-hidden | on | 31 bits | 14 bits |
| aarch64 | 5.15.211 | mainline | perf-open | on | exact | 9 bits |
| aarch64 | 5.15.211 | mainline | dmesg-open | on | 31 bits | 14 bits |
| aarch64 | 5.15.211 | mainline | hardened | on | 31 bits | 14 bits |
| aarch64 | 6.6.144 | mainline | default | on | 31 bits | 14 bits |
| aarch64 | 6.6.144 | mainline | kptr-hidden | on | 31 bits | 14 bits |
| aarch64 | 6.6.144 | mainline | perf-open | on | exact | 9 bits |
| aarch64 | 6.6.144 | mainline | dmesg-open | on | 31 bits | 14 bits |
| aarch64 | 6.6.144 | mainline | hardened | on | 31 bits | 14 bits |
| aarch64 | 7.0.0 | mainline | default | on | 31 bits | 14 bits |
| aarch64 | 7.0.0 | mainline | kptr-hidden | on | 31 bits | 14 bits |
| aarch64 | 7.0.0 | mainline | perf-open | on | exact | 9 bits |
| aarch64 | 7.0.0 | mainline | dmesg-open | on | 31 bits | 14 bits |
| aarch64 | 7.0.0 | mainline | hardened | on | 31 bits | 14 bits |
| armv7 | 6.12.81-0-lts | alpine | default | off | — | — |
| armv7 | 6.12.81-0-lts | alpine | kptr-hidden | off | — | — |
| armv7 | 6.12.81-0-lts | alpine | perf-open | off | — | — |
| armv7 | 6.12.81-0-lts | alpine | dmesg-open | off | — | — |
| armv7 | 6.12.81-0-lts | alpine | hardened | off | — | — |
| armv7 | 5.15.211 | mainline | default | off | — | — |
| armv7 | 5.15.211 | mainline | kptr-hidden | off | — | — |
| armv7 | 5.15.211 | mainline | perf-open | off | — | — |
| armv7 | 5.15.211 | mainline | dmesg-open | off | — | — |
| armv7 | 5.15.211 | mainline | hardened | off | — | — |
| armv7 | 6.6.144 | mainline | default | off | — | — |
| armv7 | 6.6.144 | mainline | kptr-hidden | off | — | — |
| armv7 | 6.6.144 | mainline | perf-open | off | — | — |
| armv7 | 6.6.144 | mainline | dmesg-open | off | — | — |
| armv7 | 6.6.144 | mainline | hardened | off | — | — |
| armv7 | 7.0.0 | mainline | default | off | — | — |
| armv7 | 7.0.0 | mainline | kptr-hidden | off | — | — |
| armv7 | 7.0.0 | mainline | perf-open | off | — | — |
| armv7 | 7.0.0 | mainline | dmesg-open | off | — | — |
| armv7 | 7.0.0 | mainline | hardened | off | — | — |
| i686 | 6.12.81-0-lts | alpine | default | on | 5 bits | coupled |
| i686 | 6.12.81-0-lts | alpine | kptr-hidden | on | 5 bits | coupled |
| i686 | 6.12.81-0-lts | alpine | perf-open | on | exact | coupled |
| i686 | 6.12.81-0-lts | alpine | dmesg-open | on | 5 bits | coupled |
| i686 | 6.12.81-0-lts | alpine | hardened | on | 5 bits | coupled |
| i686 | 5.15.211 | mainline | default | on | 8 bits | coupled |
| i686 | 5.15.211 | mainline | kptr-hidden | on | 8 bits | coupled |
| i686 | 5.15.211 | mainline | perf-open | on | exact | coupled |
| i686 | 5.15.211 | mainline | dmesg-open | on | 8 bits | coupled |
| i686 | 5.15.211 | mainline | hardened | on | 8 bits | coupled |
| i686 | 6.6.144 | mainline | default | on | 8 bits | coupled |
| i686 | 6.6.144 | mainline | kptr-hidden | on | 8 bits | coupled |
| i686 | 6.6.144 | mainline | perf-open | on | exact | coupled |
| i686 | 6.6.144 | mainline | dmesg-open | on | 8 bits | coupled |
| i686 | 6.6.144 | mainline | hardened | on | 8 bits | coupled |
| i686 | 7.0.0 | mainline | default | on | 8 bits | coupled |
| i686 | 7.0.0 | mainline | kptr-hidden | on | 8 bits | coupled |
| i686 | 7.0.0 | mainline | perf-open | on | exact | coupled |
| i686 | 7.0.0 | mainline | dmesg-open | on | 8 bits | coupled |
| i686 | 7.0.0 | mainline | hardened | on | 8 bits | coupled |
| loongarch64 | 6.18.35-0-lts | alpine | default | on | 14 bits | coupled |
| loongarch64 | 6.18.35-0-lts | alpine | kptr-hidden | on | 14 bits | coupled |
| loongarch64 | 6.18.35-0-lts | alpine | perf-open | on | exact | coupled |
| loongarch64 | 6.18.35-0-lts | alpine | dmesg-open | on | 14 bits | coupled |
| loongarch64 | 6.18.35-0-lts | alpine | hardened | on | 14 bits | coupled |
| loongarch64 | 6.6.144 | mainline | default | on | 14 bits | coupled |
| loongarch64 | 6.6.144 | mainline | kptr-hidden | on | 14 bits | coupled |
| loongarch64 | 6.6.144 | mainline | perf-open | on | exact | coupled |
| loongarch64 | 6.6.144 | mainline | dmesg-open | on | 14 bits | coupled |
| loongarch64 | 6.6.144 | mainline | hardened | on | 14 bits | coupled |
| loongarch64 | 7.0.0 | mainline | default | on | 14 bits | coupled |
| loongarch64 | 7.0.0 | mainline | kptr-hidden | on | 14 bits | coupled |
| loongarch64 | 7.0.0 | mainline | perf-open | on | exact | coupled |
| loongarch64 | 7.0.0 | mainline | dmesg-open | on | 14 bits | coupled |
| loongarch64 | 7.0.0 | mainline | hardened | on | 14 bits | coupled |
| mips | 5.15.211 | mainline | default | on | 11 bits | coupled |
| mips | 5.15.211 | mainline | kptr-hidden | on | 11 bits | coupled |
| mips | 5.15.211 | mainline | perf-open | on | 11 bits | coupled |
| mips | 5.15.211 | mainline | dmesg-open | on | 11 bits | coupled |
| mips | 5.15.211 | mainline | hardened | on | 11 bits | coupled |
| mips | 6.6.144 | mainline | default | on | 11 bits | coupled |
| mips | 6.6.144 | mainline | kptr-hidden | on | 11 bits | coupled |
| mips | 6.6.144 | mainline | perf-open | on | 11 bits | coupled |
| mips | 6.6.144 | mainline | dmesg-open | on | 11 bits | coupled |
| mips | 6.6.144 | mainline | hardened | on | 11 bits | coupled |
| mips | 7.0.0 | mainline | default | on | 11 bits | coupled |
| mips | 7.0.0 | mainline | kptr-hidden | on | 11 bits | coupled |
| mips | 7.0.0 | mainline | perf-open | on | 11 bits | coupled |
| mips | 7.0.0 | mainline | dmesg-open | on | 11 bits | coupled |
| mips | 7.0.0 | mainline | hardened | on | 11 bits | coupled |
| mips64el | 5.15.211 | mainline | default | on | 14 bits | coupled |
| mips64el | 5.15.211 | mainline | kptr-hidden | on | 14 bits | coupled |
| mips64el | 5.15.211 | mainline | perf-open | on | 14 bits | coupled |
| mips64el | 5.15.211 | mainline | dmesg-open | on | 14 bits | coupled |
| mips64el | 5.15.211 | mainline | hardened | on | 14 bits | coupled |
| mips64el | 6.6.144 | mainline | default | on | 14 bits | coupled |
| mips64el | 6.6.144 | mainline | kptr-hidden | on | 14 bits | coupled |
| mips64el | 6.6.144 | mainline | perf-open | on | 14 bits | coupled |
| mips64el | 6.6.144 | mainline | dmesg-open | on | 14 bits | coupled |
| mips64el | 6.6.144 | mainline | hardened | on | 14 bits | coupled |
| mips64el | 7.0.0 | mainline | default | on | 14 bits | coupled |
| mips64el | 7.0.0 | mainline | kptr-hidden | on | 14 bits | coupled |
| mips64el | 7.0.0 | mainline | perf-open | on | 14 bits | coupled |
| mips64el | 7.0.0 | mainline | dmesg-open | on | 14 bits | coupled |
| mips64el | 7.0.0 | mainline | hardened | on | 14 bits | coupled |
| mipsel | 5.15.211 | mainline | default | on | 11 bits | coupled |
| mipsel | 5.15.211 | mainline | kptr-hidden | on | 11 bits | coupled |
| mipsel | 5.15.211 | mainline | perf-open | on | 11 bits | coupled |
| mipsel | 5.15.211 | mainline | dmesg-open | on | 11 bits | coupled |
| mipsel | 5.15.211 | mainline | hardened | on | 11 bits | coupled |
| mipsel | 6.6.144 | mainline | default | on | 11 bits | coupled |
| mipsel | 6.6.144 | mainline | kptr-hidden | on | 11 bits | coupled |
| mipsel | 6.6.144 | mainline | perf-open | on | 11 bits | coupled |
| mipsel | 6.6.144 | mainline | dmesg-open | on | 11 bits | coupled |
| mipsel | 6.6.144 | mainline | hardened | on | 11 bits | coupled |
| mipsel | 7.0.0 | mainline | default | on | 11 bits | coupled |
| mipsel | 7.0.0 | mainline | kptr-hidden | on | 11 bits | coupled |
| mipsel | 7.0.0 | mainline | perf-open | on | 11 bits | coupled |
| mipsel | 7.0.0 | mainline | dmesg-open | on | 11 bits | coupled |
| mipsel | 7.0.0 | mainline | hardened | on | 11 bits | coupled |
| powerpc64 | 5.15.211 | mainline | default | off | — | — |
| powerpc64 | 5.15.211 | mainline | kptr-hidden | off | — | — |
| powerpc64 | 5.15.211 | mainline | perf-open | off | — | — |
| powerpc64 | 5.15.211 | mainline | dmesg-open | off | — | — |
| powerpc64 | 5.15.211 | mainline | hardened | off | — | — |
| powerpc64 | 6.6.144 | mainline | default | off | — | — |
| powerpc64 | 6.6.144 | mainline | kptr-hidden | off | — | — |
| powerpc64 | 6.6.144 | mainline | perf-open | off | — | — |
| powerpc64 | 6.6.144 | mainline | dmesg-open | off | — | — |
| powerpc64 | 6.6.144 | mainline | hardened | off | — | — |
| powerpc64 | 7.0.0 | mainline | default | off | — | — |
| powerpc64 | 7.0.0 | mainline | kptr-hidden | off | — | — |
| powerpc64 | 7.0.0 | mainline | perf-open | off | — | — |
| powerpc64 | 7.0.0 | mainline | dmesg-open | off | — | — |
| powerpc64 | 7.0.0 | mainline | hardened | off | — | — |
| ppc32 | 5.15.211 | mainline | default | on | 14 bits | coupled |
| ppc32 | 5.15.211 | mainline | kptr-hidden | on | 14 bits | coupled |
| ppc32 | 5.15.211 | mainline | perf-open | on | exact | coupled |
| ppc32 | 5.15.211 | mainline | dmesg-open | on | 14 bits | coupled |
| ppc32 | 5.15.211 | mainline | hardened | on | 14 bits | coupled |
| ppc32 | 6.6.144 | mainline | default | on | 14 bits | coupled |
| ppc32 | 6.6.144 | mainline | kptr-hidden | on | 14 bits | coupled |
| ppc32 | 6.6.144 | mainline | perf-open | on | exact | coupled |
| ppc32 | 6.6.144 | mainline | dmesg-open | on | 13 bits | coupled |
| ppc32 | 6.6.144 | mainline | hardened | on | 14 bits | coupled |
| ppc32 | 7.0.0 | mainline | default | on | 11 bits | coupled |
| ppc32 | 7.0.0 | mainline | kptr-hidden | on | 14 bits | coupled |
| ppc32 | 7.0.0 | mainline | perf-open | on | exact | coupled |
| ppc32 | 7.0.0 | mainline | dmesg-open | on | 14 bits | coupled |
| ppc32 | 7.0.0 | mainline | hardened | on | 12 bits | coupled |
| ppc64le | 6.12.81-0-lts | alpine | default | off | — | — |
| ppc64le | 6.12.81-0-lts | alpine | kptr-hidden | off | — | — |
| ppc64le | 6.12.81-0-lts | alpine | perf-open | off | — | — |
| ppc64le | 6.12.81-0-lts | alpine | dmesg-open | off | — | — |
| ppc64le | 6.12.81-0-lts | alpine | hardened | off | — | — |
| ppc64le | 5.15.211 | mainline | default | off | — | — |
| ppc64le | 5.15.211 | mainline | kptr-hidden | off | — | — |
| ppc64le | 5.15.211 | mainline | perf-open | off | — | — |
| ppc64le | 5.15.211 | mainline | dmesg-open | off | — | — |
| ppc64le | 5.15.211 | mainline | hardened | off | — | — |
| ppc64le | 6.6.144 | mainline | default | off | — | — |
| ppc64le | 6.6.144 | mainline | kptr-hidden | off | — | — |
| ppc64le | 6.6.144 | mainline | perf-open | off | — | — |
| ppc64le | 6.6.144 | mainline | dmesg-open | off | — | — |
| ppc64le | 6.6.144 | mainline | hardened | off | — | — |
| ppc64le | 7.0.0 | mainline | default | off | — | — |
| ppc64le | 7.0.0 | mainline | kptr-hidden | off | — | — |
| ppc64le | 7.0.0 | mainline | perf-open | off | — | — |
| ppc64le | 7.0.0 | mainline | dmesg-open | off | — | — |
| ppc64le | 7.0.0 | mainline | hardened | off | — | — |
| riscv32 | 5.15.211 | mainline | default | off | — | — |
| riscv32 | 5.15.211 | mainline | kptr-hidden | off | — | — |
| riscv32 | 5.15.211 | mainline | perf-open | off | — | — |
| riscv32 | 5.15.211 | mainline | dmesg-open | off | — | — |
| riscv32 | 5.15.211 | mainline | hardened | off | — | — |
| riscv32 | 6.6.144 | mainline | default | off | — | — |
| riscv32 | 6.6.144 | mainline | kptr-hidden | off | — | — |
| riscv32 | 6.6.144 | mainline | perf-open | off | — | — |
| riscv32 | 6.6.144 | mainline | dmesg-open | off | — | — |
| riscv32 | 6.6.144 | mainline | hardened | off | — | — |
| riscv32 | 7.0.0 | mainline | default | off | — | — |
| riscv32 | 7.0.0 | mainline | kptr-hidden | off | — | — |
| riscv32 | 7.0.0 | mainline | perf-open | off | — | — |
| riscv32 | 7.0.0 | mainline | dmesg-open | off | — | — |
| riscv32 | 7.0.0 | mainline | hardened | off | — | — |
| riscv64 | 6.18.35-0-lts | alpine | default | off | — | — |
| riscv64 | 6.18.35-0-lts | alpine | kptr-hidden | off | — | — |
| riscv64 | 6.18.35-0-lts | alpine | perf-open | off | — | — |
| riscv64 | 6.18.35-0-lts | alpine | dmesg-open | off | — | — |
| riscv64 | 6.18.35-0-lts | alpine | hardened | off | — | — |
| riscv64 | 5.15.211 | mainline | default | off | — | — |
| riscv64 | 5.15.211 | mainline | kptr-hidden | off | — | — |
| riscv64 | 5.15.211 | mainline | perf-open | off | — | — |
| riscv64 | 5.15.211 | mainline | dmesg-open | off | — | — |
| riscv64 | 5.15.211 | mainline | hardened | off | — | — |
| riscv64 | 6.6.144 | mainline | default | on | exact | 9 bits |
| riscv64 | 6.6.144 | mainline | kptr-hidden | on | exact | 9 bits |
| riscv64 | 6.6.144 | mainline | perf-open | on | exact | 9 bits |
| riscv64 | 6.6.144 | mainline | dmesg-open | on | exact | 9 bits |
| riscv64 | 6.6.144 | mainline | hardened | on | 16 bits | 9 bits |
| riscv64 | 7.0.0 | mainline | default | on | 16 bits | 9 bits |
| riscv64 | 7.0.0 | mainline | kptr-hidden | on | 16 bits | 9 bits |
| riscv64 | 7.0.0 | mainline | perf-open | on | exact | 9 bits |
| riscv64 | 7.0.0 | mainline | dmesg-open | on | 16 bits | 9 bits |
| riscv64 | 7.0.0 | mainline | hardened | on | 16 bits | 9 bits |
| s390x | 6.12.81-0-lts | alpine | default | on | 39 bits | 10 bits |
| s390x | 6.12.81-0-lts | alpine | kptr-hidden | on | 39 bits | 10 bits |
| s390x | 6.12.81-0-lts | alpine | perf-open | on | exact | 10 bits |
| s390x | 6.12.81-0-lts | alpine | dmesg-open | on | 39 bits | 10 bits |
| s390x | 6.12.81-0-lts | alpine | hardened | on | 39 bits | 10 bits |
| s390x | 5.15.211 | mainline | default | on | 39 bits | 10 bits |
| s390x | 5.15.211 | mainline | kptr-hidden | on | 39 bits | 10 bits |
| s390x | 5.15.211 | mainline | perf-open | on | exact | exact |
| s390x | 5.15.211 | mainline | dmesg-open | on | 39 bits | 10 bits |
| s390x | 5.15.211 | mainline | hardened | on | 39 bits | 10 bits |
| s390x | 6.6.144 | mainline | default | on | 39 bits | 10 bits |
| s390x | 6.6.144 | mainline | kptr-hidden | on | 39 bits | 10 bits |
| s390x | 6.6.144 | mainline | perf-open | on | exact | exact |
| s390x | 6.6.144 | mainline | dmesg-open | on | 39 bits | 10 bits |
| s390x | 6.6.144 | mainline | hardened | on | 39 bits | 10 bits |
| s390x | 7.0.0 | mainline | default | on | 39 bits | 10 bits |
| s390x | 7.0.0 | mainline | kptr-hidden | on | 39 bits | 10 bits |
| s390x | 7.0.0 | mainline | perf-open | on | exact | 10 bits |
| s390x | 7.0.0 | mainline | dmesg-open | on | 39 bits | 10 bits |
| s390x | 7.0.0 | mainline | hardened | on | 39 bits | 10 bits |
| x86_64 | 6.12.81-0-virt | alpine | default | on | 6 bits | 6 bits |
| x86_64 | 6.12.81-0-virt | alpine | kptr-hidden | on | 6 bits | 6 bits |
| x86_64 | 6.12.81-0-virt | alpine | perf-open | on | exact | 6 bits |
| x86_64 | 6.12.81-0-virt | alpine | dmesg-open | on | 6 bits | 6 bits |
| x86_64 | 6.12.81-0-virt | alpine | hardened | on | 6 bits | 6 bits |
| x86_64 | 5.15.211 | mainline | default | on | 9 bits | 9 bits |
| x86_64 | 5.15.211 | mainline | kptr-hidden | on | 9 bits | 9 bits |
| x86_64 | 5.15.211 | mainline | perf-open | on | exact | 9 bits |
| x86_64 | 5.15.211 | mainline | dmesg-open | on | 9 bits | 9 bits |
| x86_64 | 5.15.211 | mainline | hardened | on | 9 bits | 9 bits |
| x86_64 | 6.6.144 | mainline | default | on | 9 bits | 9 bits |
| x86_64 | 6.6.144 | mainline | kptr-hidden | on | 9 bits | 9 bits |
| x86_64 | 6.6.144 | mainline | perf-open | on | exact | 9 bits |
| x86_64 | 6.6.144 | mainline | dmesg-open | on | 9 bits | 9 bits |
| x86_64 | 6.6.144 | mainline | hardened | on | 9 bits | 9 bits |
| x86_64 | 7.0.0 | mainline | default | on | 9 bits | 9 bits |
| x86_64 | 7.0.0 | mainline | kptr-hidden | on | 9 bits | 9 bits |
| x86_64 | 7.0.0 | mainline | perf-open | on | exact | 9 bits |
| x86_64 | 7.0.0 | mainline | dmesg-open | on | 9 bits | 9 bits |
| x86_64 | 7.0.0 | mainline | hardened | on | 9 bits | 9 bits |

All five profiles run unprivileged, and on a stock kernel `default` is *not*
`exact`: at the upstream
`perf_event_paranoid=2`, `/proc/kallsyms` is zeroed even with `kptr_restrict=0`
(`kallsyms_show_value()` needs `perf_event_paranoid<=1` or `CAP_SYSLOG`), so the
symbol table contributes nothing and the virtual base comes from sound inference
alone — e.g. 6 bits on Alpine `x86_64`, 9 bits on mainline `x86_64`, 5 bits on
`i686`. `kptr-hidden` adds `kptr_restrict=2` on top and lands on the same
numbers, because perf already gated kallsyms: raising `kptr_restrict` removes a
source that was already dark.

`perf-open` is the profile that recovers `exact` on every KASLR-on cell. Dropping
`perf_event_paranoid` to 0 simultaneously un-zeroes `/proc/kallsyms` (a sound
`proc_kallsyms` pin) and permits the `perf_event_open` text-poke leak — either
alone pins the virtual base. The recovery is thus a *perf* relaxation, not a
`kptr_restrict` one: a stock `kptr_restrict=0` kernel is not derandomized by the
symbol table until perf is also relaxed. `dmesg-open` re-opens the ring buffer
where a kernel shipped `dmesg_restrict=1` (Alpine); across this corpus that
exposed no additional kernel-text landmark, so its guaranteed windows match
`default`. `hardened` (`kptr_restrict=2`, `dmesg_restrict=1`,
`perf_event_paranoid=3`) strips every relaxable source and is the widest column;
its bits are what sound inference bounds with no leak at all.

The `phys residual` moves independently: the physical image base is read from
`/proc/iomem`, whose `Kernel code` addresses the kernel zeroes for a non-root
reader regardless of `kptr_restrict` *or* `perf_event_paranoid`. So on most
decoupled arches (x86-64, arm64, riscv64) the physical axis stays at `<n> bits`
under *every* profile, including `perf-open`: the perf unlock recovers the
virtual text base but not the physical one, which a *root* reader would have
pinned exact. s390 is the exception on some lines — a sound source unlocked with
perf resolves its physical base to `exact` too (5.15/6.6 mainline), while on the
others (7.0 mainline, Alpine) it stays at its bounded `10 bits`.

Several architectures show KASLR `off`: under the default qemu machine they
receive no KASLR seed (or the port has no text KASLR), so the kernel boots
unrandomized. `residual` is `—` for every `off` row — there is
no randomness to strip — but KASLD still bounds, and on seedless arches pins, the
fixed base soundly via the disabled-base path (from arch constants plus the
world-readable device-tree). It simply is not a KASLR-defeat result, so the
column does not score it.

riscv64 is the mixed case. Its text KASLR (`RANDOMIZE_BASE`) needs both a kernel
built for it *and* a boot-supplied seed, and qemu's `virt` machine provides
neither by default — hence the seedless `off` rows above. The mainline 6.6 and
7.0 cells are therefore built with `RANDOMIZE_BASE` and booted with a fresh
per-boot `kaslr-seed` spliced into the device tree, so they randomize like the
other 64-bit arches: the base moves every boot and the truth stays inside the
window. The 5.15 cell predates riscv KASLR (added in 5.18) and the Alpine kernel
is not built with it, so both stay honestly `off`. The two enabled lines differ
in recovery for a config reason: 6.6's stock `defconfig` sets `CONFIG_DEBUG_VM`,
so `mem_init()` prints a kernel-layout line that pins `_text` from readable dmesg
(defeated only under `hardened`, which restricts dmesg); 7.0 drops `DEBUG_VM`,
leaving inference to bound the base to 16 bits until `perf-open` unlocks the
symbol table for an exact pin.

### Speculative narrowing (the likely window)

`residual` above is the **guaranteed** window — resolved only from signals at or
above the sound floor, and gate-checked to contain the truth. The engine also
resolves a **likely** window: the guaranteed window narrowed further by sub-floor
signals (timing side-channels, a single leaked pointer, config defaults). It is a
best-guess, always a subset of guaranteed, and — unlike guaranteed — it is *not*
gated to contain the truth. It surfaces in `-j` JSON as the `likely` /
`likely_physical` objects, emitted only when strictly tighter than guaranteed.

`tests/vm/run spec-table` renders a table of the cells where the likely window
beats guaranteed, but by default lists only *reproducible* narrowings:
deterministic `parsed` signals (a file, a leaked pointer, a config default) that
beat the sound floor the same way on every run. On this run there are none, so it
reports "no reproducible speculative narrowing" and emits no rows — at the
reproducible level the likely window equals the guaranteed window on every cell.

That is the expected outcome once the profiles and rules are correct. Where a
perf or kallsyms signal exists it is a *sound* pin, so it resolves the
**guaranteed** window under `perf-open` (to `exact`), never the likely one — a
sound signal has nothing left to narrow. And the memory-map heuristics that bound
RAM from world-readable facts (`/proc/zoneinfo` spans, the device-tree `memory`
node, dmesg zone lines) never tighten past the placement-tracking guaranteed
ceiling on any arch here, so they add no `likely`-only row either. Every parsed
signal thus lands in the guaranteed matrix or contributes nothing. The only cells
whose likely window beats guaranteed are narrowed by a *timing* side channel,
excluded by default for reproducibility (below).

Absolute recovery is monotonic in how much the profile relaxes: `perf-open`
recovers the most, `hardened` the least, with `default`/`kptr-hidden`/`dmesg-open`
between — read that off the guaranteed matrix above, not the likely window.

**Timing side-channel narrowings are excluded by default** — 16 would appear on
this run, every one an x86_64 cell narrowed by `prefetch` (both the Alpine and
mainline kernels, across the non-`perf-open` profiles) — but they work, and they
materially improve recovery. The likely window can also be narrowed by a
microarchitectural side channel: a cache or speculation timing oracle such as
`prefetch` or `entrybleed` that survives even `perf_event_paranoid=3`, pinning the
base where no parsed signal can. On this run `prefetch` narrowed the `x86_64`
`hardened` cell (7.0 mainline) from its 9-bit guaranteed window all the way to
`exact` — a full KASLR defeat on the profile that strips every file-derived leak.
They are omitted **only** because a timing oracle's success is a function of the
host CPU and varies from run to run, even on the same machine, so including them
would make the results irreproducible — not because the technique fails. On
capable hardware these side channels routinely strip more entropy than the
guaranteed matrix shows. They are validated separately (see [Scope](#scope));
`tests/vm/run spec-table --with-timing` lists them, populating the
otherwise-empty table.

For illustration, that populated table from the capable host that generated this
matrix — `prefetch` collapses every x86_64 cell to `exact`, `hardened` included:

| arch | release | source | scenario | guaranteed | likely | via | method | truth ∈ likely |
|------|---------|--------|----------|------------|--------|-----|--------|:---:|
| x86_64 | 6.12.81-0-virt | alpine | default | 6 bits | exact | `prefetch` | timing | yes |
| x86_64 | 6.12.81-0-virt | alpine | kptr-hidden | 6 bits | exact | `prefetch` | timing | yes |
| x86_64 | 6.12.81-0-virt | alpine | dmesg-open | 6 bits | exact | `prefetch` | timing | yes |
| x86_64 | 6.12.81-0-virt | alpine | hardened | 6 bits | exact | `prefetch` | timing | yes |
| x86_64 | 5.15.211 | mainline | default | 9 bits | exact | `prefetch` | timing | yes |
| x86_64 | 5.15.211 | mainline | kptr-hidden | 9 bits | exact | `prefetch` | timing | yes |
| x86_64 | 5.15.211 | mainline | dmesg-open | 9 bits | exact | `prefetch` | timing | yes |
| x86_64 | 5.15.211 | mainline | hardened | 9 bits | exact | `prefetch` | timing | yes |
| x86_64 | 6.6.144 | mainline | default | 9 bits | exact | `prefetch` | timing | yes |
| x86_64 | 6.6.144 | mainline | kptr-hidden | 9 bits | exact | `prefetch` | timing | yes |
| x86_64 | 6.6.144 | mainline | dmesg-open | 9 bits | exact | `prefetch` | timing | yes |
| x86_64 | 6.6.144 | mainline | hardened | 9 bits | exact | `prefetch` | timing | yes |
| x86_64 | 7.0.0 | mainline | default | 9 bits | exact | `prefetch` | timing | yes |
| x86_64 | 7.0.0 | mainline | kptr-hidden | 9 bits | exact | `prefetch` | timing | yes |
| x86_64 | 7.0.0 | mainline | dmesg-open | 9 bits | exact | `prefetch` | timing | yes |
| x86_64 | 7.0.0 | mainline | hardened | 9 bits | exact | `prefetch` | timing | yes |

This table is exactly what "excluded for reproducibility" means, and it is shown
here only to make the capability concrete: it is a snapshot of one capable host,
not a reproducible result. On a mitigated CPU (microcode or hypervisor Spectre-v2
defenses) or a lower-microarchitecture part the `prefetch` signal flattens and
these rows narrow less or disappear entirely — which is why they are kept out of
the guaranteed matrix and gated behind `--with-timing`. Only the guaranteed
matrix above reproduces run to run and machine to machine. (`perf-open` is absent
because its base is already `exact` in the guaranteed window, leaving the oracle
nothing to add.)

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

The matrix exercises the **kernel**, not a distribution's userland. Each cell
boots straight into the analysis harness from a minimal initramfs, so no distro
init, `sysctl.d` drop-ins, service sandboxing, or LSM policy (AppArmor / SELinux /
seccomp) ever runs. Every profile therefore measures the kernel's *own* posture —
its compile-time sysctl defaults plus the one explicit sysctl vector the harness
sets — and nothing a userland would layer on top. This cuts both ways and is a
scope boundary in both directions: a real distribution install may enforce
controls these cells do not (so an actual system can be *stricter* than even the
`hardened` column), and userland is itself a potential leak surface — setuid
helpers, privileged daemons, and files a running service populates — that the
matrix does not exercise (so an actual system may expose *more* than the
`default` column). The isolation is deliberate: it attributes each result to a
named kernel and a declared sysctl vector, keeping the cells reproducible and
independent of any particular distribution's userspace.

These are limits on what the checks here *verify*. For what a KASLD result means
when it is run against a target — in particular why a failure to recover the base
is not evidence the system is secure — see [limitations.md](limitations.md).
