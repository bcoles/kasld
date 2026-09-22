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
iomem kernel line, so the base survives. A capture's symbol table is reduced to
the landmarks a fixture reads by `extra/trim-kallsyms`, which validates the
capture before and after and keeps the reduction only when the soundness result
is identical — a component that resolves a symbol by name reads a truncated
table as an absence rather than an omission. The offline checks are cheap and
continuous; the VM check is slower and run periodically.

## Table of Contents

- [1. On the local kernel](#1-on-the-local-kernel)
- [2. Live, across architectures](#2-live-across-architectures)
  - [Architecture characterization](#architecture-characterization)
  - [Results matrix: image base](#results-matrix-image-base)
  - [Memory-KASLR region bases](#memory-kaslr-region-bases)
  - [Vantage sensitivity](#vantage-sensitivity)
  - [Kernel-configuration sensitivity](#kernel-configuration-sensitivity)
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

It also lists which vantage sources the bundle carries — the collecting
process's identity, its MAC label, the active LSM list, the group database, and
the container markers. Those do not affect an inferred range, so a missing one
is reported rather than failed; it is reported at all because its absence is
silent in the analysis, where an unread source and an empty answer both present
as "unknown".

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
builds, `1` on Alpine). The other profiles move away from that booted baseline:
`kptr-hidden`, `perf-open`, `dmesg-open` and `bpf-open` each shift a single axis;
`hardened` tightens all of them at once.

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
- `bpf-open` — `default` plus `unprivileged_bpf_disabled=0`: unprivileged
  `bpf()` permitted, which the BPF verifier-log leaks require. The `perf-open`
  equivalent for the BPF axis. Cells fall into three groups. Where the kernel has
  `CONFIG_BPF_SYSCALL` and unprivileged use is locked off — the distro cells ship
  `CONFIG_BPF_UNPRIV_DEFAULT_OFF`, the mainline ones are built with it forced on
  — that lock is what this profile relaxes, and `default` reflects an attacker
  who cannot call `bpf()`. Roughly half the mainline cells do not set
  `CONFIG_BPF_SYSCALL` at all — among them every `x86_64`, `i686`, `armv7`,
  `armeb`, `ppc32` and MIPS build — so there is no `bpf()` and no
  `unprivileged_bpf_disabled` sysctl to relax; the profile is a no-op there, and
  the boot log records the knob as `absent`. On the 5.15 mainline cells that do
  have `CONFIG_BPF_SYSCALL` the forced lock did not take, so those boot with
  unprivileged `bpf()` already permitted and `default` measures the same vantage
  `bpf-open` does.
  The row is shown on **every** cell, like the other sysctl profiles, including
  where it reads the same as `default` — that is a result, not an absence, and
  it is the one this profile most often reports. Where the syscall exists, a row
  matching `default` says unprivileged `bpf()` was permitted and still leaked
  nothing; where it does not, the row says there was never a syscall to permit.
  A missing row would leave a reader unable to tell either case from a cell
  nobody ran. On a mainline cell that does have `bpf()`, the verifier-log
  components would still report `unavailable`: their offset table is keyed by
  `uname` and built from a corpus of published distro kernels, which a locally
  built `7.0.0` is not in.
- `hardened` — `kptr_restrict=2`, `dmesg_restrict=1`, `perf_event_paranoid=3`,
  `unprivileged_bpf_disabled=2`: the realistic attacker floor, where only
  file-derived facts survive.

Under the tighter profiles the window may widen but must still contain the truth.
See [tests/vm/README.md](../tests/vm/README.md) for the full arch list and options.

Every architecture is booted on mainline kernel.org kernels — the LTS lines 5.15
and 6.6 and current 7.0 — cross-built from pinned source by `tests/vm/build-kernel`
(a stock upstream defconfig plus fixed config overlays: endianness, devtmpfs, and
text KASLR for riscv64 and ppc32). Of the fifteen, eight additionally boot a
publicly-fetchable Alpine distro kernel; the other seven — `armeb`, `mips`,
`mipsel`, `mips64el`, `powerpc64`, `ppc32`, `riscv32` — have no Alpine port, so
mainline is their only source. Cells are named `<arch>-<distro>-<line>`;
for a mainline cell the version in the name is a label and `LINUX_VERSION` sets
the source:

```sh
LINUX_VERSION=5.15.211 tests/vm/build-kernel ppc32-mainline-5.15  # cross-build -> cache (slow)
tests/vm/run ppc32-mainline-5.15                                  # boot it, verdict
```

`armeb` needs `-mbe8` on both payloads. The cross set's big-endian arm toolchain
emits BE32 by default, which cannot run on the BE8 userspace an arm kernel
provides from ARMv6 on — it takes SIGILL on its first instruction. `-mbe8`
produces BE8 instead, and `make cross` passes it for the armeb triple, as does
the VM harness for the init it stages beside kasld.

### Architecture characterization

*Which* layout quantities KASLR randomizes — and therefore which columns the
results tables below can carry at all — is a structural property of each
architecture's memory model, not of whether the KASLR feature is enabled. Two
architecture flags decide it: whether kernel text tracks the direct map (so a
physical leak also fixes the virtual base), and whether the direct map is a
static compile-time projection. Together they set, per architecture, whether the
**physical image base** is an independently-randomized quantity and whether the
**direct-map / vmalloc / vmemmap region bases** move on their own. This table is
the reason a single flat grid does not fit: different architectures have
different quantities to measure.

| architecture | text ↔ direct map | direct map | independent phys base | independent region bases |
|--------------|-------------------|------------|-----------------------|--------------------------|
| x86_64 | decoupled | randomized | yes | **yes** (`RANDOMIZE_MEMORY`) |
| aarch64 | decoupled | randomized | yes | no † |
| riscv64 | decoupled | randomized | yes | no † |
| s390x | decoupled | randomized | yes | no † |
| i686 | coupled | static | coupled | no |
| armv7, armeb | coupled | static | coupled | no |
| mips, mipsel | coupled | static | coupled | no |
| mips64el | coupled | static | coupled | no |
| ppc32 | coupled | static | coupled | no |
| ppc64le, powerpc64 | coupled | static | coupled | no |
| riscv32 | coupled | static | coupled | no |
| loongarch64 | coupled | static | coupled | no |

*Coupled* means kernel text and the direct map share a fixed offset, so a
physical leak reveals the virtual base and there is no separate physical quantity
to score — the results matrix marks these `coupled`. *Decoupled* means the kernel
image is placed independently in physical memory, so the physical image base is
its own quantity. † The decoupled non-x86 architectures *do* randomize the linear
map, but by a mechanism (`aarch64` `memstart_addr`, `s390` identity base,
`riscv64` `kernel_map.page_offset`) that this harness bounds but does not
ground-truth; only x86_64's `CONFIG_RANDOMIZE_MEMORY` region bases are truth-gated
(see [Memory-KASLR region bases](#memory-kaslr-region-bases)).

Reading the result cells in the tables below:

- `exact` — the base was recovered (a byte-exact pin, or a window narrower than
  one KASLR slot); 0 bits of KASLR entropy remain.
- `<n> bits` — KASLR still randomized, `n` bits (2ⁿ candidate slots) unrecovered.
- `—` — KASLR is off on that cell, so there is no randomization to defeat.
- `coupled` — the quantity is a fixed projection of another (not independently
  randomized), so there is no separate value to score.
- `n/a` — the quantity does not exist on that architecture at all.

Soundness itself is not a per-cell column: **every published cell is sound on
every gated axis, and a cell whose window excludes the truth is withheld, never
shown.** The tables report *how much* was recovered; that the window contains the
truth is the invariant behind the whole page.

### Results matrix: image base

This is the core soundness result — the virtual kernel-text base and, on
decoupled architectures, the physical image base. Every cell is sound: the true
base lies inside the **guaranteed** window on *both* axes, and a cell whose
window excludes the truth is withheld, never published. The snapshot is
generated by `tests/vm/run all <scenario>` followed by `tests/vm/run table`.

The guaranteed window is resolved purely from signals at or above the sound floor
and **never depends on a timing or microarchitectural side channel** — that is
what makes the *soundness verdict* reproducible run to run and machine to
machine: every cell contains the truth on every boot, on any host.

The shape of the result, one bar per architecture. `tests/vm/run chart` renders
it from the same rows as the table below, so the two cannot disagree. Where the
table varies every axis, the chart holds all but one still: a single kernel
line, each architecture on its own upstream defconfig, every figure read at the
default vantage. What is left differing between the bars is the architecture:

![How much kernel address entropy survives, by architecture - one horizontal bar per architecture giving the sound residual in the kernel image base on a single kernel line, each architecture built from its own upstream defconfig and read by an unprivileged user at the default vantage: aarch64 31 bits, s390x 29, loongarch64 16, mips64el and ppc32 14, mips and mipsel 13, riscv64 and x86_64 9, i686 8. Five further architectures - armeb, armv7, powerpc64, ppc64le and riscv32 - do not randomise the kernel image in this configuration and are listed beneath the bars rather than plotted, there being nothing to measure](diagrams/residual-entropy-by-arch.svg)

Each bar is one machine, not an average. No figure in it is a total, a mean or
a distribution across cells: the matrix is a convenience sample whose shape
follows whatever was investigated most recently, so counting over it would
measure that attention rather than the subject. One architecture, one kernel,
one configuration, one number — and one boot. On the architectures that redraw
the image base each boot the figure can land a bit or two either side of the one
plotted; the note beneath the full matrix gives the observed spread.

A defconfig is each architecture's own upstream default, which is what a stock
build produces, not a single configuration imposed across all of them — and on
this kernel line the default does not agree with itself. The figure names the
three groups; they divide evenly, five each, and they reach their state by
different routes. `aarch64` and `loongarch64` carry `CONFIG_RANDOMIZE_BASE=y` in
the defconfig file itself, while `s390x` and the two x86 architectures reach it
from a Kconfig `default y` and name it in no defconfig. Neither route is
available to `mips`, `mipsel`, `mips64el`, `ppc32` or `riscv64`: the option has
no default on those architectures and appears in none of their configurations,
including every fragment merged into the 85xx configuration `ppc32` is built
from, so the plotted cells randomise only because `tests/vm/build-kernel` asks
for `RELOCATABLE` and `RANDOMIZE_BASE`. They are plotted because the cell exists
to exercise the randomised layout, but a stock build of them randomises nothing.

The five that cannot randomise at all are excluded by the architecture rather
than by a choice: mainline arm32 has no kernel-image KASLR, `RANDOMIZE_BASE`
depends on `PPC_85xx && FLATMEM` and so is unreachable on 64-bit PowerPC, and it
depends on `MMU && 64BIT`, which rules out `riscv32`. They are named beneath the
bars rather than drawn at zero, a bar of no length being a different claim from
no randomisation.

**A long bar is not evidence of a strong kernel**, and on this kernel line most
of them are not evidence of anything the analysis did. Nine of the ten plotted
figures are the starting window unmoved, `ppc32` being the only one the evidence
touches at all. `aarch64` is the clearest case of the nine — its
virtual-address width resolves exactly and its direct map pins to a single
candidate, yet the image base ends where it began, because the kallsyms and perf
routes are both closed to an unprivileged reader.

That is a statement about the vantage, not about the architectures. The default
profile is an unprivileged reader with nothing opened, against a stock upstream
defconfig, which is the least the tool is ever given; the same cells give up the
base exactly once `perf_event_paranoid` is lowered, and the matrix below carries
those figures. Read the bars as a bound on what sound inference proves from that
standing start, never as a bound on what an attacker holding another route could
reach.

One consequence is that the bars are reproducible for the wrong reason. A figure
that is a prior is a constant, so it repeats exactly; a figure the evidence
actually moves need not. Across three boots of every plotted cell, nine returned
bit-identical residuals and `ppc32` did not, spanning 12 to 14 bits over four
observations. Its lower bound and its prior hold still between boots and only
the ceiling moves, that ceiling being read off an observed address which the
draw itself placed: land low and it cuts hard, land high and it barely cuts. The
published `ppc32` bar is therefore one boot's result. The architectures that
share its self-seeding mechanism — `mips`, `mipsel` and `mips64el`, which seed
from `random_get_entropy()` rather than a device-tree value — do not vary, so
the cause is not the seeding but the fact that `ppc32` is the one cell where
anything is narrowed at all.

Configuration moves these figures further than the kernel line does, which is
why the chart fixes both rather than pooling them; that axis is measured
separately under [Kernel-configuration
sensitivity](#kernel-configuration-sensitivity), and the per-vantage figures are
the matrix's own job.

These figures are **not** directly comparable with the per-architecture entropy
in [Default text base and KASLR alignment](kaslr.md#default-text-base-and-kaslr-alignment).
That chart counts the placements a kernel drew from, given a known
configuration; this one measures the window KASLD can prove *without* knowing
it. So a residual may legitimately exceed the architectural figure — in the
chart above aarch64 reports 31 bits against an architectural 30, and
loongarch64 16 against 12 — and the excess is uncertainty about the build, not
entropy the kernel holds. The window has to span every layout and placement
formula the architecture admits until evidence rules one out. On aarch64 the
minimum offset differs between the pre-v5.4, v6.6 and v6.12 formulas. On
loongarch64 `CONFIG_RANDOMIZE_BASE_MAX_OFFSET` is a build choice an
unprivileged reader cannot see. riscv64 shows the same effect off the default
vantage rather than on it: the chart's 9 bits matches its architectural figure,
but a kernel booted `no4lvl` leaves 16, the window still having to reach down to
the legacy linear-map base because nothing observable distinguishes that layout
from the modern one.

Reading a cell. `source` is the kernel: `alpine` (a distro kernel) or `mainline`
(a vanilla kernel.org build via `tests/vm/build-kernel`). `virt residual` and
`phys residual` say how much KASLR entropy KASLD could *not* strip from each
axis; the vocabulary (`exact` / `<n> bits` / `—` / `coupled`) is defined in
[Architecture characterization](#architecture-characterization) above.

Every residual in this document is the **sound** one: the guaranteed window,
which admits only evidence at or above the sound floor. That is a narrower
claim than "what an attacker would face", and deliberately so. The
microarchitectural side channels ship and run in these boots — `prefetch` and
`avx_maskload` succeed on the x86_64 cells — but they rest on timing, which
sits below that floor, so they shape the likely window and can never move the
figure tabulated here. A cell can therefore report several bits of sound
residual while its likely window names the base exactly. Where that matters the
`-j` output carries both. `phys residual` carries an independent count only on
the *decoupled* arches; elsewhere it reads `coupled`, and the virtual result
already determines it.

`CONFIG_PHYSICAL_ALIGN` is a build choice, not a property of the architecture.
Alpine sets it to 16 MiB on x86 where the mainline builds take the 2 MiB
default — eight times coarser, so an Alpine image base starts with 3 bits less
entropy for anything to strip. The `alpine` x86 rows therefore report fewer bits
than the `mainline` rows beside them because of how they were built, not because
of the release. Those 3 bits are the whole of the shortfall on i686 and on the
x86_64 physical axis; where a gap is wider, the rest is a difference in what that
release leaked. See
[x86 slot granularity (CONFIG_PHYSICAL_ALIGN)](kaslr.md#x86-slot-granularity-config_physical_align).

The bits are a **floor, not a ceiling**: they are the most KASLR entropy that
survives sound, reproducible inference, and a microarchitectural oracle can
strip more on capable hardware — see
[Speculative narrowing](#speculative-narrowing-the-likely-window) below. They are
also one boot's sample rather than a constant: a row whose ceiling comes from a
leak positioned relative to the kernel image has a span that tracks that boot's
KASLR draw, so it can move a bit or two between runs, in either direction. Read
a profile's effect from the component it unlocks, not from a small step.

Every profile is run on every cell and gets a row, including where it reads the
same as `default` — a profile that changed nothing is a result, and the table
would otherwise leave that indistinguishable from a cell nobody ran. Cells
carrying a configuration in the release column (`7.0.0 (va39)`,
`7.0.0 (vmsplit2g)`) are purpose-built kernels on the config axis; see
[Kernel-configuration sensitivity](#kernel-configuration-sensitivity).

Two conventions explain rows that would otherwise look like gaps. An
architecture predating a kernel line has no row for it (LoongArch, mainlined in
6.1, has no 5.15 row). And a cell may show `KASLR: off` where its neighbours on
the same architecture show `on`: the three MIPS cells on the 6.6 line are built
without `CONFIG_RANDOMIZE_BASE`, because on that line MIPS Oopses in the
exception path once the kernel actually relocates. Those cells still test
soundness — an unprivileged process cannot read `CONFIG_RANDOMIZE_BASE`, so
KASLD reports the conservative KASLR-possible window, which must contain the
fixed base like any other.

The summary names the two scenarios that carry the result: `default` is the
ordinary unprivileged vantage, and `perf-open` is the one that moves the answer
on most architectures. The remaining scenarios — `kptr-hidden`, `dmesg-open`,
`bpf-open`, `hardened`, and the x86 paging modes — restate their cell's
`default` in all but 41 rows, and the fold beneath carries every one of them.

| arch | release | source | KASLR | default (virt / phys) | perf-open (virt / phys) |
|------|---------|--------|-------|-----------------------|-------------------------|
| aarch64 | 6.12.81-0-virt | alpine | on | 32 bits / 14 bits | exact / 9 bits |
| aarch64 | 4.19.325 | mainline | on | 32 bits / 14 bits | exact / 9 bits |
| aarch64 | 5.15.211 | mainline | on | 32 bits / 14 bits | exact / 9 bits |
| aarch64 | 6.6.144 | mainline | on | 32 bits / 14 bits | exact / 9 bits |
| aarch64 | 7.0.0 | mainline | on | 31 bits / 14 bits | exact / 9 bits |
| aarch64 | 7.0.0 (va39) | mainline | on | 23 bits / 14 bits | exact / 9 bits |
| aarch64 | 7.0.0 (ftrace) | mainline | on | 31 bits / 14 bits | exact / 9 bits |
| aarch64 | 7.0.0 (va47) | mainline | on | 31 bits / 14 bits | exact / 9 bits |
| aarch64 | 7.0.0 (va42) | mainline | on | 25 bits / 13 bits | exact / 9 bits |
| aarch64 | 7.0.0 (va36) | mainline | on | 20 bits / 14 bits | exact / 9 bits |
| armeb | 5.15.211 | mainline | off | — / — | — / — |
| armeb | 6.6.144 | mainline | off | — / — | — / — |
| armeb | 7.0.0 | mainline | off | — / — | — / — |
| armv7 | 6.12.81-0-lts | alpine | off | — / — | — / — |
| armv7 | 5.15.211 | mainline | off | — / — | — / — |
| armv7 | 6.6.144 | mainline | off | — / — | — / — |
| armv7 | 7.0.0 | mainline | off | — / — | — / — |
| armv7 | 7.0.0 (vmsplit2g) | mainline | off | — / — | — / — |
| i686 | 6.12.81-0-lts | alpine | on | 5 bits / coupled | exact / coupled |
| i686 | 5.15.211 | mainline | on | 8 bits / coupled | exact / coupled |
| i686 | 6.6.144 | mainline | on | 8 bits / coupled | exact / coupled |
| i686 | 7.0.0 | mainline | on | 8 bits / coupled | exact / coupled |
| i686 | 7.0.0 (vmsplit2g) | mainline | on | 8 bits / coupled | exact / coupled |
| loongarch64 | 6.18.44-0-lts | alpine | on | 11 bits / coupled | exact / coupled |
| loongarch64 | 6.6.144 | mainline | on | 11 bits / coupled | exact / coupled |
| loongarch64 | 7.0.0 | mainline | on | 16 bits / coupled | exact / coupled |
| mips | 5.15.211 | mainline | on | 8 bits / coupled | exact / coupled |
| mips | 6.6.144 | mainline | on | 8 bits / coupled | exact / coupled |
| mips | 7.0.0 | mainline | on | 13 bits / coupled | exact / coupled |
| mips64el | 5.15.211 | mainline | on | 8 bits / coupled | exact / coupled |
| mips64el | 6.6.144 | mainline | on | 8 bits / coupled | exact / coupled |
| mips64el | 7.0.0 | mainline | on | 14 bits / coupled | exact / coupled |
| mipsel | 5.15.211 | mainline | on | 8 bits / coupled | exact / coupled |
| mipsel | 6.6.144 | mainline | on | 8 bits / coupled | exact / coupled |
| mipsel | 7.0.0 | mainline | on | 13 bits / coupled | exact / coupled |
| powerpc64 | 5.15.211 | mainline | off | — / — | — / — |
| powerpc64 | 6.6.144 | mainline | off | — / — | — / — |
| powerpc64 | 7.0.0 | mainline | off | — / — | — / — |
| ppc32 | 5.15.211 | mainline | on | 14 bits / coupled | exact / coupled |
| ppc32 | 6.6.144 | mainline | on | 14 bits / coupled | exact / coupled |
| ppc32 | 7.0.0 | mainline | on | 14 bits / coupled | exact / coupled |
| ppc64le | 6.12.81-0-lts | alpine | off | — / — | — / — |
| ppc64le | 5.15.211 | mainline | off | — / — | — / — |
| ppc64le | 6.6.144 | mainline | off | — / — | — / — |
| ppc64le | 7.0.0 | mainline | off | — / — | — / — |
| riscv32 | 5.15.211 | mainline | off | — / — | — / — |
| riscv32 | 6.6.144 | mainline | off | — / — | — / — |
| riscv32 | 7.0.0 | mainline | off | — / — | — / — |
| riscv64 | 6.18.44-0-lts | alpine | off | — / — | — / — |
| riscv64 | 5.15.211 | mainline | off | — / — | — / — |
| riscv64 | 6.6.144 | mainline | on | exact / 9 bits | exact / 9 bits |
| riscv64 | 7.0.0 | mainline | on | 9 bits / 9 bits | exact / 9 bits |
| s390x | 6.12.81-0-lts | alpine | on | 39 bits / 10 bits | exact / 10 bits |
| s390x | 5.15.211 | mainline | on | 17 bits / 10 bits | exact / 9 bits |
| s390x | 6.6.144 | mainline | on | 17 bits / 10 bits | exact / 9 bits |
| s390x | 7.0.0 | mainline | on | 29 bits / 10 bits | exact / 10 bits |
| s390x | 7.0.0 (4level) | mainline | on | 39 bits / 10 bits | exact / 10 bits |
| x86_64 | 6.12.81-0-virt | alpine | on | 2 bits / 6 bits | exact / 6 bits |
| x86_64 | 4.19.325 | mainline | on | 4 bits / 9 bits | exact / 9 bits |
| x86_64 | 5.15.211 | mainline | on | 5 bits / 9 bits | exact / 9 bits |
| x86_64 | 6.6.144 | mainline | on | 5 bits / 9 bits | exact / 9 bits |
| x86_64 | 7.0.0 | mainline | on | 9 bits / 9 bits | exact / 9 bits |

<details>
<summary>Full results matrix — every scenario, 452 rows</summary>

| arch | release | source | scenario | KASLR | virt residual | phys residual |
|------|---------|--------|----------|-------|---------------|---------------|
| aarch64 | 6.12.81-0-virt | alpine | default | on | 32 bits | 14 bits |
| aarch64 | 6.12.81-0-virt | alpine | kptr-hidden | on | 32 bits | 14 bits |
| aarch64 | 6.12.81-0-virt | alpine | perf-open | on | exact | 9 bits |
| aarch64 | 6.12.81-0-virt | alpine | dmesg-open | on | 32 bits | 14 bits |
| aarch64 | 6.12.81-0-virt | alpine | bpf-open | on | 15 bits | 14 bits |
| aarch64 | 6.12.81-0-virt | alpine | hardened | on | 32 bits | 14 bits |
| aarch64 | 6.12.81-0-virt | alpine | tracefs-open | on | 32 bits | 14 bits |
| aarch64 | 4.19.325 | mainline | default | on | 32 bits | 14 bits |
| aarch64 | 4.19.325 | mainline | kptr-hidden | on | 32 bits | 14 bits |
| aarch64 | 4.19.325 | mainline | perf-open | on | exact | 9 bits |
| aarch64 | 4.19.325 | mainline | dmesg-open | on | 32 bits | 14 bits |
| aarch64 | 4.19.325 | mainline | bpf-open | on | 32 bits | 14 bits |
| aarch64 | 4.19.325 | mainline | hardened | on | 32 bits | 14 bits |
| aarch64 | 4.19.325 | mainline | tracefs-open | on | 32 bits | 14 bits |
| aarch64 | 5.15.211 | mainline | default | on | 32 bits | 14 bits |
| aarch64 | 5.15.211 | mainline | kptr-hidden | on | 32 bits | 14 bits |
| aarch64 | 5.15.211 | mainline | perf-open | on | exact | 9 bits |
| aarch64 | 5.15.211 | mainline | dmesg-open | on | 32 bits | 14 bits |
| aarch64 | 5.15.211 | mainline | bpf-open | on | 32 bits | 14 bits |
| aarch64 | 5.15.211 | mainline | hardened | on | 32 bits | 14 bits |
| aarch64 | 5.15.211 | mainline | tracefs-open | on | 32 bits | 14 bits |
| aarch64 | 6.6.144 | mainline | default | on | 32 bits | 14 bits |
| aarch64 | 6.6.144 | mainline | kptr-hidden | on | 32 bits | 14 bits |
| aarch64 | 6.6.144 | mainline | perf-open | on | exact | 9 bits |
| aarch64 | 6.6.144 | mainline | dmesg-open | on | 32 bits | 14 bits |
| aarch64 | 6.6.144 | mainline | bpf-open | on | 31 bits | 14 bits |
| aarch64 | 6.6.144 | mainline | hardened | on | 32 bits | 14 bits |
| aarch64 | 6.6.144 | mainline | tracefs-open | on | 32 bits | 14 bits |
| aarch64 | 7.0.0 | mainline | default | on | 31 bits | 14 bits |
| aarch64 | 7.0.0 | mainline | kptr-hidden | on | 31 bits | 14 bits |
| aarch64 | 7.0.0 | mainline | perf-open | on | exact | 9 bits |
| aarch64 | 7.0.0 | mainline | dmesg-open | on | 31 bits | 14 bits |
| aarch64 | 7.0.0 | mainline | bpf-open | on | 31 bits | 14 bits |
| aarch64 | 7.0.0 | mainline | hardened | on | 31 bits | 14 bits |
| aarch64 | 7.0.0 | mainline | tracefs-open | on | 31 bits | 14 bits |
| aarch64 | 7.0.0 (va39) | mainline | default | on | 23 bits | 14 bits |
| aarch64 | 7.0.0 (va39) | mainline | kptr-hidden | on | 23 bits | 14 bits |
| aarch64 | 7.0.0 (va39) | mainline | perf-open | on | exact | 9 bits |
| aarch64 | 7.0.0 (va39) | mainline | dmesg-open | on | 23 bits | 14 bits |
| aarch64 | 7.0.0 (va39) | mainline | bpf-open | on | 22 bits | 14 bits |
| aarch64 | 7.0.0 (va39) | mainline | hardened | on | 23 bits | 14 bits |
| aarch64 | 7.0.0 (va39) | mainline | tracefs-open | on | 23 bits | 14 bits |
| aarch64 | 7.0.0 (ftrace) | mainline | default | on | 31 bits | 14 bits |
| aarch64 | 7.0.0 (ftrace) | mainline | kptr-hidden | on | 31 bits | 14 bits |
| aarch64 | 7.0.0 (ftrace) | mainline | perf-open | on | exact | 9 bits |
| aarch64 | 7.0.0 (ftrace) | mainline | dmesg-open | on | 31 bits | 14 bits |
| aarch64 | 7.0.0 (ftrace) | mainline | bpf-open | on | 31 bits | 14 bits |
| aarch64 | 7.0.0 (ftrace) | mainline | hardened | on | 31 bits | 14 bits |
| aarch64 | 7.0.0 (ftrace) | mainline | tracefs-open | on | 7 bits | 14 bits |
| aarch64 | 7.0.0 (va47) | mainline | default | on | 31 bits | 14 bits |
| aarch64 | 7.0.0 (va47) | mainline | kptr-hidden | on | 31 bits | 14 bits |
| aarch64 | 7.0.0 (va47) | mainline | perf-open | on | exact | 9 bits |
| aarch64 | 7.0.0 (va47) | mainline | dmesg-open | on | 31 bits | 14 bits |
| aarch64 | 7.0.0 (va47) | mainline | bpf-open | on | 32 bits | 14 bits |
| aarch64 | 7.0.0 (va47) | mainline | hardened | on | 31 bits | 14 bits |
| aarch64 | 7.0.0 (va47) | mainline | tracefs-open | on | 31 bits | 14 bits |
| aarch64 | 7.0.0 (va42) | mainline | default | on | 25 bits | 13 bits |
| aarch64 | 7.0.0 (va42) | mainline | kptr-hidden | on | 25 bits | 13 bits |
| aarch64 | 7.0.0 (va42) | mainline | perf-open | on | exact | 9 bits |
| aarch64 | 7.0.0 (va42) | mainline | dmesg-open | on | 25 bits | 13 bits |
| aarch64 | 7.0.0 (va42) | mainline | bpf-open | on | 24 bits | 13 bits |
| aarch64 | 7.0.0 (va42) | mainline | hardened | on | 25 bits | 13 bits |
| aarch64 | 7.0.0 (va42) | mainline | tracefs-open | on | 25 bits | 13 bits |
| aarch64 | 7.0.0 (va36) | mainline | default | on | 20 bits | 14 bits |
| aarch64 | 7.0.0 (va36) | mainline | kptr-hidden | on | 20 bits | 14 bits |
| aarch64 | 7.0.0 (va36) | mainline | perf-open | on | exact | 9 bits |
| aarch64 | 7.0.0 (va36) | mainline | dmesg-open | on | 20 bits | 14 bits |
| aarch64 | 7.0.0 (va36) | mainline | bpf-open | on | 20 bits | 14 bits |
| aarch64 | 7.0.0 (va36) | mainline | hardened | on | 20 bits | 14 bits |
| aarch64 | 7.0.0 (va36) | mainline | tracefs-open | on | 20 bits | 14 bits |
| armeb | 5.15.211 | mainline | default | off | — | — |
| armeb | 5.15.211 | mainline | kptr-hidden | off | — | — |
| armeb | 5.15.211 | mainline | perf-open | off | — | — |
| armeb | 5.15.211 | mainline | dmesg-open | off | — | — |
| armeb | 5.15.211 | mainline | bpf-open | off | — | — |
| armeb | 5.15.211 | mainline | hardened | off | — | — |
| armeb | 5.15.211 | mainline | tracefs-open | off | — | — |
| armeb | 6.6.144 | mainline | default | off | — | — |
| armeb | 6.6.144 | mainline | kptr-hidden | off | — | — |
| armeb | 6.6.144 | mainline | perf-open | off | — | — |
| armeb | 6.6.144 | mainline | dmesg-open | off | — | — |
| armeb | 6.6.144 | mainline | bpf-open | off | — | — |
| armeb | 6.6.144 | mainline | hardened | off | — | — |
| armeb | 6.6.144 | mainline | tracefs-open | off | — | — |
| armeb | 7.0.0 | mainline | default | off | — | — |
| armeb | 7.0.0 | mainline | kptr-hidden | off | — | — |
| armeb | 7.0.0 | mainline | perf-open | off | — | — |
| armeb | 7.0.0 | mainline | dmesg-open | off | — | — |
| armeb | 7.0.0 | mainline | bpf-open | off | — | — |
| armeb | 7.0.0 | mainline | hardened | off | — | — |
| armeb | 7.0.0 | mainline | tracefs-open | off | — | — |
| armv7 | 6.12.81-0-lts | alpine | default | off | — | — |
| armv7 | 6.12.81-0-lts | alpine | kptr-hidden | off | — | — |
| armv7 | 6.12.81-0-lts | alpine | perf-open | off | — | — |
| armv7 | 6.12.81-0-lts | alpine | dmesg-open | off | — | — |
| armv7 | 6.12.81-0-lts | alpine | bpf-open | off | — | — |
| armv7 | 6.12.81-0-lts | alpine | hardened | off | — | — |
| armv7 | 6.12.81-0-lts | alpine | tracefs-open | off | — | — |
| armv7 | 5.15.211 | mainline | default | off | — | — |
| armv7 | 5.15.211 | mainline | kptr-hidden | off | — | — |
| armv7 | 5.15.211 | mainline | perf-open | off | — | — |
| armv7 | 5.15.211 | mainline | dmesg-open | off | — | — |
| armv7 | 5.15.211 | mainline | bpf-open | off | — | — |
| armv7 | 5.15.211 | mainline | hardened | off | — | — |
| armv7 | 5.15.211 | mainline | tracefs-open | off | — | — |
| armv7 | 6.6.144 | mainline | default | off | — | — |
| armv7 | 6.6.144 | mainline | kptr-hidden | off | — | — |
| armv7 | 6.6.144 | mainline | perf-open | off | — | — |
| armv7 | 6.6.144 | mainline | dmesg-open | off | — | — |
| armv7 | 6.6.144 | mainline | bpf-open | off | — | — |
| armv7 | 6.6.144 | mainline | hardened | off | — | — |
| armv7 | 6.6.144 | mainline | tracefs-open | off | — | — |
| armv7 | 7.0.0 | mainline | default | off | — | — |
| armv7 | 7.0.0 | mainline | kptr-hidden | off | — | — |
| armv7 | 7.0.0 | mainline | perf-open | off | — | — |
| armv7 | 7.0.0 | mainline | dmesg-open | off | — | — |
| armv7 | 7.0.0 | mainline | bpf-open | off | — | — |
| armv7 | 7.0.0 | mainline | hardened | off | — | — |
| armv7 | 7.0.0 | mainline | tracefs-open | off | — | — |
| armv7 | 7.0.0 (vmsplit2g) | mainline | default | off | — | — |
| armv7 | 7.0.0 (vmsplit2g) | mainline | kptr-hidden | off | — | — |
| armv7 | 7.0.0 (vmsplit2g) | mainline | perf-open | off | — | — |
| armv7 | 7.0.0 (vmsplit2g) | mainline | dmesg-open | off | — | — |
| armv7 | 7.0.0 (vmsplit2g) | mainline | bpf-open | off | — | — |
| armv7 | 7.0.0 (vmsplit2g) | mainline | hardened | off | — | — |
| armv7 | 7.0.0 (vmsplit2g) | mainline | tracefs-open | off | — | — |
| i686 | 6.12.81-0-lts | alpine | default | on | 5 bits | coupled |
| i686 | 6.12.81-0-lts | alpine | kptr-hidden | on | 5 bits | coupled |
| i686 | 6.12.81-0-lts | alpine | perf-open | on | exact | coupled |
| i686 | 6.12.81-0-lts | alpine | dmesg-open | on | 5 bits | coupled |
| i686 | 6.12.81-0-lts | alpine | bpf-open | on | 5 bits | coupled |
| i686 | 6.12.81-0-lts | alpine | hardened | on | 5 bits | coupled |
| i686 | 6.12.81-0-lts | alpine | tracefs-open | on | exact | coupled |
| i686 | 5.15.211 | mainline | default | on | 8 bits | coupled |
| i686 | 5.15.211 | mainline | kptr-hidden | on | 8 bits | coupled |
| i686 | 5.15.211 | mainline | perf-open | on | exact | coupled |
| i686 | 5.15.211 | mainline | dmesg-open | on | 8 bits | coupled |
| i686 | 5.15.211 | mainline | bpf-open | on | 8 bits | coupled |
| i686 | 5.15.211 | mainline | hardened | on | 8 bits | coupled |
| i686 | 5.15.211 | mainline | tracefs-open | on | 4 bits | coupled |
| i686 | 6.6.144 | mainline | default | on | 8 bits | coupled |
| i686 | 6.6.144 | mainline | kptr-hidden | on | 8 bits | coupled |
| i686 | 6.6.144 | mainline | perf-open | on | exact | coupled |
| i686 | 6.6.144 | mainline | dmesg-open | on | 8 bits | coupled |
| i686 | 6.6.144 | mainline | bpf-open | on | 8 bits | coupled |
| i686 | 6.6.144 | mainline | hardened | on | 8 bits | coupled |
| i686 | 6.6.144 | mainline | tracefs-open | on | 4 bits | coupled |
| i686 | 7.0.0 | mainline | default | on | 8 bits | coupled |
| i686 | 7.0.0 | mainline | kptr-hidden | on | 8 bits | coupled |
| i686 | 7.0.0 | mainline | perf-open | on | exact | coupled |
| i686 | 7.0.0 | mainline | dmesg-open | on | 8 bits | coupled |
| i686 | 7.0.0 | mainline | bpf-open | on | 8 bits | coupled |
| i686 | 7.0.0 | mainline | hardened | on | 8 bits | coupled |
| i686 | 7.0.0 | mainline | tracefs-open | on | 4 bits | coupled |
| i686 | 7.0.0 (vmsplit2g) | mainline | default | on | 8 bits | coupled |
| i686 | 7.0.0 (vmsplit2g) | mainline | kptr-hidden | on | 8 bits | coupled |
| i686 | 7.0.0 (vmsplit2g) | mainline | perf-open | on | exact | coupled |
| i686 | 7.0.0 (vmsplit2g) | mainline | dmesg-open | on | 8 bits | coupled |
| i686 | 7.0.0 (vmsplit2g) | mainline | bpf-open | on | 8 bits | coupled |
| i686 | 7.0.0 (vmsplit2g) | mainline | hardened | on | 8 bits | coupled |
| i686 | 7.0.0 (vmsplit2g) | mainline | tracefs-open | on | 4 bits | coupled |
| loongarch64 | 6.18.44-0-lts | alpine | default | on | 11 bits | coupled |
| loongarch64 | 6.18.44-0-lts | alpine | kptr-hidden | on | 10 bits | coupled |
| loongarch64 | 6.18.44-0-lts | alpine | perf-open | on | exact | coupled |
| loongarch64 | 6.18.44-0-lts | alpine | dmesg-open | on | 10 bits | coupled |
| loongarch64 | 6.18.44-0-lts | alpine | bpf-open | on | 10 bits | coupled |
| loongarch64 | 6.18.44-0-lts | alpine | hardened | on | 11 bits | coupled |
| loongarch64 | 6.18.44-0-lts | alpine | tracefs-open | on | 10 bits | coupled |
| loongarch64 | 6.6.144 | mainline | default | on | 11 bits | coupled |
| loongarch64 | 6.6.144 | mainline | kptr-hidden | on | 10 bits | coupled |
| loongarch64 | 6.6.144 | mainline | perf-open | on | exact | coupled |
| loongarch64 | 6.6.144 | mainline | dmesg-open | on | 10 bits | coupled |
| loongarch64 | 6.6.144 | mainline | bpf-open | on | 10 bits | coupled |
| loongarch64 | 6.6.144 | mainline | hardened | on | 10 bits | coupled |
| loongarch64 | 6.6.144 | mainline | tracefs-open | on | 11 bits | coupled |
| loongarch64 | 7.0.0 | mainline | default | on | 16 bits | coupled |
| loongarch64 | 7.0.0 | mainline | kptr-hidden | on | 16 bits | coupled |
| loongarch64 | 7.0.0 | mainline | perf-open | on | exact | coupled |
| loongarch64 | 7.0.0 | mainline | dmesg-open | on | 16 bits | coupled |
| loongarch64 | 7.0.0 | mainline | bpf-open | on | 16 bits | coupled |
| loongarch64 | 7.0.0 | mainline | hardened | on | 16 bits | coupled |
| loongarch64 | 7.0.0 | mainline | tracefs-open | on | 16 bits | coupled |
| mips | 5.15.211 | mainline | default | on | 8 bits | coupled |
| mips | 5.15.211 | mainline | kptr-hidden | on | 8 bits | coupled |
| mips | 5.15.211 | mainline | perf-open | on | exact | coupled |
| mips | 5.15.211 | mainline | dmesg-open | on | 8 bits | coupled |
| mips | 5.15.211 | mainline | bpf-open | on | 8 bits | coupled |
| mips | 5.15.211 | mainline | hardened | on | 8 bits | coupled |
| mips | 5.15.211 | mainline | tracefs-open | on | 8 bits | coupled |
| mips | 6.6.144 | mainline | default | on | 8 bits | coupled |
| mips | 6.6.144 | mainline | kptr-hidden | on | 8 bits | coupled |
| mips | 6.6.144 | mainline | perf-open | on | exact | coupled |
| mips | 6.6.144 | mainline | dmesg-open | on | 8 bits | coupled |
| mips | 6.6.144 | mainline | bpf-open | on | 8 bits | coupled |
| mips | 6.6.144 | mainline | hardened | on | 8 bits | coupled |
| mips | 6.6.144 | mainline | tracefs-open | on | 8 bits | coupled |
| mips | 7.0.0 | mainline | default | on | 13 bits | coupled |
| mips | 7.0.0 | mainline | kptr-hidden | on | 13 bits | coupled |
| mips | 7.0.0 | mainline | perf-open | on | exact | coupled |
| mips | 7.0.0 | mainline | dmesg-open | on | 13 bits | coupled |
| mips | 7.0.0 | mainline | bpf-open | on | 13 bits | coupled |
| mips | 7.0.0 | mainline | hardened | on | 13 bits | coupled |
| mips | 7.0.0 | mainline | tracefs-open | on | 8 bits | coupled |
| mips64el | 5.15.211 | mainline | default | on | 8 bits | coupled |
| mips64el | 5.15.211 | mainline | kptr-hidden | on | 8 bits | coupled |
| mips64el | 5.15.211 | mainline | perf-open | on | exact | coupled |
| mips64el | 5.15.211 | mainline | dmesg-open | on | 8 bits | coupled |
| mips64el | 5.15.211 | mainline | bpf-open | on | 8 bits | coupled |
| mips64el | 5.15.211 | mainline | hardened | on | 8 bits | coupled |
| mips64el | 5.15.211 | mainline | tracefs-open | on | 8 bits | coupled |
| mips64el | 6.6.144 | mainline | default | on | 8 bits | coupled |
| mips64el | 6.6.144 | mainline | kptr-hidden | on | 8 bits | coupled |
| mips64el | 6.6.144 | mainline | perf-open | on | exact | coupled |
| mips64el | 6.6.144 | mainline | dmesg-open | on | 8 bits | coupled |
| mips64el | 6.6.144 | mainline | bpf-open | on | 8 bits | coupled |
| mips64el | 6.6.144 | mainline | hardened | on | 8 bits | coupled |
| mips64el | 6.6.144 | mainline | tracefs-open | on | 8 bits | coupled |
| mips64el | 7.0.0 | mainline | default | on | 14 bits | coupled |
| mips64el | 7.0.0 | mainline | kptr-hidden | on | 14 bits | coupled |
| mips64el | 7.0.0 | mainline | perf-open | on | exact | coupled |
| mips64el | 7.0.0 | mainline | dmesg-open | on | 14 bits | coupled |
| mips64el | 7.0.0 | mainline | bpf-open | on | 14 bits | coupled |
| mips64el | 7.0.0 | mainline | hardened | on | 14 bits | coupled |
| mips64el | 7.0.0 | mainline | tracefs-open | on | 8 bits | coupled |
| mipsel | 5.15.211 | mainline | default | on | 8 bits | coupled |
| mipsel | 5.15.211 | mainline | kptr-hidden | on | 8 bits | coupled |
| mipsel | 5.15.211 | mainline | perf-open | on | exact | coupled |
| mipsel | 5.15.211 | mainline | dmesg-open | on | 8 bits | coupled |
| mipsel | 5.15.211 | mainline | bpf-open | on | 8 bits | coupled |
| mipsel | 5.15.211 | mainline | hardened | on | 8 bits | coupled |
| mipsel | 5.15.211 | mainline | tracefs-open | on | 8 bits | coupled |
| mipsel | 6.6.144 | mainline | default | on | 8 bits | coupled |
| mipsel | 6.6.144 | mainline | kptr-hidden | on | 8 bits | coupled |
| mipsel | 6.6.144 | mainline | perf-open | on | exact | coupled |
| mipsel | 6.6.144 | mainline | dmesg-open | on | 8 bits | coupled |
| mipsel | 6.6.144 | mainline | bpf-open | on | 8 bits | coupled |
| mipsel | 6.6.144 | mainline | hardened | on | 8 bits | coupled |
| mipsel | 6.6.144 | mainline | tracefs-open | on | 8 bits | coupled |
| mipsel | 7.0.0 | mainline | default | on | 13 bits | coupled |
| mipsel | 7.0.0 | mainline | kptr-hidden | on | 13 bits | coupled |
| mipsel | 7.0.0 | mainline | perf-open | on | exact | coupled |
| mipsel | 7.0.0 | mainline | dmesg-open | on | 13 bits | coupled |
| mipsel | 7.0.0 | mainline | bpf-open | on | 13 bits | coupled |
| mipsel | 7.0.0 | mainline | hardened | on | 13 bits | coupled |
| mipsel | 7.0.0 | mainline | tracefs-open | on | 8 bits | coupled |
| powerpc64 | 5.15.211 | mainline | default | off | — | — |
| powerpc64 | 5.15.211 | mainline | kptr-hidden | off | — | — |
| powerpc64 | 5.15.211 | mainline | perf-open | off | — | — |
| powerpc64 | 5.15.211 | mainline | dmesg-open | off | — | — |
| powerpc64 | 5.15.211 | mainline | bpf-open | off | — | — |
| powerpc64 | 5.15.211 | mainline | hardened | off | — | — |
| powerpc64 | 5.15.211 | mainline | tracefs-open | off | — | — |
| powerpc64 | 6.6.144 | mainline | default | off | — | — |
| powerpc64 | 6.6.144 | mainline | kptr-hidden | off | — | — |
| powerpc64 | 6.6.144 | mainline | perf-open | off | — | — |
| powerpc64 | 6.6.144 | mainline | dmesg-open | off | — | — |
| powerpc64 | 6.6.144 | mainline | bpf-open | off | — | — |
| powerpc64 | 6.6.144 | mainline | hardened | off | — | — |
| powerpc64 | 6.6.144 | mainline | tracefs-open | off | — | — |
| powerpc64 | 7.0.0 | mainline | default | off | — | — |
| powerpc64 | 7.0.0 | mainline | kptr-hidden | off | — | — |
| powerpc64 | 7.0.0 | mainline | perf-open | off | — | — |
| powerpc64 | 7.0.0 | mainline | dmesg-open | off | — | — |
| powerpc64 | 7.0.0 | mainline | bpf-open | off | — | — |
| powerpc64 | 7.0.0 | mainline | hardened | off | — | — |
| powerpc64 | 7.0.0 | mainline | tracefs-open | off | — | — |
| ppc32 | 5.15.211 | mainline | default | on | 14 bits | coupled |
| ppc32 | 5.15.211 | mainline | kptr-hidden | on | 12 bits | coupled |
| ppc32 | 5.15.211 | mainline | perf-open | on | exact | coupled |
| ppc32 | 5.15.211 | mainline | dmesg-open | on | 14 bits | coupled |
| ppc32 | 5.15.211 | mainline | bpf-open | on | 14 bits | coupled |
| ppc32 | 5.15.211 | mainline | hardened | on | 14 bits | coupled |
| ppc32 | 5.15.211 | mainline | tracefs-open | on | 11 bits | coupled |
| ppc32 | 6.6.144 | mainline | default | on | 14 bits | coupled |
| ppc32 | 6.6.144 | mainline | kptr-hidden | on | 14 bits | coupled |
| ppc32 | 6.6.144 | mainline | perf-open | on | exact | coupled |
| ppc32 | 6.6.144 | mainline | dmesg-open | on | 14 bits | coupled |
| ppc32 | 6.6.144 | mainline | bpf-open | on | 14 bits | coupled |
| ppc32 | 6.6.144 | mainline | hardened | on | 14 bits | coupled |
| ppc32 | 6.6.144 | mainline | tracefs-open | on | 11 bits | coupled |
| ppc32 | 7.0.0 | mainline | default | on | 14 bits | coupled |
| ppc32 | 7.0.0 | mainline | kptr-hidden | on | 14 bits | coupled |
| ppc32 | 7.0.0 | mainline | perf-open | on | exact | coupled |
| ppc32 | 7.0.0 | mainline | dmesg-open | on | 14 bits | coupled |
| ppc32 | 7.0.0 | mainline | bpf-open | on | 14 bits | coupled |
| ppc32 | 7.0.0 | mainline | hardened | on | 11 bits | coupled |
| ppc32 | 7.0.0 | mainline | tracefs-open | on | 11 bits | coupled |
| ppc64le | 6.12.81-0-lts | alpine | default | off | — | — |
| ppc64le | 6.12.81-0-lts | alpine | kptr-hidden | off | — | — |
| ppc64le | 6.12.81-0-lts | alpine | perf-open | off | — | — |
| ppc64le | 6.12.81-0-lts | alpine | dmesg-open | off | — | — |
| ppc64le | 6.12.81-0-lts | alpine | bpf-open | off | — | — |
| ppc64le | 6.12.81-0-lts | alpine | hardened | off | — | — |
| ppc64le | 6.12.81-0-lts | alpine | tracefs-open | off | — | — |
| ppc64le | 5.15.211 | mainline | default | off | — | — |
| ppc64le | 5.15.211 | mainline | kptr-hidden | off | — | — |
| ppc64le | 5.15.211 | mainline | perf-open | off | — | — |
| ppc64le | 5.15.211 | mainline | dmesg-open | off | — | — |
| ppc64le | 5.15.211 | mainline | bpf-open | off | — | — |
| ppc64le | 5.15.211 | mainline | hardened | off | — | — |
| ppc64le | 5.15.211 | mainline | tracefs-open | off | — | — |
| ppc64le | 6.6.144 | mainline | default | off | — | — |
| ppc64le | 6.6.144 | mainline | kptr-hidden | off | — | — |
| ppc64le | 6.6.144 | mainline | perf-open | off | — | — |
| ppc64le | 6.6.144 | mainline | dmesg-open | off | — | — |
| ppc64le | 6.6.144 | mainline | bpf-open | off | — | — |
| ppc64le | 6.6.144 | mainline | hardened | off | — | — |
| ppc64le | 6.6.144 | mainline | tracefs-open | off | — | — |
| ppc64le | 7.0.0 | mainline | default | off | — | — |
| ppc64le | 7.0.0 | mainline | kptr-hidden | off | — | — |
| ppc64le | 7.0.0 | mainline | perf-open | off | — | — |
| ppc64le | 7.0.0 | mainline | dmesg-open | off | — | — |
| ppc64le | 7.0.0 | mainline | bpf-open | off | — | — |
| ppc64le | 7.0.0 | mainline | hardened | off | — | — |
| ppc64le | 7.0.0 | mainline | tracefs-open | off | — | — |
| riscv32 | 5.15.211 | mainline | default | off | — | — |
| riscv32 | 5.15.211 | mainline | kptr-hidden | off | — | — |
| riscv32 | 5.15.211 | mainline | perf-open | off | — | — |
| riscv32 | 5.15.211 | mainline | dmesg-open | off | — | — |
| riscv32 | 5.15.211 | mainline | bpf-open | off | — | — |
| riscv32 | 5.15.211 | mainline | hardened | off | — | — |
| riscv32 | 5.15.211 | mainline | tracefs-open | off | — | — |
| riscv32 | 6.6.144 | mainline | default | off | — | — |
| riscv32 | 6.6.144 | mainline | kptr-hidden | off | — | — |
| riscv32 | 6.6.144 | mainline | perf-open | off | — | — |
| riscv32 | 6.6.144 | mainline | dmesg-open | off | — | — |
| riscv32 | 6.6.144 | mainline | bpf-open | off | — | — |
| riscv32 | 6.6.144 | mainline | hardened | off | — | — |
| riscv32 | 6.6.144 | mainline | tracefs-open | off | — | — |
| riscv32 | 7.0.0 | mainline | default | off | — | — |
| riscv32 | 7.0.0 | mainline | kptr-hidden | off | — | — |
| riscv32 | 7.0.0 | mainline | perf-open | off | — | — |
| riscv32 | 7.0.0 | mainline | dmesg-open | off | — | — |
| riscv32 | 7.0.0 | mainline | bpf-open | off | — | — |
| riscv32 | 7.0.0 | mainline | hardened | off | — | — |
| riscv32 | 7.0.0 | mainline | tracefs-open | off | — | — |
| riscv64 | 6.18.44-0-lts | alpine | default | off | — | — |
| riscv64 | 6.18.44-0-lts | alpine | kptr-hidden | off | — | — |
| riscv64 | 6.18.44-0-lts | alpine | perf-open | off | — | — |
| riscv64 | 6.18.44-0-lts | alpine | dmesg-open | off | — | — |
| riscv64 | 6.18.44-0-lts | alpine | bpf-open | off | — | — |
| riscv64 | 6.18.44-0-lts | alpine | hardened | off | — | — |
| riscv64 | 6.18.44-0-lts | alpine | tracefs-open | off | — | — |
| riscv64 | 6.18.44-0-lts | alpine | no5lvl | off | — | — |
| riscv64 | 6.18.44-0-lts | alpine | no4lvl | off | — | — |
| riscv64 | 5.15.211 | mainline | default | off | — | — |
| riscv64 | 5.15.211 | mainline | kptr-hidden | off | — | — |
| riscv64 | 5.15.211 | mainline | perf-open | off | — | — |
| riscv64 | 5.15.211 | mainline | dmesg-open | off | — | — |
| riscv64 | 5.15.211 | mainline | bpf-open | off | — | — |
| riscv64 | 5.15.211 | mainline | hardened | off | — | — |
| riscv64 | 5.15.211 | mainline | tracefs-open | off | — | — |
| riscv64 | 5.15.211 | mainline | no5lvl | off | — | — |
| riscv64 | 5.15.211 | mainline | no4lvl | off | — | — |
| riscv64 | 6.6.144 | mainline | default | on | exact | 9 bits |
| riscv64 | 6.6.144 | mainline | kptr-hidden | on | exact | 9 bits |
| riscv64 | 6.6.144 | mainline | perf-open | on | exact | 9 bits |
| riscv64 | 6.6.144 | mainline | dmesg-open | on | exact | 9 bits |
| riscv64 | 6.6.144 | mainline | bpf-open | on | exact | 9 bits |
| riscv64 | 6.6.144 | mainline | hardened | on | 4 bits | 9 bits |
| riscv64 | 6.6.144 | mainline | tracefs-open | on | exact | 9 bits |
| riscv64 | 6.6.144 | mainline | no5lvl | on | exact | 9 bits |
| riscv64 | 6.6.144 | mainline | no4lvl | on | exact | 9 bits |
| riscv64 | 7.0.0 | mainline | default | on | 9 bits | 9 bits |
| riscv64 | 7.0.0 | mainline | kptr-hidden | on | 9 bits | 9 bits |
| riscv64 | 7.0.0 | mainline | perf-open | on | exact | 9 bits |
| riscv64 | 7.0.0 | mainline | dmesg-open | on | 9 bits | 9 bits |
| riscv64 | 7.0.0 | mainline | bpf-open | on | 9 bits | 9 bits |
| riscv64 | 7.0.0 | mainline | hardened | on | 9 bits | 9 bits |
| riscv64 | 7.0.0 | mainline | tracefs-open | on | 4 bits | 9 bits |
| riscv64 | 7.0.0 | mainline | no5lvl | on | 9 bits | 9 bits |
| riscv64 | 7.0.0 | mainline | no4lvl | on | 16 bits | 9 bits |
| s390x | 6.12.81-0-lts | alpine | default | on | 39 bits | 10 bits |
| s390x | 6.12.81-0-lts | alpine | kptr-hidden | on | 39 bits | 10 bits |
| s390x | 6.12.81-0-lts | alpine | perf-open | on | exact | 10 bits |
| s390x | 6.12.81-0-lts | alpine | dmesg-open | on | 39 bits | 10 bits |
| s390x | 6.12.81-0-lts | alpine | bpf-open | on | 28 bits | 10 bits |
| s390x | 6.12.81-0-lts | alpine | hardened | on | 39 bits | 10 bits |
| s390x | 6.12.81-0-lts | alpine | tracefs-open | on | 28 bits | 10 bits |
| s390x | 5.15.211 | mainline | default | on | 17 bits | 10 bits |
| s390x | 5.15.211 | mainline | kptr-hidden | on | 17 bits | 10 bits |
| s390x | 5.15.211 | mainline | perf-open | on | exact | 9 bits |
| s390x | 5.15.211 | mainline | dmesg-open | on | 17 bits | 10 bits |
| s390x | 5.15.211 | mainline | bpf-open | on | 17 bits | 10 bits |
| s390x | 5.15.211 | mainline | hardened | on | 17 bits | 10 bits |
| s390x | 5.15.211 | mainline | tracefs-open | on | 11 bits | 10 bits |
| s390x | 6.6.144 | mainline | default | on | 17 bits | 10 bits |
| s390x | 6.6.144 | mainline | kptr-hidden | on | 17 bits | 10 bits |
| s390x | 6.6.144 | mainline | perf-open | on | exact | 9 bits |
| s390x | 6.6.144 | mainline | dmesg-open | on | 17 bits | 10 bits |
| s390x | 6.6.144 | mainline | bpf-open | on | 17 bits | 10 bits |
| s390x | 6.6.144 | mainline | hardened | on | 17 bits | 10 bits |
| s390x | 6.6.144 | mainline | tracefs-open | on | 7 bits | 10 bits |
| s390x | 7.0.0 | mainline | default | on | 29 bits | 10 bits |
| s390x | 7.0.0 | mainline | kptr-hidden | on | 29 bits | 10 bits |
| s390x | 7.0.0 | mainline | perf-open | on | exact | 10 bits |
| s390x | 7.0.0 | mainline | dmesg-open | on | 29 bits | 10 bits |
| s390x | 7.0.0 | mainline | bpf-open | on | 29 bits | 10 bits |
| s390x | 7.0.0 | mainline | hardened | on | 29 bits | 10 bits |
| s390x | 7.0.0 | mainline | tracefs-open | on | 12 bits | 10 bits |
| s390x | 7.0.0 (4level) | mainline | default | on | 39 bits | 10 bits |
| s390x | 7.0.0 (4level) | mainline | kptr-hidden | on | 39 bits | 10 bits |
| s390x | 7.0.0 (4level) | mainline | perf-open | on | exact | 10 bits |
| s390x | 7.0.0 (4level) | mainline | dmesg-open | on | 39 bits | 10 bits |
| s390x | 7.0.0 (4level) | mainline | bpf-open | on | 39 bits | 10 bits |
| s390x | 7.0.0 (4level) | mainline | hardened | on | 39 bits | 10 bits |
| s390x | 7.0.0 (4level) | mainline | tracefs-open | on | 12 bits | 10 bits |
| x86_64 | 6.12.81-0-virt | alpine | default | on | 2 bits | 6 bits |
| x86_64 | 6.12.81-0-virt | alpine | kptr-hidden | on | 2 bits | 6 bits |
| x86_64 | 6.12.81-0-virt | alpine | perf-open | on | exact | 6 bits |
| x86_64 | 6.12.81-0-virt | alpine | dmesg-open | on | 2 bits | 6 bits |
| x86_64 | 6.12.81-0-virt | alpine | bpf-open | on | exact | 6 bits |
| x86_64 | 6.12.81-0-virt | alpine | hardened | on | 2 bits | 6 bits |
| x86_64 | 6.12.81-0-virt | alpine | tracefs-open | on | exact | 6 bits |
| x86_64 | 6.12.81-0-virt | alpine | no5lvl | on | 2 bits | 6 bits |
| x86_64 | 6.12.81-0-virt | alpine | la57 | on | 2 bits | 6 bits |
| x86_64 | 4.19.325 | mainline | default | on | 4 bits | 9 bits |
| x86_64 | 4.19.325 | mainline | kptr-hidden | on | 4 bits | 9 bits |
| x86_64 | 4.19.325 | mainline | perf-open | on | exact | 9 bits |
| x86_64 | 4.19.325 | mainline | dmesg-open | on | 4 bits | 9 bits |
| x86_64 | 4.19.325 | mainline | bpf-open | on | 4 bits | 9 bits |
| x86_64 | 4.19.325 | mainline | hardened | on | 4 bits | 9 bits |
| x86_64 | 4.19.325 | mainline | tracefs-open | on | 4 bits | 9 bits |
| x86_64 | 4.19.325 | mainline | no5lvl | on | 4 bits | 9 bits |
| x86_64 | 4.19.325 | mainline | la57 | on | 4 bits | 9 bits |
| x86_64 | 5.15.211 | mainline | default | on | 5 bits | 9 bits |
| x86_64 | 5.15.211 | mainline | kptr-hidden | on | 5 bits | 9 bits |
| x86_64 | 5.15.211 | mainline | perf-open | on | exact | 9 bits |
| x86_64 | 5.15.211 | mainline | dmesg-open | on | 5 bits | 9 bits |
| x86_64 | 5.15.211 | mainline | bpf-open | on | 5 bits | 9 bits |
| x86_64 | 5.15.211 | mainline | hardened | on | 5 bits | 9 bits |
| x86_64 | 5.15.211 | mainline | tracefs-open | on | 4 bits | 9 bits |
| x86_64 | 5.15.211 | mainline | no5lvl | on | 5 bits | 9 bits |
| x86_64 | 5.15.211 | mainline | la57 | on | 5 bits | 9 bits |
| x86_64 | 6.6.144 | mainline | default | on | 5 bits | 9 bits |
| x86_64 | 6.6.144 | mainline | kptr-hidden | on | 5 bits | 9 bits |
| x86_64 | 6.6.144 | mainline | perf-open | on | exact | 9 bits |
| x86_64 | 6.6.144 | mainline | dmesg-open | on | 5 bits | 9 bits |
| x86_64 | 6.6.144 | mainline | bpf-open | on | 5 bits | 9 bits |
| x86_64 | 6.6.144 | mainline | hardened | on | 5 bits | 9 bits |
| x86_64 | 6.6.144 | mainline | tracefs-open | on | 4 bits | 9 bits |
| x86_64 | 6.6.144 | mainline | no5lvl | on | 5 bits | 9 bits |
| x86_64 | 6.6.144 | mainline | la57 | on | 5 bits | 9 bits |
| x86_64 | 7.0.0 | mainline | default | on | 9 bits | 9 bits |
| x86_64 | 7.0.0 | mainline | kptr-hidden | on | 9 bits | 9 bits |
| x86_64 | 7.0.0 | mainline | perf-open | on | exact | 9 bits |
| x86_64 | 7.0.0 | mainline | dmesg-open | on | 9 bits | 9 bits |
| x86_64 | 7.0.0 | mainline | bpf-open | on | 9 bits | 9 bits |
| x86_64 | 7.0.0 | mainline | hardened | on | 9 bits | 9 bits |
| x86_64 | 7.0.0 | mainline | tracefs-open | on | 5 bits | 9 bits |
| x86_64 | 7.0.0 | mainline | no5lvl | on | 9 bits | 9 bits |
| x86_64 | 7.0.0 | mainline | la57 | on | 9 bits | 9 bits |

Each row is one boot, and the residual is not a constant of the cell. Where the
architecture redraws the image base every boot, a figure the evidence actually
moves follows where the base landed — the mechanism, and which cells it touches,
are set out under the chart above. On this kernel line it reaches `ppc32` and
the `loongarch64` 6.x cells; a figure that is the starting window unmoved
repeats exactly, because a prior is a constant.

Two consequences follow for reading the table. A small difference between two
profile rows of the same cell may be the draw rather than the profile, since the
two rows are separate boots. A difference in the *narrowing* direction under a
more restrictive profile is always the draw and never the profile, because
withholding a source can only widen a guaranteed window. A profile effect shows
instead as a large and directional change, such as `perf-open` resolving to
`exact`.

The soundness verdict does not vary with the draw: on every boot the guaranteed
window contained the true base, which is the property this table gates on.

</details>

What the profiles do is described in [§2](#2-live-across-architectures) above;
what the table adds is where a profile makes no difference, and why.

On a stock kernel `default` is *not* `exact`: at the upstream
`perf_event_paranoid=2`, `/proc/kallsyms` is zeroed even with `kptr_restrict=0`
(`kallsyms_show_value()` needs `perf_event_paranoid<=1` or `CAP_SYSLOG`), so the
base comes from sound inference alone. `kptr-hidden` therefore lands on the same
numbers — it removes a source that was already dark.

`perf-open` is the profile that recovers the base, and it does so on every
KASLR-on cell whose kernel is built with `CONFIG_PERF_EVENTS`. That build
dependency is why its two unlocks are really one lever: `kallsyms_show_value()`
reaches its `kallsyms_for_perf()` shortcut only inside the same `#ifdef` that
provides `perf_event_open`. On a kernel built without it the profile is inert —
the sysctl it writes does not exist, and `kptr_restrict=0` falls through to a
`CAP_SYSLOG` check an unprivileged reader fails, so the symbol table stays
readable and wholly zeroed at once and every profile reports the same window.

The `phys residual` moves independently, because `/proc/iomem` zeroes its
`Kernel code` addresses for any non-root reader regardless of `kptr_restrict` or
`perf_event_paranoid`. So the physical axis is largely unmoved by the profiles:
the perf unlock recovers the virtual text base, not the physical one.

Architectures showing KASLR `off` receive no seed under the default qemu machine
(or the port has no text KASLR), so the kernel boots unrandomized and `residual`
reads `—`. KASLD still bounds the fixed base soundly via the disabled-base path;
it is simply not a KASLR-defeat result, so the column does not score it. riscv64
is the mixed case: its text KASLR needs both a kernel built for it and a
boot-supplied seed, so the mainline 6.6 and 7.0 cells are built with
`RANDOMIZE_BASE` and booted with a per-boot `kaslr-seed` spliced into the device
tree, while 5.15 (predating riscv KASLR) and the Alpine kernel stay honestly
`off`.

### Memory-KASLR region bases

On x86_64, `CONFIG_RANDOMIZE_MEMORY` randomizes the direct-map
(`page_offset_base`), vmalloc (`vmalloc_base`) and vmemmap (`vmemmap_base`)
region bases independently of the kernel text. Each live boot captures their true
values from `/proc/kcore` — the resolved variable's word, never the
terabyte-sparse whole — as ground truth, and gates the engine's resolved window
for each against it. A cell whose region window excludes the true base is withheld
exactly like a text-base violation; this gate runs in the live matrix and offline
via `validate-bundle`, and every gated cell is sound.

The per-region *residual entropy* is not yet tabulated here: the harness gates
each region window for soundness but does not yet emit its residual bit-count.
That is a reporting gap, not a soundness gap — the windows are checked to contain
the truth today; only the "how many bits survived" number for these three
quantities is still to be surfaced.

Scope (see [Architecture characterization](#architecture-characterization)):
these three region bases are independently randomized only under
`CONFIG_RANDOMIZE_MEMORY`, i.e. x86_64. The other decoupled architectures
randomize the linear map by a different mechanism (`aarch64` `memstart_addr`,
`s390` identity base, `riscv64` `kernel_map.page_offset`), which the engine
bounds but this harness does not ground-truth; a leak of one of those bases only
makes the reported residual an upper bound, never unsound. On coupled
architectures the direct map is a static projection of kernel text and carries no
independent base to randomize.

### Vantage sensitivity

The matrix carries one column per vantage — the restriction profile the analysis
runs under, the unprivileged uid being the same in all of them. Reading across a
row rather than down a column answers a different question: not how much
survives, but which gate is holding it.

One gate dominates. `perf-open` reaches `exact` on every KASLR-on row below, on
every architecture, kernel line and configuration tested, without exception.
Where `CONFIG_PERF_EVENTS` is built in, lowering `perf_event_paranoid` hands over
the image base outright, and nothing else on the axis is comparable to it. A
kernel that leaves perf open to unprivileged callers has no image-base entropy to
defend, whatever its architecture would otherwise supply.

The mitigation reached for first is the one that does least. `kptr_restrict`
leaves 40 of the 42 KASLR-on cells bit-identical, and the two that move are
both `loongarch64`, one gaining a bit and one losing one — movement in both
directions at once, which is not the signature of a mitigation taking
effect. The routes that matter either parse the kernel's own boot log or
recover an address from a pointer hash, and neither is what `%pK`
suppresses. Hiding pointers does not hide the base.

With perf shut, what remains is interface-specific and unevenly spread. Opening
`tracefs` alone narrows 22 of the 42 KASLR-on cells, across nine architectures,
by anything from one bit to twenty-seven. The widest and the narrowest, with a
few in between:

| cell | default | tracefs-open | given up |
|------|---------|--------------|----------|
| `s390x` 4-level paging | 39 bits | 12 bits | 27 bits |
| `aarch64` with function tracing | 31 bits | 7 bits | 24 bits |
| `s390x` | 29 bits | 12 bits | 17 bits |
| `mips64el` | 14 bits | 8 bits | 6 bits |
| `riscv64` | 9 bits | 4 bits | 5 bits |
| `x86_64` | 9 bits | 5 bits | 4 bits |
| `i686` | 8 bits | 4 bits | 4 bits |
| `x86_64` (older line) | 5 bits | 4 bits | 1 bit |

Two files account for it, and neither is a `%pK` consumer.
`available_filter_functions_addrs` publishes a byte-exact table of text
addresses, and exists only where `DYNAMIC_FTRACE` is built in: the `s390`
defconfig enables function tracing and carries it as shipped, while the `arm64`
defconfig turns tracing off explicitly, which is why the `aarch64` figure above
comes from a cell built to have it. `printk_formats` needs no tracing
configuration at all and is what narrows the rest, `i686` among them; across the
matrix it contributes on 46 cells against the address table's 12, and no third
tracefs file contributes anywhere. Neither is named in any of the sysctls above,
and which of the two a kernel carries follows from a tracing option rather than
from a hardening decision.

Every cell runs all seven of these profiles, so any row in the matrix above can
be read straight across; the `no5lvl`, `no4lvl` and `la57` columns are
paging-mode variants and appear only on the architectures that offer them.

### Kernel-configuration sensitivity

The matrix covers this axis in part. A kernel's paging mode and virtual-address
width — x86_64 4- vs 5-level paging, `aarch64` VA36 / VA39 / VA42 / VA47
alongside the default VA48, the 32-bit VMSPLIT variants — shift the layout
windows and are a distinct axis from the kernel line. This axis is a direct test
of the engine's *structural* soundness: a wrong paging assumption or an
over-coarse alignment moves the image-base window, which is exactly the window
the soundness gate already checks (it is how past VA-bits and alignment bugs
surfaced), so each configuration cell is another soundness data point.

On `aarch64` the width fixes the page size, so those four cells also span all
three granules — VA39 at 4K, VA36 and VA47 at 16K, VA42 at 64K. VA52 is the one
width left uncovered. `x86_64` and `riscv64` reach the same axis from a single
image through the `no5lvl` / `no4lvl` / `la57` boot parameters, and `armv7` and
`i686` carry a purpose-built 2G/2G split against the default 3G/1G. The
configuration axes still outside the matrix are listed under [Scope](#scope).

### Speculative narrowing (the likely window)

`residual` above is the **guaranteed** window — resolved only from signals at or
above the sound floor, and gate-checked to contain the truth. The engine also
resolves a **likely** window: the guaranteed window narrowed further by sub-floor
signals (timing side-channels, a single leaked pointer, config defaults). It is a
best-guess, always a subset of guaranteed, and — unlike guaranteed — it is *not*
gated to contain the truth. It surfaces in `-j` JSON as the `likely` /
`likely_physical` objects, emitted only when strictly tighter than guaranteed.

`tests/vm/run spec-table` lists the cells where the likely window beats
guaranteed, and by default only the *reproducible* narrowings: deterministic
`parsed` signals — a file, a leaked pointer, a config default — that beat the
sound floor the same way on every run.

Which cells appear, and which component supplies each, is not recorded here.
Membership turns over as leaks are patched upstream and as the kernel matrix
moves, so the command is the answer; a list transcribed into this document would
describe kernels that are no longer in the run.

The shape is stable in one respect: where a perf or kallsyms signal exists it is
a *sound* pin, so it resolves the **guaranteed** window under `perf-open` (to
`exact`) and never the likely one — a sound signal has nothing left to narrow.

The memory-map heuristics that bound RAM from world-readable facts are the
opposite case, and they dominate the listing rather than staying out of it:
the device-tree `memory` node alone is named by most of the rows the command
prints.

`aarch64` shows what that costs. A 48-bit kernel has two possible linear-map
bases, one for the layout adopted in v5.4 and one for the layout before it,
and an unprivileged reader sees nothing that tells them apart: the width
resolves exactly while `PAGE_OFFSET` stays at two candidates. The guaranteed
window respects that ambiguity and spans both image bands, from
`0xffff000008000000`. The likely window breaks the tie in favour of the
modern layout, which lifts the floor to `0xffff800008000000` — correct for
every kernel since v5.4, and wrong for one before it, where the image sits
below the linear map rather than above it. The single pre-flip cell in the
matrix is the single cell reporting `**NO**`, at every vantage where the
signal is reachable, while the cells sharing its width and its guaranteed
floor contain their truth.

That is the column doing its job rather than a defect: the likely window is
a best guess and is not gated to contain the truth, which is why the
soundness claim rests on the guaranteed matrix above and never on this
table.

The BPF verifier-log table is the counter-example worth noting: it used to be
listed here, and no longer is, because its match now resolves the guaranteed
window itself under `bpf-open` — a signal that graduates out of `likely` is the
outcome to want.

Absolute recovery is monotonic in how much the profile relaxes: `perf-open`
recovers the most, `hardened` the least, with `default`/`kptr-hidden`/`dmesg-open`
between — read that off the guaranteed matrix above, not the likely window.

**Timing side-channel narrowings are excluded by default, and no figure for them
is published here.** The likely window can also be narrowed by a
microarchitectural side channel — a cache or speculation oracle such as
`prefetch` or `entrybleed` that survives even `perf_event_paranoid=3`, pinning
the base where no parsed signal can. Such rows do appear in these runs, and they
are withheld for two independent reasons.

The first is reproducibility, and it is the whole reason the two are treated
differently. A parsed narrowing reproduces on any machine that boots the same
image: the signal is in the file, so the reader gets the same answer as the run
that produced it. A timing oracle's success is instead a function of the host
CPU — on a mitigated part (microcode or hypervisor Spectre-v2 defences) or a
lower microarchitecture the `prefetch` signal flattens, and the same cell narrows
less or not at all. It varies run to run on one machine, so a number derived from
one run is not a result a reader can check.

The second is that this harness is
the wrong instrument for the measurement. The x86-64 cells boot under KVM, where a
prefetch-timing signal can be an artifact of nested paging rather than the
behaviour it is taken to demonstrate — so a bit-count obtained here would
characterise the hypervisor as much as the technique, in either direction.
Neither reason is that the technique fails; these channels are validated
separately, against hardware, and are out of the matrix's scope (see
[Scope](#scope)). `tests/vm/run spec-table --with-timing` will list them for
anyone reproducing the run locally, with the same caveat attached.

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
rather than pass. The corpus spans 13 architecture variants across
distributions (Alpine, Debian, Ubuntu/Raspbian) and kernels from 4.14 to 7.0:

| family | example kernels |
|--------|-----------------|
| x86_64, i686 | 5.15 – 7.0 (Alpine, Debian, Ubuntu) |
| aarch64, armv7 | 4.14 – 7.0 |
| ppc64, ppc32 | 5.15 – 7.0 |
| riscv64, riscv32 | 5.10 – 6.18 |
| s390x | 5.15 – 6.19 |
| loongarch64 | 6.18 |
| mips32, mips32el, mips64el | 4.19 – 6.15 |

## Scope

These checks cover soundness — whether the inferred range contains the truth —
across a broad set of architectures, kernel versions, and reader-privilege
levels. They use one stock kernel configuration per architecture, plus
purpose-built cells on the two configuration axes that relocate the kernel
memory map: VA-bits / paging mode (`aarch64` 36/39/42/47, and `x86_64` /
`riscv64` via `no5lvl` / `no4lvl` / `la57` from a single image) and VMSPLIT
(`armv7` and `i686` at 2G/2G). Those are the axes a wrong answer would be
*silent* on, because every other cell is built at the architecture's default
split and paging mode, so a model that assumed the default would pass the whole
matrix by coincidence. The remaining configuration axes — endianness, and
individual `CONFIG_*` toggles — are not covered. Timing and side-channel
components are validated separately, as their behaviour depends on hardware
rather than configuration.

The matrix exercises the **kernel**, not a distribution's userland. Each cell
boots straight into the analysis harness from a minimal initramfs, so no distro
init, `sysctl.d` drop-ins, service sandboxing, or LSM policy (AppArmor / SELinux /
seccomp) ever runs. Every profile therefore measures the kernel's *own* posture —
its compile-time sysctl defaults plus the one explicit sysctl vector the harness
sets — and nothing a userland would layer on top. That scope boundary cuts both ways. A real
distribution install may enforce controls these cells do not, so an actual
system can be *stricter* than even the `hardened` column. And userland is
itself a leak surface the matrix does not exercise — setuid helpers,
privileged daemons, and files a running service populates — so an actual
system may expose *more* than the `default` column. The isolation is deliberate: it attributes each result to a
named kernel and a declared sysctl vector, keeping the cells reproducible and
independent of any particular distribution's userspace.

Neither an unprivileged user namespace nor unprivileged eBPF widens
text-base recovery, so neither is a scenario of its own. A user namespace does
not help because the symbol table, `/proc/iomem`, `dmesg`, and
`perf_event_open` gates all check `capable()` in the *initial* user namespace,
which the `ns_capable()` a child namespace grants cannot satisfy — so the
`default` and `hardened` results already bound a userns-wielding attacker for the
text base. A user namespace reaches only `ns_capable`-gated leaks through created
virtual devices (a third-party-driver ioctl surface), which the minimal
initramfs does not expose.

eBPF does not help either. Where it is enabled
(`kernel.unprivileged_bpf_disabled=0`; the upstream default flipped to disabled
in 5.16), the disclosure KASLD does exploit is the verifier log printing an
unmasked `struct bpf_map *` — a *direct-map* virtual address, not the text base.
Like a `%pK` `/proc/net` socket pointer, it bounds `page_offset` / the direct map
— a memory-KASLR region this matrix does not score — so it leaves the
text-image-base residual unchanged (the relevant verifier-log hole is
version-specific and was masked in 7.2). Both are disclosure channels in their
own right, but of kernel *data* addresses, not the text base measured here.

These are limits on what the checks here *verify*. For what a KASLD result means
when it is run against a target — in particular why a failure to recover the base
is not evidence the system is secure — see [limitations.md](limitations.md).
