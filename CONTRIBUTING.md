# Contributing to KASLD

KASLD's architecture is a simple contract: each **component** is a
standalone executable that probes one data source and prints tagged lines
to stdout. The **orchestrator** discovers, runs, and post-processes
components automatically — no registration, no linking, no Makefile
changes. The **inference engine** runs after collection, narrowing kernel
layout quantities from the merged observations.

This document covers everything a component author or rule author needs.
For end-user material, see [README.md](README.md) and
[docs/usage.md](docs/usage.md).

## Table of Contents

- [Architecture](#architecture)
  - [Component model](#component-model)
  - [Phases](#phases)
  - [Inference engine](#inference-engine)
  - [Cross-region derivation](#cross-region-derivation)
    - [Component-level derivation](#component-level-derivation)
    - [Inference-time derivation](#inference-time-derivation)
  - [Kernel version detection](#kernel-version-detection)
- [Writing a component](#writing-a-component)
  - [Tagged line protocol](#tagged-line-protocol)
  - [Position vs. confidence](#position-vs-confidence)
  - [Regions](#regions)
  - [Confidence](#confidence)
  - [Emitter API](#emitter-api)
  - [KASLR runtime states](#kaslr-runtime-states)
  - [Exit code convention](#exit-code-convention)
  - [Minimal component](#minimal-component)
  - [Component metadata](#component-metadata)
- [API reference](#api-reference)

---

## Architecture

### Component model

The orchestrator runs each component as an isolated child process:

1. `fork()` + `execl()` — the component runs in its own process group
2. stdout and stderr are merged into a single pipe back to the orchestrator
3. The orchestrator reads lines from the pipe, capturing tagged lines as
   results and (in verbose mode) printing all output
4. A per-component timeout (default: 30 seconds, configurable via
   `--timeout`) kills the component and its children if it does not exit
   in time
5. The exit code signals the component's relationship with its data
   source (see [Exit code convention](#exit-code-convention) below).
   Tagged lines emitted before exit (or timeout) are always captured.

This model means a component that segfaults, hangs, or exits with an error
does not affect other components or the orchestrator.

Tagged lines are parsed into structured records (type, region, position,
confidence, bounds, sample), validated against the region's expected
virtual address space, and merged across components by
`(type, region, name)`. Components do not need to align addresses or
validate ranges — they emit via the intent-revealing helpers and the
orchestrator handles parsing, merging, bound tightening, and consensus.

### Phases

Components run in two phases:

| Phase | Purpose | Assignment |
|---|---|---|
| **Inference** | All non-probing components | `.kasld_meta` declares `phase:inference` (default when `phase:` is omitted) |
| **Probing** | Side-channels, timing attacks, brute-force | `.kasld_meta` declares `phase:probing` — e.g. `prefetch`, `entrybleed`, `databounce` |

Inference-phase components run in a fixed-width worker pool (default: nproc
threads); pass `--workers 0` to run sequentially, and verbose mode (`-v`) runs
sequentially to avoid interleaved output. These components only *collect* — the
results are merged after the pool joins, and all inference happens afterward in
a single pass of the engine, so worker scheduling and component order have no
effect on the result. The probing phase runs after all inference components,
unconditionally. Components that cannot run on the current system (KASLR
disabled, lockdown, access denied) return `KASLD_EXIT_NOPERM` or
`KASLD_EXIT_UNAVAILABLE` and are recorded as such in the component log.

New components default to the inference phase when `phase:` is omitted
from `KASLD_META()`. Probing phase membership requires `phase:probing`
in `.kasld_meta` — no other registration needed.

Some components are marked `status:experimental` in their `.kasld_meta`
and are skipped by default. These are components with narrow hardware
requirements, very long runtimes, or significant noise. Pass
`--experimental` (`-x`) to include them. The number of skipped
components is noted in the "Running N components..." line. Setting
`KASLD_EXPERIMENTAL=1` in the environment has the same effect.

Pass `--skip PATTERN` (`-s`) to exclude one or more components by name.
Patterns use `fnmatch(3)` glob syntax — e.g. `--skip 'dmesg_*'` skips all
components whose name starts with `dmesg_`. Comma-separate multiple patterns
in a single flag or repeat the flag to accumulate them:
`--skip dmesg_backtrace,dmesg_e820` and `--skip dmesg_backtrace --skip dmesg_e820`
are equivalent.

### Inference engine

After the orchestrator has collected and merged all component results, it runs
a single layered evidential engine (compiled into the orchestrator binary) to
resolve the layout. There is one inference path — no plugin system, no phase
loop. The engine has three layers:

- **Observations** — the collected results plus scalar system facts (kernel
  image size, MemTotal, physical-address bits, …), gathered into an evidence
  set.
- **Rules** (`src/rules/*.c`) — ~60 pure functions that read the evidence and
  the current estimates and emit *constraints* (`≥`, `≤`, `=`, alignment,
  membership, exclusion) or *verdicts* (invalidate a result) on
  the quantities. A rule does no I/O and has no side effects, so soundness is
  provable in isolation and rule order doesn't matter.
- **Estimates** — each quantity (virtual/physical text base, `PAGE_OFFSET`,
  `vmalloc`/`vmemmap` base, KASLR alignment, VA bits) starts at its honest
  compile-time bound and only ever narrows.

The resolver re-runs every rule to a fixpoint, so a constraint one rule derives
(e.g. a tightened `PAGE_OFFSET`) feeds the next pass automatically. The
resolved estimates then drive the reported summary, slot counts, and entropy.

Every rule is listed once in `src/engine_rules.c` (the single registry shared
by the orchestrator and the test suite). Adding a rule is a new
`src/rules/<name>.c` plus one line there; the rule signature is
`int rule_<name>(const struct evidence_set *, const struct estimate *,
struct constraint *out, int out_max)` — read the existing rules in
`src/rules/` for the pattern, and the contract enforced by the unit tests
in `tests/test_engine.c`. Per-rule soundness is the test gate.

### Cross-region derivation

The kernel address space contains distinct regions (text, modules,
direct map, initrd, RAM landmarks, …) at different addresses. On some
architectures these are at fixed offsets from each other (coupled), so a
leak from one region can derive addresses in another. KASLD exploits this
at two levels: components can emit derived results directly, and engine
rules narrow bounds and synthesize new derived records during the
fixpoint loop after collecting all leaked results.

#### Component-level derivation

Components that leak a physical address can convert it to a direct-map
virtual address using `phys_to_directmap_virt(p)`, guarded by
`#ifdef phys_to_directmap_virt` so the derivation is compiled out on
arches where the projection is unsound (x86_64 `CONFIG_RANDOMIZE_MEMORY`
randomises the direct-map base, arm64 / riscv64 / s390 keep text and
direct map at independent runtime offsets). The component emits two
records — one `PHYS`, one `VIRT` — both with the same `(region, name)`.
The merge pass keeps them as separate records (different `type`) while
engine rules use the pair to derive `PAGE_OFFSET`.

#### Inference-time derivation

Engine rules read the merged records and tighten the quantity estimates
(virtual/physical text base, `PAGE_OFFSET`, etc.), emitting constraints when a
derivation is sound. Estimates only ever narrow, never widen.

Key rules for cross-region derivation:

- **`phys_virt_synth`** — pairs a `VIRT/REGION_DIRECTMAP` leak with a
  matching `PHYS` DRAM leak from the same `origin` to compute
  `PAGE_OFFSET = V − P`. The same-`origin` pairing is the tightest
  signal: it identifies the same kernel object across both address
  spaces. Per-origin candidates are accumulated, and `virt_page_offset_min/max`
  are tightened to the consensus when candidates agree within
  `virt_kaslr_align`.

- **`randomize_memory_page_offset`** (x86_64 only) — derives
  `virt_page_offset_base` (the randomized direct-map start under
  `CONFIG_RANDOMIZE_MEMORY`) from a `VIRT/REGION_DIRECTMAP` leak and a
  `PHYS/REGION_RAM` base record, with a 1 GiB alignment check.

- **`directmap_page_offset_bounds`** — bounds `PAGE_OFFSET` from a
  `VIRT/REGION_DIRECTMAP` leak: `PAGE_OFFSET ≤ V_min`, and
  `PAGE_OFFSET > V_min − phys_span` where `phys_span` is derived from
  `MemTotal` and the observed physical floor.

- **`kernel_image_phys_bound`** — uses `PHYS/REGION_KERNEL_BSS`
  witnesses (which sit past `_sdata`) to tighten `phys_base_max`. Falls
  back to plain `PHYS/REGION_KERNEL_*` witnesses for a baseline bound.

- **`dram_floor_bound`** / **`dram_ceiling`** — use the minimum and maximum
  observed physical addresses in DRAM regions (RAM, DMA, DMA32, initrd,
  reserved, swiotlb, vmcoreinfo, kernel-image regions) to bound the
  KASLR text window from both sides.

- **`text_cluster_filter`** — drops outlier `VIRT/REGION_KERNEL_TEXT`
  candidates that disagree with the cluster median by more than a slot
  threshold.

- **`initrd_phys_exclude`** / **`firmware_memmap_holes`** — emit `C_EXCLUDE`
  verdicts against `PHYS` kernel-image candidates that fall inside reserved
  intervals or outside any System RAM range, removing them from the candidate
  set for the physical text base.

- **`page_offset_from_landmark`** / **`page_offset_from_config`** — pin
  `Q_PAGE_OFFSET` from a `pageoffset` landmark or `CONFIG_PAGE_OFFSET`; every
  dependent quantity is then resolved against the pinned value (this is how a
  runtime vmsplit propagates on coupled architectures).

On **coupled** architectures (x86_32, arm32, MIPS, PowerPC, LoongArch,
riscv32), a single leak from any region can produce the KASLR slide via
arithmetic on the compile-time `PAGE_OFFSET`, `PHYS_OFFSET`, and
`TEXT_OFFSET` constants (with `PAGE_OFFSET` itself runtime-detected when
vmsplit differs from the compile-time default).

On **decoupled** architectures (x86_64, arm64, riscv64, s390), physical
and virtual KASLR are randomised independently, so physical results
cannot derive virtual text directly. The summary prints a note when
physical results exist that would have been derivable on a coupled
system.

RISC-V 64-bit is a special case: its module region is anchored to the
kernel image (`MODULES_VADDR = _end − 2 GiB`), so module addresses
provide an additional derivation path that `module_text_bound` exploits
to estimate `_end` and bound `kernel_text` from above.

### Kernel version detection

Some techniques (e.g., EntryBleed) have been mitigated in specific mainline
kernel releases. It would seem natural to check `uname -r` and skip components
that target patched vulnerabilities.

KASLD deliberately does not do this. Distribution kernels (Ubuntu, Debian, RHEL,
SUSE, etc.) backport security fixes extensively, and their version numbers
do not correspond to the mainline release where a fix appeared:

* Ubuntu ships `4.4.0-xxx` and `4.15.0-xxx` LTS kernels that contain
  backported fixes from mainline 5.x and 6.x.
* RHEL ships `3.10.0-xxx` kernels with fixes from mainline 4.x and 5.x.
* A kernel reporting `6.8.0` may lack a fix from mainline 6.3, or include
  a fix from mainline 6.12, depending on the distributor.

Version-based gating would be wrong in both directions: skipping a technique
on a kernel that is actually vulnerable (false negative), or running a
technique on a kernel that has already been patched (false positive).

Instead, KASLD treats each component as its own detector. Components probe the
actual kernel — they either produce a result or they don't. Side-channel
components that target patched vulnerabilities will time out (bounded by
`--timeout`, default 30 seconds) or exit with no output, which the orchestrator
handles gracefully. Filesystem-based components that lack access typically fail
in under a second.

This design means KASLD is correct on any kernel — mainline, distro, custom,
or embedded — without maintaining per-component version ranges that would be
inaccurate for most real-world deployments.

---

## Writing a component

### Tagged line protocol

Components communicate results to the orchestrator via tagged lines on
stdout:

```
<type> <region>[:<name>] pos=<pos> conf=<conf> [lo=<hex>] [hi=<hex>|sz=<hex>] [sample=<hex>] [base_align=<hex>]
```

| Field | Format | Description |
|---|---|---|
| `type` | Single char: `P` or `V` | `P` = physical, `V` = virtual |
| `region` | Wire name from the `kasld_region` enum (snake_case) | What kind of kernel memory is at the address — closed vocabulary; see "Regions" below |
| `name` | Optional, after the first `:` | The specific instance, when known (kernel symbol, ACPI OEM ID, module name, PCI BDF). Names may legitimately contain `:` (e.g. PCI BDF `0000:00:14.0`); the split is on the first `:` only |
| `pos` | `base` / `top` / `interior` / `unknown` | What `sample` represents within the region's extent. `base` requires `lo`, `top` requires `hi`, `interior` requires `sample`. `unknown` requires at least one of the address keys. |
| `conf` | `parsed` / `derived` / `inferred` / `heuristic` / `timing` / `brute` | How reliable the source is. Strict trust ordering — see "Confidence". |
| `lo` / `hi` | `0x`-prefixed hex | Inclusive extent bounds. Either may be absent. |
| `sz` | `0x`-prefixed hex | Mutually exclusive with `hi`. Parser normalises to `hi = lo + sz - 1`. Rejected on overflow or `sz == 0`. |
| `sample` | `0x`-prefixed hex | A representative interior point. |
| `base_align` | `0x`-prefixed hex, power of two | Declared alignment of the extent base. Optional. |

Example emissions:

```
P initrd pos=base conf=parsed lo=0x33000000 hi=0x333fffff
V kernel_image:commit_creds pos=interior conf=parsed sample=0xffffffff81234000
P ram pos=top conf=parsed hi=0x100000000
V vmalloc pos=interior conf=heuristic sample=0xffffc90000123456
```

The orchestrator ignores any line that does not begin with `P` or `V`
followed by a space. Components can freely print diagnostic messages
(progress, errors, explanations) to stdout — only tagged lines are
captured as results. A component may emit zero, one, or multiple tagged
lines.

Components don't write the tagged format by hand — they call one of the
five intent-revealing helpers (see [Emitter API](#emitter-api) below), which
produce the correct line shape and reject malformed inputs at the source.

### Position vs. confidence

These are independent axes:

- **`pos`** describes what `sample` represents (base / top / interior).
  It does NOT say "we know the base" — that is a question about whether
  `lo` is set, not about `pos`. Use `HAS_LO(r)` for that.
- **`conf`** is a trust ranking of how the address was obtained. It does
  NOT describe precision — precision lives in the width of `[lo, hi]`. A
  CONF_PARSED record with `lo`–`hi` spanning 64 MB is "trustworthy but
  imprecise"; a CONF_HEURISTIC record with `lo == hi` is "precise but
  weak evidence".

### Regions

Region constants describe what kind of kernel memory is at the address.
The vocabulary is a closed enum, grounded in standard Linux memory
concepts. Subsystem-specific reservations (CBMEM, RMTFS, ION, …)
collapse to a standard concept (`REGION_RESERVED_MEM`, `REGION_PMEM`,
…); the discovery method is captured by the orchestrator-filled
`origin`.

Adding a new component should normally require zero new region constants.
The complete vocabulary is defined in
[`src/include/kasld/api.h`](src/include/kasld/api.h):

| Group | Constants |
|---|---|
| Physical landmarks | `REGION_RAM`, `REGION_DMA`, `REGION_DMA32`, `REGION_INITRD`, `REGION_CMDLINE`, `REGION_CMDLINE_MEMMAP`, `REGION_RESERVED_MEM`, `REGION_SWIOTLB`, `REGION_VMCOREINFO`, `REGION_CRASHKERNEL`, `REGION_PMEM`, `REGION_ACPI_TABLE`, `REGION_ACPI_NVS`, `REGION_EFI_MEMMAP`, `REGION_EFI_LOADER_IMAGE`, `REGION_NUMA_NODE`, `REGION_MMIO`, `REGION_PCI_MMIO` |
| Kernel image | `REGION_KERNEL_TEXT`, `REGION_KERNEL_DATA`, `REGION_KERNEL_BSS`, `REGION_KERNEL_IMAGE`, `REGION_MODULE`, `REGION_MODULE_REGION` |
| Direct-map / virtual landmarks | `REGION_DIRECTMAP`, `REGION_PAGE_OFFSET`, `REGION_VMALLOC`, `REGION_VMEMMAP` |

Edge-ness (RAM_BASE vs. RAM_TOP, DMA_TOP, etc.) is encoded via the
emitter helper (`kasld_result_base` vs. `kasld_result_top`), not via
distinct region constants.

### Confidence

Confidence ranks the trustworthiness of how the address was obtained, not
its precision. Highest to lowest: `parsed` > `derived` > `inferred` >
`heuristic` > `timing` > `brute`. Pick the value that matches how the
component produced the address:

| Value | When |
|---|---|
| `CONF_PARSED` | Read from a structured source (kallsyms, /proc/iomem, sysfs, dmesg) |
| `CONF_DERIVED` | Computed from another parsed address via a documented kernel offset |
| `CONF_INFERRED` | Multi-step inference from several parsed/derived results |
| `CONF_HEURISTIC` | Pattern match / fingerprinting — best-effort but not guaranteed |
| `CONF_TIMING` | Side-channel timing measurement |
| `CONF_BRUTE` | Brute-force probe |

The orchestrator weights conflicting claims by `conf`: a parsed address
beats a timing address when they disagree.

### Emitter API

Components emit results via five intent-revealing helpers from
[`src/include/kasld/api.h`](src/include/kasld/api.h). Each picks the wire shape
that matches what the component actually knows. There is no `_exact`
helper — "exact" was a precision conflation; precision lives in trust
(`conf`) plus bounds width.

| Helper | Use when |
|---|---|
| `kasld_result_range(type, region, lo, hi, name, conf)` | Both bounds known (full extent — e.g. a `/proc/iomem` entry) |
| `kasld_result_sized(type, region, lo, sz, name, conf)` | Base and size known; emits `lo, hi = lo + sz - 1` |
| `kasld_result_base(type, region, lo, name, conf)` | Lower bound known, upper unknown |
| `kasld_result_top(type, region, hi, name, conf)` | Upper bound known, lower unknown |
| `kasld_result_sample(type, region, addr, name, conf)` | A representative interior point — no extent claim |

All helpers return `1` on emit, `0` on rejection (with a stderr
warning). Rejection happens for: `CONF_UNKNOWN`, invalid type, invalid
region, helper-specific preconditions (e.g. `_sized` overflow,
`_range` with `lo > hi`).

Pass `name = NULL` (or `""`) when the leak only tells you "somewhere in
this kind of memory" but not the specific instance. Pass a real name
when you know exactly what's at the address — a kernel symbol
(`hypercall_page`), an ACPI OEM ID (`Cpu0Ist`), a module
(`nf_conntrack`), a device (`0000:00:14.0`).

### KASLR runtime states

KASLD distinguishes three distinct "KASLR is not adding entropy" states
because they have different implications for the inference engine:

| State | Scalar fact(s) | Kernel position | Engine action |
|---|---|---|---|
| **Disabled** (user/build opt-out) | `SF_VIRT_KASLR_DISABLED` + `SF_PHYS_KASLR_DISABLED` | Compile-time default (link-time `KERNEL_VIRT_TEXT_DEFAULT`) on each axis | `virt_kaslr_disabled_pin` pins `Q_VIRT_TEXT_BASE` on arches that set `KASLR_DISABLED_PINS_VIRT_TEXT`; `phys_kaslr_disabled_pin` pins `Q_PHYS_TEXT_BASE` on arches that set `KASLR_DISABLED_PINS_PHYS` |
| **Unsupported** (arch never had KASLR) | both `SF_*_KASLR_DISABLED` synthesised with origin `arch-no-kaslr` | Bootloader-determined | Inert for inference (these arches set neither `KASLR_DISABLED_PINS_VIRT_TEXT` nor `KASLR_DISABLED_PINS_PHYS`); lights the renderer's "KASLR not supported" banner |
| **Randomization failed** (boot stub tried, no entropy) | `SF_VIRT_KASLR_RANDOMIZATION_FAILED` + `SF_PHYS_KASLR_RANDOMIZATION_FAILED` | Firmware-/boot-stub-deterministic, NOT the link-time default | Does not pin. Three consumers: hardening-report entropy downgrade; `efi_loader_kernel_pick` lowest-survivor disambiguation on EFI arches; `s390_text_no_random` upper bound on s390 phys_text_base |

#### Disabled — `SF_VIRT_KASLR_DISABLED` + `SF_PHYS_KASLR_DISABLED`

KASLD treats the virtual and physical disable signals as independent
scalar facts because real kernels can disable one axis without the
other. Today every emitter that observes "KASLR off" proves both at
once and emits both facts (the same disable mechanism — `nokaslr`,
`CONFIG_RANDOMIZE_BASE=n`, kdump, etc. — affects both axes); a future
detector that proves only one (e.g. `EFI_RNG_PROTOCOL unavailable`
disables only physical placement while DTB-seeded virtual placement
still proceeds) emits only the relevant fact.

A handful of components detect a definitive opt-out and emit the pair
via two `kasld_emit_scalar()` calls — proc_cmdline (the `nokaslr` boot
flag), boot_config / proc_config (no `CONFIG_RANDOMIZE_BASE`),
dmesg_kaslr_disabled (the cmdline / hibernation / loongarch
"KASLR disabled" / "KASLR is disabled" lines, excluding the stricter
"EFI_RNG_PROTOCOL unavailable" line that wouldn't prove virt-off),
hibernation_nokaslr, riscv64_no_seed (FDT without
`/chosen/kaslr-seed`), loongarch_kexec_file_nokaslr (`kexec_file`
token), s390_kdump_nokaslr (`elfcorehdr=` kdump handoff).

The orchestrator reads `SF_VIRT_KASLR_DISABLED` to set the summary's
`kaslr.disabled` flag (which drives the renderer's "kernel sits at
default text base" banner and `slide`/`slot` zeroing — the user-facing
claim is about virt text, so it tracks the virt signal). The engine's
`virt_kaslr_disabled_pin` rule consumes `SF_VIRT_KASLR_DISABLED` to
pin `Q_VIRT_TEXT_BASE` to the compile-time default on arches that set
`KASLR_DISABLED_PINS_VIRT_TEXT` (x86_64, arm64, riscv64, loongarch64, s390),
gated by a window-containment soundness check; `phys_kaslr_disabled_pin`
does the analogous job for `Q_PHYS_TEXT_BASE` on arches that set
`KASLR_DISABLED_PINS_PHYS` (currently x86_64 and loongarch64).

#### Unsupported — synthesised `SF_VIRT_KASLR_DISABLED` + `SF_PHYS_KASLR_DISABLED`

"KASLR not supported" (compile-time `KASLR_SUPPORTED=0` — arm32, ppc64,
riscv32, sparc) is surfaced the same way: synthesised by the
orchestrator as both facts with origin `arch-no-kaslr`, inert for
inference (none of these arches set `KASLR_DISABLED_PINS_VIRT_TEXT` or
`KASLR_DISABLED_PINS_PHYS`, matching the relocating reality), but
lights the renderer's "KASLR not supported" banner.

#### Randomization failed — `SF_VIRT_KASLR_RANDOMIZATION_FAILED` + `SF_PHYS_KASLR_RANDOMIZATION_FAILED`

Distinct from disabled: the KASLR machinery was enabled in the build
and ran in the boot stub, but could not produce a random offset because
the entropy source was unavailable (arm64 / riscv64 "lack of seed",
arm64 "FDT remapping failure", s390 "CPU has no PRNG" / "not enough
memory"). The kernel was still relocated by the boot stub to a
firmware-/boot-stub-deterministic position — *not* the link-time
default — so this signal MUST NOT be fed to `virt_/phys_kaslr_disabled_pin`.

The dmesg_kaslr_disabled component distinguishes the two by inspecting
the exact reason string in the kernel's "KASLR disabled" line and emits
the appropriate fact. The summary flag `kaslr.disabled` stays *false*
in this state: the engine has not pinned the kernel to a known address,
even though no random offset was applied.

Engine consumers:

- Hardening-report posture section in `-H` mode (text + JSON).
  Surfaces the state with its detector origin and downgrades reported
  KASLR slot entropy to 0 bits.
- `efi_loader_kernel_pick` — when multiple `EFI_LOADER_CODE` entries
  pass the alignment+size filters, prefer the lowest-addressed
  survivor at `CONF_HEURISTIC` (the EFI stub's deterministic fallback
  policy is "first big-enough slot in memmap order").
- `s390_text_no_random` — on s390, emit `C_UPPER_BOUND` on
  `Q_PHYS_TEXT_BASE` at the conservative ceiling that bounds the
  boot stub's `nokaslr_text_lma = ALIGN(mem_safe_offset(), 1 MiB)`
  algorithm across all observed kernel versions. `CONF_HEURISTIC` so
  any real leak overrides.

### Exit code convention

Components signal their outcome to the orchestrator via exit code:

| Exit code | Constant | Meaning |
|---|---|---|
| **0** | — | Ran successfully (results, if any, are in tagged output) |
| **69** | `KASLD_EXIT_UNAVAILABLE` | Data source or hardware feature not present on this system |
| **77** | `KASLD_EXIT_NOPERM` | Access denied to data source |

The orchestrator classifies each component's outcome using this priority:

1. **SUCCESS** — component emitted at least one tagged line
2. **TIMEOUT** — component was killed by the timeout
3. **ACCESS_DENIED** — exit code 77
4. **UNAVAILABLE** — exit code 69
5. **NO_RESULT** — ran successfully but found nothing

The exit code answers "what was your relationship with your data
source?" — not "did you find results". A component that accessed its
data source and found no matching data should exit 0, not 69 or 77.
The orchestrator already knows whether results were found from the
tagged output.

The constants are defined in
[`src/include/kasld/internal.h`](src/include/kasld/internal.h) and
follow the `<sysexits.h>` convention (`EX_UNAVAILABLE` = 69,
`EX_NOPERM` = 77).

### Minimal component

```c
// src/components/my-leak.c
#include "include/kasld/api.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
  unsigned long addr;

  /* ... probe a data source ... */
  addr = 0; /* replace with actual leak logic */

  if (!addr) {
    printf("[-] no kernel address found via my-leak\n");
    return 0;
  }

  printf("leaked kernel text address: 0x%lx\n", addr);
  /* Leak gives a precise symbol address — interior of the kernel image,
   * confidently parsed from a structured source. */
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, addr,
                      "my_symbol", CONF_PARSED);
  return 0;
}
```

Place the file in `src/components/`. Run `make` — the build system
automatically discovers all `.c` files in that directory and compiles each
into a standalone binary under `build/<arch>/components/`. No Makefile
edits required.

The component can also be run directly:

```
$ ./build/x86_64-linux-musl/components/my-leak
leaked kernel text address: 0xffffffff81000000
V kernel_image:my_symbol pos=interior conf=parsed sample=0xffffffff81000000
```

Components that leak a physical address with a known extent (e.g. a
`/proc/iomem` region) should use `kasld_result_range` to convey both
bounds in a single call:

```c
kasld_result_range(KASLD_TYPE_PHYS, REGION_INITRD, phys_start, phys_end,
                   NULL, CONF_PARSED);
```

On coupled architectures, the same logical region exists in both spaces
— emit both records and let the merge pass link them by
`(region, name)`:

```c
kasld_result_range(KASLD_TYPE_PHYS, REGION_INITRD, phys_lo, phys_hi,
                   NULL, CONF_PARSED);

#ifdef phys_to_directmap_virt
kasld_result_range(KASLD_TYPE_VIRT, REGION_INITRD,
                   phys_to_directmap_virt(phys_lo),
                   phys_to_directmap_virt(phys_hi),
                   NULL, CONF_DERIVED);
#endif
```

The `#ifdef` guard compiles the derivation out on arches where the
direct-map projection is unsound at compile time — x86_64 with
`CONFIG_RANDOMIZE_MEMORY` (direct-map base randomised), arm64 / riscv64
/ s390 (text and direct map at independent runtime offsets). On those
arches the macro is undefined, so forgetting the guard fails to compile
rather than silently emitting a wrong observation. See
[Cross-region derivation](#cross-region-derivation) for details.

### Component metadata

Each component embeds two optional pieces of metadata via dedicated macros:

**`KASLD_EXPLAIN(text)`** — a plain-text explanation of the technique,
stored in a `.kasld_explain` ELF section. Displayed by `--explain` mode.

```c
KASLD_EXPLAIN("Searches dmesg for 'Freeing ... memory' messages from "
              "free_reserved_area() that print kernel virtual addresses.");
```

**`KASLD_META(text)`** — machine-readable key:value metadata, stored in a
`.kasld_meta` ELF section. The orchestrator reads this to determine the
component's leak primitive, address type, applicable mitigations, and
CVE associations. Used by the `--hardening` assessment.

```c
KASLD_META(
    "method:parsed\n"
    "phase:inference\n"
    "addr:virtual\n"
    "sysctl:dmesg_restrict>=1\n"
    "bypass:CAP_SYSLOG\n"
    "fallback:/var/log/dmesg\n"
    "patch:v4.10\n"
);
```

Supported metadata keys:

| Key | Description | Example |
|---|---|---|
| `method` | Technique category, used by the hardening report | `parsed`, `heuristic`, `timing`, `brute` |
| `phase` | Scheduling phase | `inference` (default when omitted), `probing` |
| `addr` | Address type leaked | `virtual`, `physical`, `both` |
| `sysctl` | Runtime sysctl gate | `dmesg_restrict>=1`, `kptr_restrict>=1` |
| `bypass` | Condition that bypasses the gate | `CAP_SYSLOG`, `adm group` |
| `fallback` | Alternative data source | `/var/log/dmesg` |
| `lockdown` | Blocked by kernel lockdown | `integrity`, `confidentiality` |
| `config` | Kernel compile-time config dependency | `CONFIG_E820_TABLE` |
| `cve` | Associated CVE identifier | `CVE-2022-4543` |
| `patch` | Kernel version where the leak was patched | `v4.10`, `v6.2` |

Each component should also include structured comment blocks in its file
header documenting the leak primitive and mitigations:

```c
// Leak primitive:
//   Data leaked:      kernel virtual addresses (freed memory section boundaries)
//   Kernel subsystem: mm — free_reserved_area()
//   Address type:     virtual (kernel text / initrd)
//   Method:           parsed (dmesg string)
//   Status:           removed in v4.10
//
// Mitigations:
//   Removed in v4.10. Access gated by dmesg_restrict.
```

---

## API reference

The complete component API is in [`src/include/kasld/api.h`](src/include/kasld/api.h)
(emitter helpers, enums, address-layout constants) and
[`src/include/kasld/internal.h`](src/include/kasld/internal.h) (exit
codes — components don't include this directly).

**Emitter helpers** — pick the one matching what you know:

| Helper | Use |
|---|---|
| `kasld_result_range(type, region, lo, hi, name, conf)` | Both bounds known (full extent) |
| `kasld_result_sized(type, region, lo, sz, name, conf)` | Base and size known |
| `kasld_result_base(type, region, lo, name, conf)` | Lower bound only |
| `kasld_result_top(type, region, hi, name, conf)` | Upper bound only |
| `kasld_result_sample(type, region, addr, name, conf)` | Interior point sample |

All return `1` on emit, `0` on rejection (stderr warning is written).

**Enums**:

| Symbol | Values |
|---|---|
| `enum kasld_addr_type` | `KASLD_TYPE_PHYS`, `KASLD_TYPE_VIRT`, `KASLD_TYPE_DEFAULT_VIRT` |
| `enum kasld_region` | `REGION_KERNEL_TEXT`, `REGION_RAM`, `REGION_INITRD`, `REGION_PCI_MMIO`, … (see [kasld/api.h](src/include/kasld/api.h) for the full list) |
| `enum kasld_confidence` | `CONF_PARSED` > `CONF_DERIVED` > `CONF_INFERRED` > `CONF_HEURISTIC` > `CONF_TIMING` > `CONF_BRUTE` |

**ELF metadata**:

| Symbol | Purpose |
|---|---|
| `KASLD_EXPLAIN(text)` | Embed a technique explanation (`.kasld_explain` ELF section) |
| `KASLD_META(text)` | Embed machine-readable metadata (`.kasld_meta` ELF section) |

**Exit codes** (from `kasld/internal.h`, but components reference them
directly via the constants in `kasld/api.h`'s include chain):

| Symbol | Purpose |
|---|---|
| `KASLD_EXIT_UNAVAILABLE` | Exit code 69: feature/hardware not present |
| `KASLD_EXIT_NOPERM` | Exit code 77: access denied |

**Address-layout constants** (per-arch, from `arch/<arch>.h`):

| Symbol | Purpose |
|---|---|
| `KERNEL_VIRT_TEXT_DEFAULT` | Default (non-randomized) kernel text base |
| `KERNEL_VIRT_VAS_START`, `KERNEL_VIRT_VAS_END` | Kernel virtual address space bounds |
| `KERNEL_VIRT_TEXT_MIN`, `KERNEL_VIRT_TEXT_MAX` | Plausible kernel text range (validation) |
| `KASLR_VIRT_TEXT_MIN`, `KASLR_VIRT_TEXT_MAX` | KASLR randomisation window (slot counting) |
| `KASLR_VIRT_TEXT_MIN_WIDE` | Conservative widened floor (admits non-default Kconfigs) |
| `PAGE_OFFSET` | Direct-map base (compile-time default) |
| `PHYS_OFFSET` | Physical RAM base address |
| `TEXT_TRACKS_DIRECTMAP` | 1 on arches where text + directmap move together |
| `DIRECTMAP_STATIC` | 1 where the directmap projection is sound at compile time |
| `phys_to_directmap_virt(p)` | Convert phys → directmap virt (defined only on sound arches) |
| `directmap_virt_to_phys(v)` | Inverse — same gate as above |
