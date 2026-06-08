# Contributing to KASLD

KASLD's architecture is a simple contract: each **component** is a
standalone executable that probes one data source and prints tagged lines
to stdout. The **orchestrator** discovers, runs, and post-processes
components automatically — no registration, no linking, no Makefile
changes. The **inference engine** runs after collection, narrowing kernel
layout quantities from the merged observations.

This document covers the actionable mechanics a component author or rule
author needs. For how the system works as a whole — the layered engine and
its fixpoint, the data-flow seams, cross-region derivation, and KASLR
runtime states — see [docs/architecture.md](docs/architecture.md). For
end-user material, see [README.md](README.md) and
[docs/usage.md](docs/usage.md).

## Table of Contents

- [Architecture in brief](#architecture-in-brief)
- [Writing a component](#writing-a-component)
  - [Tagged output](#tagged-output)
  - [Position vs. confidence](#position-vs-confidence)
  - [Regions](#regions)
  - [Confidence](#confidence)
  - [Emitter API](#emitter-api)
  - [Exit code convention](#exit-code-convention)
  - [Minimal component](#minimal-component)
  - [Component metadata](#component-metadata)
- [Writing a rule](#writing-a-rule)
- [API reference](#api-reference)

---

## Architecture in brief

KASLD is a three-stage pipeline. Standalone **components** probe data sources
and print tagged lines; the **orchestrator** runs each as an isolated child
process (`fork()` + `execl()`, per-component timeout, exit code signalling its
relationship with its data source) and merges the results by
`(type, region, name)`; the **inference engine** then resolves the kernel layout
from the merged evidence and reports each value with provenance. Components are
fully decoupled — drop a `.c` file in `src/components/` and the build discovers
it; no registration or Makefile change. A component that segfaults, hangs, or
errors cannot affect the others.

The full conceptual reference — component lifecycle and phases, the three-layer
engine and its fixpoint, the store-vs-read seam, the tagged-line protocol,
cross-region derivation, and the three KASLR runtime states — lives in
[docs/architecture.md](docs/architecture.md). The rest of this document is the
actionable mechanics of **writing a component or rule**.

---

## Writing a component

### Tagged output

Components emit results as tagged lines on stdout — but never by hand. Call one
of the five emitter helpers (see [Emitter API](#emitter-api) below); each prints
the correct wire shape and rejects malformed inputs at the source. The full
protocol — the field grammar, a field-by-field anatomy of a line, and the
region/confidence vocabularies — is documented in
[docs/architecture.md → The tagged-line protocol](docs/architecture.md#the-tagged-line-protocol).

The orchestrator ignores any line that does not begin with `P` or `V` followed
by a space, so a component can freely print diagnostic messages (progress,
errors, explanations). A component may emit zero, one, or multiple tagged lines.

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

A component that detects KASLR being switched off (or unsupported, or having
failed to randomise) emits scalar facts via `kasld_emit_scalar()` instead of an
address; which facts, and how the engine consumes each, are documented in
[docs/architecture.md → KASLR runtime states](docs/architecture.md#kaslr-runtime-states).

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
[docs/architecture.md → Cross-region derivation](docs/architecture.md#cross-region-derivation)
for the full picture.

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

## Writing a rule

Engine rules are pure functions in `src/rules/`. Adding one is a new file plus a
single registry line:

1. Create `src/rules/<name>.c` with the rule signature:
   ```c
   int rule_<name>(const struct evidence_set *ev, const struct estimate *est,
                   struct constraint *out, int out_max);
   ```
   Read `ev` (observations + scalar facts) and the current `est` array; emit
   constraints into `out[0..out_max)` and return the count. A rule does no I/O
   and has no side effects. For curation, write a verdict rule that emits
   `V_INVALID` to drop an observation from the effective set.
2. Register it: add the prototype and one entry to `k_rules[]` (or `k_vrules[]`
   for a verdict rule) in `src/engine_rules.c` — the single registry shared by
   the orchestrator and the test suite.
3. Add unit tests in `tests/test_engine.c` proving soundness: truth stays inside
   the estimate, and an adversarial observation cannot push it past truth. The
   per-rule unit test is the soundness gate.

Estimates only narrow — never emit a constraint that would widen a quantity past
its honest top. The fixpoint re-runs every rule, so depend only on `ev` and
`est`, never on rule order. The engine model and the existing rule catalogue are
described in
[docs/architecture.md → The inference engine](docs/architecture.md#the-inference-engine)
and [Cross-region derivation](docs/architecture.md#cross-region-derivation).

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
```
