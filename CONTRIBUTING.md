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
  - [Testing a component](#testing-a-component)
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

**Confidence and the two windows.** The engine resolves twice: a *guaranteed*
window from signals at or above a sound floor (`CONF_INFERRED`), and a *likely*
window from all signals (see
[Two-window resolution](docs/architecture.md#two-window-resolution-guaranteed-and-likely)).
So the level chosen decides which window an emission can reach. Before picking
one, classify the value:

- A **fact** — derived from an observation (a parsed address, a value computed
  from one) — is `CONF_INFERRED` or higher and may shape the guaranteed window.
- A **guess** — a bootloader convention, a standard-config default, a
  fingerprint, a timing estimate — is `CONF_HEURISTIC` or lower, so it refines
  only the speculative likely window.

Emitting a guess at `CONF_INFERRED` or above puts it in the guaranteed window,
where a wrong guess excludes the truth on a legitimate non-default kernel — the
one thing that window must never do. A value not computed from an observation is
a guess; when in doubt, emit it below the floor.

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

A `range` variant, `kasld_result_extent(type, region, lo, hi, name, conf)`,
emits the same `lo`+`hi` but as `pos=extent` — one member of a **complete,
single-source covering** of the region (a whole RAM map: every E820 / device-tree
`/memory` / online hotplug extent). The value lives in the *gaps* between
extents, so it makes no positional claim: floor rules ignore it (they require
`pos=base`), and the orchestrator routes it out of the cross-source merge into
the engine's `coverings[]` so the map stays faithful and per-source. Only emit it
from a source that reads the **whole** map — a partial map would synthesize false
gaps, which `tests/check-extent-callers` guards against.

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
failed to randomize) emits scalar facts via `kasld_emit_scalar()` instead of an
address; which facts, and how the engine consumes each, are documented in
[docs/architecture.md → KASLR runtime states](docs/architecture.md#kaslr-runtime-states).

### Diagnostics and options

Two channels, kept separate (`include/kasld/cli.h`):

- **stdout is the machine channel** — *only* the `P`/`V`/`S` wire lines the
  emitter helpers print. Never write a human message to stdout (so
  `component 2>/dev/null` is clean, parseable output).
- **stderr is the human channel** — every diagnostic, through the levelled
  logger, never a bare `printf`/`fprintf`:

  | Macro | Prefix | Use |
  |---|---|---|
  | `kasld_info(fmt, …)` | `[.]` | normal progress |
  | `kasld_debug(fmt, …)` | `[.]` | firehose detail — printed only under verbose |
  | `kasld_err(fmt, …)` | `[-]` | failure / data unavailable |
  | `kasld_found(fmt, …)` | `[+]` | a leak was produced |

  The `info`/`debug` split matters: verbose means different things per component
  (a couple of lines for `proc_iomem`, a per-collision firehose for
  `kernelsnitch`). Demote firehose lines to `kasld_debug` so a normal run — and
  `kasld -v` — stay readable; they surface only under the component's own
  verbose. `tests/check-component-output` enforces this: any component
  printing a diagnostic to stdout fails the build.

**Options** are optional and **manual** (testing/debugging — the orchestrator
passes none and sets no env). If a component takes any, parse them with
`kasld_cli(argc, argv)` rather than hand-rolling `argv` — it gives every
component the same `-v` / `--verbose`, `-t SECS` / `--time` (the component's own
probe budget, in seconds — *not* kasld's kill timeout), and `-h` / `--help`. A
component then reads `kasld_verbose` (or `kasld_is_verbose()`) and `kasld_time_s`
as it cares; one with no options stays `int main(void)`. `kasld_is_verbose()`
also honours `$KASLD_VERBOSE`, so a `main(void)` component is debuggable without
an `argc/argv` conversion.

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

A complete, real component. It searches the kernel log for the
`free_reserved_area()` messages that pre-v4.10 kernels printed when freeing init
memory, parses the leaked address, and emits it. The shape — find a line, parse
an address, emit one tagged result — is the one most components share.

```c
// src/components/freeing.c — free_reserved_area() leak (pre-v4.10 kernels)
#define _GNU_SOURCE
#include "include/dmesg.h"
#include "include/kasld/api.h"
#include <stdlib.h>
#include <string.h>

/* dmesg_search() invokes this for every log line containing "Freeing".
 * Old kernels print:
 *   Freeing unused kernel memory: 1476K (ffffffff81f41000 - ffffffff820b2000)
 * The address inside the parentheses lies within the kernel image. */
static int on_match(const char *line, void *ctx) {
  (void)ctx;
  const char *paren = strchr(line, '(');
  if (paren == NULL)
    return 1; /* v4.10+ prints no address — keep scanning */

  unsigned long addr = strtoul(paren + 1, NULL, 16);
  if (!kasld_addr_is_kernel_text(addr))
    return 1;

  /* The exact position within the image is unknown (an interior point), and
   * the value is parsed from a structured log line: pos=interior, conf=parsed. */
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, addr, NULL,
                      CONF_PARSED);
  return 1; /* keep scanning for further "Freeing" lines */
}

int main(void) {
  if (dmesg_search("Freeing ", on_match, NULL) < 0)
    return KASLD_EXIT_NOPERM; /* dmesg_restrict blocked the read */
  return 0;
}
```

Place the file in `src/components/`. Run `make` — the build system
automatically discovers every `.c` file in that directory and compiles each
into a standalone binary under `build/<arch>/components/`. No Makefile edits
required.

Run it directly to see the tagged result it prints to stdout:

```
$ ./build/x86_64-linux-musl/components/freeing
V kernel_image pos=interior conf=parsed sample=0xffffffff81f41000
```

That single `V …` line is the component's entire contract with the engine — the
orchestrator reads it from stdout and the rest is automatic. KASLD ships a fuller
version of this technique as `dmesg_free_reserved_area.c`, which additionally
classifies the address by range and derives the physical address on coupled
architectures. To see this exact result flow through a rule, the engine, and the
rendered output, follow
[the end-to-end walkthrough](docs/architecture.md#a-leak-from-end-to-end).

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
`CONFIG_RANDOMIZE_MEMORY` (direct-map base randomized), arm64 / riscv64
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
| `method` | Technique category, used by the hardening report | `parsed`, `heuristic`, `timing`, `brute`, `detection` |
| `phase` | Scheduling phase | `inference` (default when omitted), `probing` |
| `addr` | Address type leaked | `virtual`, `physical`, `both` |
| `sysctl` | Runtime sysctl gate | `dmesg_restrict>=1`, `kptr_restrict>=1` |
| `bypass` | Condition that bypasses the gate | `CAP_SYSLOG`, `adm group` |
| `fallback` | Alternative data source | `/var/log/dmesg` |
| `lockdown` | Blocked by kernel lockdown | `integrity`, `confidentiality` |
| `config` | Kernel compile-time config dependency | `CONFIG_E820_TABLE` |
| `cve` | Associated CVE identifier | `CVE-2022-4543` |
| `patch` | Kernel version where the leak was patched | `v4.10`, `v6.2` |
| `status` | Opt-in gate; the component runs only with `-x` | `experimental` |

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

### Testing a component

The inference engine is the unit-tested core (`tests/test_engine.c`,
`tests/test_engine_integration.c`, and the estimate/evidence suites).
Components are thin parse-and-emit shims, and most are covered end to end by
running the real binary over captured real systems:

- `tests/replay` runs each architecture's `kasld` over the captured
  `/proc`+`/sys` trees in `tests/fixtures/` — crash coverage of the parse and
  render paths on real data.
- `extra/validate-bundle` runs offline against a captured bundle and asserts the
  engine's resolved ranges contain the ground truth (soundness).

A component therefore does **not** get its own unit test by default. Add a
hermetic parser test **only when the component is fixture-unreachable** — when
its input cannot appear in a captured tree:

- it requires specific hardware or firmware a normal capture will not have
  (CXL, coreboot, an active IOMMU, NVDIMM, UIO, a Qualcomm modem, …), or
- its input is too large or absent on the build host (e.g. the multi-megabyte
  `/sys/kernel/btf/vmlinux`).

Such parsers must route their reads through the `kasld_*` wrappers
(`kasld_opendir`, `kasld_fopen`, …) so a test can stage a `KASLD_SYSROOT`
fixture in place of the live system. The test then `#include`s the component
with its `main` renamed, drives it over hand-built fixture files reproducing the
exact kernel ABI (text format, units, endianness), and checks the emitted wire
line. `tests/test_sysfs_parsers.c` is the pattern; `tests/test_btf.c` covers the
oversized-input case.

Hermetic tests are regression guards against parser *code* changes, not a way to
detect kernel-side ABI drift — a frozen fixture cannot track a moving kernel.
Drift is caught by widening the real-capture corpus under `tests/fixtures/` and
by source review against new kernel releases.

> One component carries a hermetic test for a different reason:
> `dmesg_mem_init_kernel_layout` (`tests/test_dmesg_layout.c`) is reachable via
> the dmesg captures, but its test exists to validate the parser across every
> width and endianness under `tests/test-cross`. That is a deliberate exception
> to the fixture-reachability rule above.

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
`est`, never on rule order.

### A minimal rule

This complete rule turns an interior leak into a sound ceiling on the kernel
image base — the rule the
[end-to-end walkthrough](docs/architecture.md#a-leak-from-end-to-end) traces.
(The shipped `range_from_interior` is this plus the parallel physical quantity.)

```c
// src/rules/text_ceiling_from_interior.c
#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"
#include <limits.h>
#include <string.h>

int rule_text_ceiling_from_interior(const struct evidence_set *ev,
                                    const struct estimate *est,
                                    struct constraint *out, int out_max) {
  (void)est; /* depends only on the evidence, not the current estimate */

  /* Lowest virtual address seen inside the kernel image. _text cannot lie
   * above it, so it is a sound upper bound on the image base. */
  unsigned long ceil = ULONG_MAX;
  uint32_t src = 0;
  enum kasld_confidence conf = CONF_UNKNOWN;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->eff_type != KASLD_TYPE_VIRT)
      continue;
    if (o->eff_region != REGION_KERNEL_IMAGE || !HAS_SAMPLE(o))
      continue;
    if (o->sample < ceil) {
      ceil = o->sample;
      src = o->id;
      conf = o->conf;
    }
  }
  if (ceil == ULONG_MAX || out_max < 1)
    return 0; /* no qualifying observation — emit nothing */

  memset(&out[0], 0, sizeof(out[0]));
  out[0].q = Q_VIRT_IMAGE_BASE;
  out[0].op = C_UPPER_BOUND; /* image base <= ceil */
  out[0].value = ceil;
  out[0].conf = conf;
  out[0].derived_from[0] = src;
  out[0].lineage_count = 1;
  snprintf(out[0].origin, ORIGIN_LEN, "text_ceiling_from_interior");
  return 1;
}
```

The reasoning *is* the soundness argument: `_text` cannot lie above an address
known to be inside the image, so the lowest such sample is a valid upper bound.
The rule reads only `ev`, ignores `est`, and emits one `C_UPPER_BOUND` — so it is
order-independent and can only narrow.

### Constraint operations

A constraint names a quantity, an op, a `value` (and `value2` for the ranged
ops), and a confidence. Pick the op for what the evidence actually proves:

| Op | Meaning | Emit when |
|---|---|---|
| `C_LOWER_BOUND` | `q >= value` | a floor — the quantity cannot be below `value` |
| `C_UPPER_BOUND` | `q <= value` | a ceiling — the quantity cannot be above `value` |
| `C_EQUALS` | `q == value` | a pin — the exact value is known |
| `C_AT_LEAST_ALIGN` | `q` divisible by `value` | the quantity is known to be at least `value`-aligned |
| `C_EXCLUDE` | `q` not in `[value, value2]` | a forbidden sub-range |
| `C_STRIDE` | `q ≡ value (mod value2)` | the quantity lands on a fixed grid |

`C_EXCLUDE` and `C_STRIDE` carry a second bound in `value2`; the others use
`value` alone. Interior `C_EXCLUDE` holes are carved at read time, not stored —
see
[Estimate narrowing and the store-vs-read seam](docs/architecture.md#estimate-narrowing-and-the-store-vs-read-seam).

### Proving soundness

The per-rule unit test is what guarantees the engine never excludes the truth.
For the rule above, `test_engine_interior_ceiling` in `tests/test_engine.c` is
the pattern: seed one interior observation, run the rule through the engine, and
assert the estimate's ceiling lands exactly on the sample (truth retained) while
the floor is untouched. A complete test also adds an adversarial observation and
shows it cannot push the estimate past the truth.

The engine model and the existing rule catalogue are described in
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
| `KASLR_VIRT_TEXT_MIN`, `KASLR_VIRT_TEXT_MAX` | KASLR randomization window (slot counting) |
| `KASLR_VIRT_TEXT_MIN_WIDE` | Conservative widened floor (admits non-default Kconfigs) |
| `PAGE_OFFSET` | Direct-map base (compile-time default) |
| `PHYS_OFFSET` | Physical RAM base address |
| `TEXT_TRACKS_DIRECTMAP` | 1 on arches where text + directmap move together |
| `DIRECTMAP_STATIC` | 1 where the directmap projection is sound at compile time |
| `phys_to_directmap_virt(p)` | Convert phys → directmap virt (defined only on sound arches) |
| `directmap_virt_to_phys(v)` | Inverse — same gate as above |
```
