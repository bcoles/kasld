# Usage

`kasld` recovers a running kernel's memory layout — primarily the kernel text
base — from a local process, using as much as its vantage (privileges, groups,
capabilities, system configuration, and any container confinement) allows. Run
it with no arguments and it prints an answer: the recovered (or narrowed)
virtual and physical image base, the direct map base, and the leaks the answer
was derived from.

Underneath, `kasld` gathers evidence from many small leak components (each a
standalone technique that probes one source) and feeds it to an inference engine
that narrows the layout to the smallest set of placements the evidence supports,
reporting every value with its provenance and any residual entropy. In normal use
that machinery is invisible — a single invocation prints the result. This
document covers the output modes and command-line options; for how the pieces fit
together see [architecture.md](architecture.md).

## Table of Contents

- [Quick start](#quick-start)
- [Vantage](#vantage)
- [Command-line options](#command-line-options)
- [Output modes](#output-modes)
  - [Default text mode](#default-text-mode)
  - [Verbose (`-v`)](#verbose--v)
  - [Oneline (`-1`)](#oneline--1)
  - [JSON (`-j`)](#json--j)
  - [Markdown (`-m`)](#markdown--m)
- [Explain mode](#explain-mode)
- [Hardening assessment](#hardening-assessment)
- [Continuous integration](#continuous-integration)

## Quick start

```sh
sudo apt install libc-dev make gcc binutils git
git clone https://github.com/bcoles/kasld
cd kasld
make
./build/<arch>/kasld
```

The `build/<arch>/` directory is self-contained and can be deployed to a
target system:

```
build/<arch>/
  kasld              <- run this
  components/        <- leak components
```

A hardened configuration (`kernel.dmesg_restrict=1`, `kernel.kptr_restrict=1`,
`kernel.perf_event_paranoid=2` or higher, `kernel.unprivileged_bpf_disabled=1`,
and `%pK` pointer hashing, on by default) narrows the filesystem-oracle path. It is one axis of the vantage
only: side-channel, weak-entropy, and capability-granted techniques are
independent of these sysctls. For testing purposes, the
[extra/weaken-kernel-hardening](../extra/weaken-kernel-hardening) script
can temporarily relax these settings (requires root).

## Vantage

What `kasld` recovers depends on the process's *vantage* — three independent
axes, not a single privilege ladder: **privileges and capabilities**, **system
configuration**, and **confinement**. The hardened sysctls above are only one of
them. A leak source is reachable only where every axis that gates it permits, so
more privilege is not a superset of less — configuration can deny a source to
root, and the side-channel and capability-granted techniques bypass the sysctls
entirely:

![Vantage matrix of leak sources against the three gating axes — privileges and capabilities, system configuration, confinement — showing the axes are independent rather than a ladder: configuration can deny a source to root, and side channels are independent of the sysctls](diagrams/vantage.svg)

The `-v`, `-j`, and `-m` outputs report the detected vantage (container,
confinement, readable oracles, and the capability-gated leaks reachable from the
current capabilities). A richer vantage lets `kasld` attempt more and gather more
evidence, but the guaranteed (sound) window reflects only the evidence actually
proven — never the privilege that gathered it — so it stays trustworthy whatever
the vantage. See [limitations.md](limitations.md).

## Command-line options

```
-j, --json          Machine-readable JSON output
-1, --oneline       Single-line summary output (shell-pipeable)
-m, --markdown      Markdown table output (for issue trackers)
-c, --color         Colorize text output (auto-detected for TTYs)
-a, --ascii         ASCII-only output: no Unicode glyphs or banner
                    (auto-enabled in a non-UTF-8 locale)
-q, --quiet         Suppress progress indicator and warnings
-v, --verbose       Add banner, system-config block, per-component logs,
                    per-region Results table, KASLR analysis, and the
                    virtual + physical memory-layout maps. The default
                    text mode prints a tight ~15-line answer-first
                    readout; -v restores the full detail.
-e, --explain       Show technique explanations before each component
-f, --fast          Use 2s per-component timeout (fast scan mode)
-w, --workers N     Parallel inference workers (default: nproc; 0 = sequential)
-x, --experimental  Enable experimental components
-s, --skip PATTERN  Skip matching components (glob, comma-separated; multiple --skip flags accumulate)
-H, --hardening     Append the hardening assessment to text/markdown output
    --map           Draw the address-space diagram (implied by --verbose)
-t, --timeout N     Per-component timeout in seconds (default: 30)
-V, --version       Print version and exit
-h, --help          Show this help
```

Single-dash short flags may be bundled: `-fq` is `-f -q`, `-vj` is `-v -j`. A
value-taking flag (`-s`/`-t`/`-w`) may appear only as the last flag in a bundle,
taking the next argument — `-fqt 2` is `-f -q -t 2`.

### Accessibility

The text output uses a few Unicode glyphs (`✓ ⚠ ✗ →`) and a box-art banner
under `-v`. These are auto-disabled in a non-UTF-8 locale (`LANG=C`, legacy
consoles), and `--ascii` (`-a`) forces plain ASCII regardless — for screen
readers on a UTF-8 system, or non-UTF-8 pipelines. The JSON (`-j`) and one-line
(`-1`) formats carry no glyphs and are the fully accessible, machine-readable
interfaces.

Colour follows the standard environment conventions: `NO_COLOR` (any value)
disables it, `CLICOLOR=0` disables it, and `CLICOLOR_FORCE` (non-empty, not `0`)
forces it on even when piped. An explicit `--color` overrides `NO_COLOR`.

## Output modes

### Default text mode

The default text mode prints a tight answer-first readout: a one-line
header, the resolved or narrowed text-base windows, the directmap window
when narrowed, the virt/phys coupling note, the leaks the answers were
derived from, and a hint about the verbose mode. No banner, no system
config, no memory-layout diagram.

```
KASLD 0.3.1-dev  --  Kernel ASLR derandomization
Target: x86_64 / 6.15.6

Running 94 of 97 components (3 experimental skipped; use -x to enable)...
[####################] 100%  94/94  13.9s

Layout
  Virtual image base     (pinned)
    guaranteed           0xffffffff8fe00000 slide +0xee00000

  Physical image base    (pinned)
    guaranteed                   0x34600000 slide +0x33600000

  Direct map base        (narrowed to ~9 bits)
    guaranteed           >= 0xffff800000000000

  Note: physical and virtual text randomize independently

Evidence  (6 findings, 5 components)
  virt kernel text    [interior] 0xffffffff8ff04104
                                 from perf_event_open, proc_kallsyms
  virt kernel image   [base]     0xffffffff8fe00000
                                 from perf_event_open, prefetch, proc_kallsyms
  virt directmap      [base]     0xffff9eeb80000000
                                 from prefetch_directmap
  phys kernel image   [base]             0x34600000
                                 from proc_iomem_kernel
  phys kernel data    [base]             0x36000000
                                 from proc_iomem_kernel
  phys kernel BSS     [base]             0x36b34000
                                 from proc_iomem_kernel

[-v: detailed results, memory map, system info]  [-H: hardening assessment]
```

Terms in this readout (slide, directmap, coupling, slot/entropy) are defined in
the [kaslr.md glossary](kaslr.md#glossary); the engine vocabulary behind them
(quantity, estimate, honest top) is in the
[architecture.md glossary](architecture.md#glossary).

### Verbose (`-v`)

`-v` (`--verbose`) restores the full banner, system-config block,
per-component logs, per-region "Results" table, KASLR analysis section,
and the virtual + physical address-space diagram (also available on its own
via `--map`). The
system-config block reports the recon vantage: whether the process is
containerized, and — when it is confined — its seccomp / capability /
no-new-privs state, plus which `/proc` leak oracles are readable here:

<details>
<summary>Click to expand verbose example</summary>

```
     ▄█   ▄█▄    ▄████████    ▄████████  ▄█       ████████▄
    ███ ▄███▀   ███    ███   ███    ███ ███       ███   ▀███
    ███▐██▀     ███    ███   ███    █▀  ███       ███    ███
   ▄█████▀      ███    ███   ███        ███       ███    ███
  ▀▀█████▄    ▀███████████ ▀███████████ ███       ███    ███
    ███▐██▄     ███    ███          ███ ███       ███    ███
    ███ ▀███▄   ███    ███    ▄█    ███ ███▌    ▄ ███   ▄███
    ███   ▀█▀   ███    █▀   ▄████████▀  █████▄▄██ ████████▀
    ▀                                   ▀ v0.3.1-dev

Kernel release:               6.15.6
Kernel version:               #1 SMP PREEMPT_DYNAMIC Wed Jun 17 13:04:17 EDT 2026
Kernel arch:                  x86_64

kernel.kptr_restrict:         0
kernel.dmesg_restrict:        0
kernel.panic_on_oops:         0
kernel.perf_event_paranoid:   -1
Kernel lockdown:              (unavailable)

Container:                    none

Readable /proc/kallsyms:      yes
Readable /proc/kcore:         no
Readable /proc/iomem:         yes
Readable /proc/modules:       yes
Readable /var/log/dmesg:      no
Readable /var/log/kern.log:   no
Readable /var/log/syslog:     no
Readable debugfs:             yes
Readable /boot/System.map:    no
Readable /boot/config:        no

--- (per-component probe logs trimmed for brevity) ---

[engine] virt_image_base: constrained by 5 independent sources: ceiling_from_image_size image_floor_from_init_size range_from_interior physical_start_lower_bound text_pin_from_observation
[engine] phys_image_base: constrained by 13 independent sources: ceiling_from_image_size phys_ceiling_from_memtotal phys_bits_ceiling mmio_floor_phys_ceiling phys_hole_filter kernel_image_phys_bound initrd_phys_exclude phys_reservation_exclude ram_map_phys_exclude initrd_above_kernel cmdline_phys_exclude physical_start_lower_bound text_pin_from_observation
[engine] virt_kaslr_align: constrained by 2 independent sources: kaslr_align_arch_default boot_params_kaslr_align
[engine] phys_kaslr_align: constrained by 2 independent sources: kaslr_align_arch_default boot_params_kaslr_align
Components: 94 total, 24 succeeded, 26 unavailable, 44 no result

========================================
 Results
========================================

Kernel text (virtual) / kernel_text [2]:
  0xffffffff8fe00000  kernel_text:_stext [base] (proc_kallsyms, parsed)
  0xffffffff900a9fc9  kernel_text [interior] (perf_event_open, parsed)
  ==> 0xffffffff8fe00000  (parsed, 1 source, 1 conflict)
      range: 0xffffffff8fe00000 - 0xffffffff900a9fc9  (2.7 MiB)

Kernel text (virtual) / kernel_image [3]:
  0xffffffff8fe00000  kernel_image:_text [base] (proc_kallsyms, parsed)
  0xffffffff8fe00000  kernel_image [base] (prefetch, timing)
  0xffffffff90000000  kernel_image [base] (perf_event_open, parsed)
  ==> 0xffffffff8fe00000  (parsed, 2 sources, 1 conflict)
      range: 0xffffffff8fe00000 - 0xffffffff90000000  (2.0 MiB)

----------------------------------------
Kernel text (physical) / kernel_image [1]:
  0x0000000034600000  kernel_image:kernel_code [base] (proc_iomem_kernel, parsed)
  ==> 0x0000000034600000  (parsed, 1 source)

----------------------------------------
Kernel data (physical) / kernel_data [1]:
  0x0000000036000000  kernel_data:kernel_data [base] (proc_iomem_kernel, parsed)
  ==> 0x0000000036000000  (parsed, 1 source)

----------------------------------------
Kernel BSS (physical) / kernel_bss [1]:
  0x0000000036b34000  kernel_bss:kernel_bss [base] (proc_iomem_kernel, parsed)
  ==> 0x0000000036b34000  (parsed, 1 source)

----------------------------------------
Physical DRAM / ram [6]:
  0x0000000000000000  ram (boot_params_e820, parsed)
  0x0000000000000000  ram (firmware_memmap, parsed)
  0x0000000000001000  ram [interior] (dmesg_free_area_init_node, proc_zoneinfo, parsed)
  0x0000000000100000  ram [base] (boot_params_e820, dmesg_e820_memory_map, dmesg_free_area_init_node, dmesg_last_pfn, proc_zoneinfo, sysfs_firmware_memmap, parsed)
  0x0000000000100000  ram (firmware_memmap, parsed)
  0x0000000000100000  ram (boot_params_e820, parsed)
  ==> 0x0000000000100000  (parsed, 3 sources, 3 conflicts)
      range: 0x0000000000000000 - 0x0000000000100000  (1.0 MiB)

----------------------------------------
Physical DRAM / initrd [1]:
  0x000000003efc2000  initrd [base] (boot_params_e820, dmesg_ramdisk, parsed)
  ==> 0x000000003efc2000  (parsed, 1 source)

----------------------------------------
Physical DRAM / cmdline [1]:
  0x0000000000020000  cmdline [base] (cmdline_region, parsed)
  ==> 0x0000000000020000  (parsed, 1 source)

----------------------------------------
Physical DRAM / numa_node [1]:
  0x000000003ffdefff  numa_node [interior] (dmesg_node_data, parsed)
  ==> 0x000000003ffdefff  (parsed, 1 source)

----------------------------------------
Physical DRAM / vmcoreinfo [1]:
  0x00000000011ee000  vmcoreinfo [interior] (sysfs_vmcoreinfo, parsed)
  ==> 0x00000000011ee000  (parsed, 1 source)

----------------------------------------
Physical MMIO / pci_mmio [8]:
  0x00000000000c0000  pci_mmio:0000:00:01.0 [base] (sysfs_pci_resource, parsed)
  0x00000000fd000000  pci_mmio:0000:00:01.0 [base] (sysfs_pci_resource, parsed)
  0x00000000feb40000  pci_mmio:0000:00:02.0 [base] (sysfs_pci_resource, parsed)
  0x00000000feb80000  pci_mmio:0000:00:02.0 [base] (sysfs_pci_resource, parsed)
  0x00000000feba0000  pci_mmio:0000:00:02.0 [base] (sysfs_pci_resource, parsed)
  0x00000000febd0000  pci_mmio:0000:00:02.0 [base] (sysfs_pci_resource, parsed)
  0x00000000febd4000  pci_mmio:0000:00:01.0 [base] (sysfs_pci_resource, parsed)
  0x00000000febd5000  pci_mmio:0000:00:1f.2 [base] (sysfs_pci_resource, parsed)
  ==> 0x00000000000c0000  (parsed, 1 source, 7 conflicts)
      range: 0x00000000000c0000 - 0x00000000febd5000  (4.0 GiB)

----------------------------------------
KASLR analysis:
  Virtual image base:   0xffffffff8fe00000
  Default image base:   0xffffffff81000000
  KASLR slide:          +0xee00000 (249561088)
  KASLR text entropy:   0 bits (pinned)

  Physical image base:  0x0000000034600000
  Default phys base:    0x0000000001000000
  Physical KASLR slide: +0x33600000 (861929472)
  Physical KASLR entropy: 0 bits (pinned)

Memory KASLR (directmap / vmalloc / vmemmap):
  Direct map base   guaranteed  >= 0xffff800000000000
  vmalloc base      guaranteed  0xffff810040000000 .. 0xffffdcffc0000000  94206 slots, ~17 bits
  vmemmap base      guaranteed  0xffffa10080000000 .. 0xfffffd0000000000  94206 slots, ~17 bits

----------------------------------------
Virtual address space (decoupled):

  0xffffffffffffffff
      . . .  16.0 MiB gap  . . .
  0xffffffffff000000
      modules (no leak)
  0xffffffffc0000000
      . . .  767.3 MiB gap  . . .
  0xffffffff900a9fc9
      kernel text
        leak hi: 0xffffffff900a9fc9
        leak lo: 0xffffffff8fe00000
  0xffffffff8fe00000
      . . .  128.0 TiB gap  . . .
      ^ extent unknown
      direct map (base proven; extent unknown)
  0xffff800000000000
      . . .  65408.0 TiB gap  . . .
  0xff00000000000000  (user space + non-canonical hole below)

Physical address space:

  0x00000000febd5000
      above DRAM
        0x00000000febd5000  [mmio] pci_mmio:0000:00:1f.2
        0x00000000febd4000  [mmio] pci_mmio:0000:00:01.0
        0x00000000febd0000  [mmio] pci_mmio:0000:00:02.0
        0x00000000feba0000  [mmio] pci_mmio:0000:00:02.0
        0x00000000feb80000  [mmio] pci_mmio:0000:00:02.0
        0x00000000feb40000  [mmio] pci_mmio:0000:00:02.0
        0x00000000fd000000  [mmio] pci_mmio:0000:00:01.0
  0x000000003ffdefff
      in DRAM
        0x000000003efc2000  [dram] initrd
        0x0000000036b34000  [bss] kernel_bss:kernel_bss
        0x0000000036000000  [data] kernel_data:kernel_data
        0x0000000034600000  [text] kernel
        0x00000000011ee000  [dram] vmcoreinfo
        0x00000000000c0000  [mmio] pci_mmio:0000:00:01.0
        0x0000000000020000  [dram] cmdline
        0x0000000000001000  [dram] ram
  0x0000000000000000
```

</details>

The slot and bit figures in the KASLR-analysis block are computed as
`slots = range / alignment-step` and `bits = ceil(log2(slots))` — the count of
alignment-aligned positions spanning the inferred range, and the rounded-up
base-2 logarithm of that count. The bits are an **upper bound on residual
entropy**: they assume every surviving slot is equally likely, whereas real KASLR
placement is slightly non-uniform (see
[bypass-techniques.md — Weak entropy](bypass-techniques.md#weak-entropy)), so the
true entropy is marginally lower. `0 bits` (a single surviving slot) means the
value is fully recovered.

These figures bound what KASLD recovered from the current vantage. A wide
residual or an empty result is not a security assurance — it reflects what the
implemented techniques could do here and now, not that the base is beyond reach.
See [limitations.md](limitations.md) for what a negative or partial result does
and does not imply.

### Oneline (`-1`)

`-1` (`--oneline`) produces a single shell-pipeable line with a **fixed
key set** — every key below appears on every line, in this order, so a
scraper can match `field=` unconditionally. A value that is unresolved
or not applicable to the arch/run renders the sentinel `na` (never a
fabricated, defaulted, or leaked value):

```
arch=x86_64 kaslr=on text=0xffffffff8fe00000 stext=na slide=+0xee00000(249561088) entropy=9bits ptext=0x34600000 pstext=na pslide=+0x33600000(861929472) pentropy=9bits dmap=0xffff800000000000 dram=[0x0..0x33fffffff](13.0 GiB) results=27
```

| Key | Meaning |
| --- | --- |
| `arch` | kernel machine (`uname`), or `unknown` |
| `kaslr` | `on` \| `off` \| `unsupported` \| `failed` (`failed` = randomization failed at boot: effective 0 bits, deterministic per boot — distinct from `off`, a deliberate opt-out at the link-time default) |
| `text` | virtual image base (`_text`); engine-resolved, never a leak |
| `stext` | virtual `_stext`, when it differs from the image base |
| `slide` | virtual KASLR slide, signed `±0xHEX(decimal)` |
| `entropy` | virtual residual entropy over the guaranteed window, `Nbits`; present whenever a window was resolved — an unpinned window reports its N bits, a pin reports `0bits`. `na` only when KASLR is off/unsupported |
| `ptext` | physical image base (`_text`) |
| `pstext` | physical `_stext`, when it differs from the physical image base |
| `pslide` | physical KASLR slide (decoupled arches only) |
| `pentropy` | physical residual entropy (same window / `na` rule as `entropy`) |
| `dmap` | direct-map base (`PAGE_OFFSET`); engine-resolved floor/pin |
| `dram` | physical DRAM extent, `[0xLO..0xHI](size)` |
| `results` | count of merged result records (not the raw component count) |

`na` carries the same "no value asserted" guarantee the human formats
express by omitting a row; `extra/ksymoff` anchors on `text=0x…`, so a
`text=na` line is correctly treated as having no derivable base.

### JSON (`-j`)

`-j` (`--json`) emits the **complete** structured view: every block
documented below is always present, whatever the other flags — a machine
consumer keys on presence-of-key, not on which flags were passed. This makes
one `-j` blob the full, self-contained posture snapshot a fleet/CI layer can
diff against a baseline or aggregate across hosts. (`--verbose` is the sole
addition: it appends each component's raw stdout `output` lines.) See
[docs/exploitation.md](exploitation.md) for how the JSON plugs into an exploit —
control-flow and data-only strategies, a pwntools template, and `ksymoff`.

The KASLR object reports two windows plus a headline base. The key names
differ from the text labels; the mapping is:

| Concept | JSON key | Text label |
| --- | --- | --- |
| Guaranteed window (sound floor; contains the true base) | `inferred` / `inferred_physical` | "Inferred text range" / "Guaranteed range" |
| Likely window (all signals; a subset of the guaranteed window; may be wrong) | `likely` / `likely_physical` (with `"speculative": true`) | "likely (speculative)" |
| Headline concrete base | `virtual` / `physical` → `image_base` | "Virtual / Physical image base" |

So `inferred*` is the guaranteed window and `likely*` is the speculative
best-guess, always contained within it. Memory-KASLR regions
(`memory_kaslr`) carry the same guaranteed `min`/`max` and an optional
nested `likely` object.

The `environment` object is the recon vantage: `container`, `seccomp`,
`capabilities`, `no_new_privs`, and a `readable_oracles` map for the `/proc`
leak sources (fields are a `null` or enum when they do not apply).

The `groups` array carries the leak evidence, one object per (`type`,
`section`, `region`) — the same split the text readout prints as separate
blocks. A group's aggregate describes only the region it names: `consensus`
(the most base-like address), `consensus_method`, `consensus_sources`,
`conflicts`, `interior_only` and the `lo`/`hi` span are computed over that
region's records alone, never across the other regions sharing its section.
Several regions routinely share one section — `dram` alone spans `ram`,
`initrd`, `cmdline`, `acpi_table` and more, whose bases are unrelated — so
`section` is not a unique key and `region` is what tells the groups apart.
Each group's `results` array lists its own records; `valid` marks whether a
record passes the layout bounds check.

The `components` array holds one record per component — `name`,
`exit_code`, `outcome`, an optional `disposition` (why a component produced no
tagged result: `category` — `mitigation` / `absent` / `disabled` /
`inconclusive` — plus, for a mitigation, the `gate` it confirmed and an optional
`message`), and the parsed `meta` from `KASLD_META` (including `cve` / `patch` /
`config` / `sysctl` keys). The `hardening` object is described under
[Hardening assessment](#hardening-assessment).
A per-component patch worklist — `{component, cve, fixed_in, leaked_here}`
— is a direct projection of the `components` array:

```sh
kasld -j | jq '[.components[]
  | select(.meta.cve or .meta.patch)
  | {component: .name, cve: .meta.cve, fixed_in: .meta.patch,
     leaked_here: (.outcome == "success")}]'
```

### Markdown (`-m`)

`-m` (`--markdown`) formats the summary for issue trackers (GitHub /
GitLab markdown tables). The KASLR table carries the same two-window
model as the text readout: the guaranteed **Inferred text range**, the
speculative **Likely text range** when a sub-floor signal narrows it,
the remaining slots with their grain (`N x <align>`) and entropy, the
**Phys/Virt coupling** classification, and any Memory-KASLR (directmap /
vmalloc / vmemmap) bounds. When the kernel-text function order is
reordered (FG-KASLR / LTO / AutoFDO / Propeller), a **Caution** note
warns that a leaked address no longer resolves the rest of the symbols
via a generic `System.map`. When KASLR is disabled or unsupported, the
compile-time **Kernel image base** is reported (there is no slide, so the
base is the answer). The leak table credits the component(s) that
produced each address. With `--verbose`, a `## Address space` section
embeds the virtual and physical ASCII address-space maps in a fenced code
block (the same diagrams the text readout draws). An `## Environment`
section reports the recon vantage (container / confinement / readable
oracles). With `-H` it also
appends the hardening assessment (see below).

## Explain mode

The `--explain` (`-e`) flag prints a brief technique explanation before
each component runs. Each component embeds a plain-text explanation in a
dedicated ELF section (`.kasld_explain`) via the `KASLD_EXPLAIN()` macro.
The orchestrator reads this section from the binary without executing it
and displays it inline.

This mode implies `--verbose`.

```
$ ./kasld --explain
...
[dmesg_free_reserved_area]
  Searches dmesg for 'Freeing ... memory' messages from free_reserved_area()
  that print kernel virtual addresses. These messages were removed in v4.10.
  On older kernels, they reveal kernel text and init section virtual addresses.
  Access is gated by dmesg_restrict.

  -> unavailable (feature/hardware not present)
...
```

## Hardening assessment

The `--hardening` (`-H`) flag appends a post-run hardening assessment that
evaluates the system's KASLR defenses based on the component results and
their machine-readable metadata. It opens with **Confirmed active mitigations**
(shown when present) — controls a component observed to defeat its leak this
run, keyed by the gate (`kpti`, an MDS hardware fix, a hardening `CONFIG`); this
is the runtime-observed complement to the sysctl gates, and appears in json as
`hardening.confirmed_mitigations`. It is followed by seven analysis sections:

1. **KASLR posture** (only when degraded) — surfaces a runtime KASLR
   state that downgrades effective slot entropy to 0 bits. Fires on
   "randomization failed" boot conditions (the boot stub attempted
   KASLR but could not produce a random offset: missing entropy seed,
   no PRNG, insufficient memory). The kernel still relocates but lands
   at a firmware-/boot-stub-deterministic position rather than the
   link-time default — meaningfully different from a deliberate
   opt-out, which the main results banner already reports. The full set
   of runtime states is catalogued in
   [kaslr.md — KASLR runtime states](kaslr.md#kaslr-runtime-states).
   Omitted when KASLR is healthy or opted out.

2. **Active defenses** — runtime security settings detected on the system
   (`dmesg_restrict`, `kptr_restrict`, `perf_event_paranoid`,
   `unprivileged_bpf_disabled`, `%pK` pointer hashing, lockdown mode) and
   their current values.

3. **Available hardening** — actionable suggestions for settings that are
   not currently active but would block one or more successful components
   (e.g. "Set `kernel.dmesg_restrict` = 1" if dmesg-based leaks succeeded).
   When the engine resolves a guaranteed base window, each suggestion is
   scored by re-resolving it: the section anchors on the current versus
   fully-hardened residual entropy, then reports, per suggestion, how much
   of that gap it is load-bearing for. The verdicts are *load-bearing —
   omitting forfeits N bits* (closing the others is not enough without this
   one), *recovers nothing* (the gate governs components but none leak the
   base), *speculative window only* (the leaks do not narrow the guaranteed
   base — the honest reading on a host whose guaranteed posture is already
   maxed), and *not required* (the base is recoverable, but the remaining
   suggestions already reach the same guaranteed posture). The numbers are
   deliberately non-additive: redundant leaks each read as load-bearing
   because closing any single one still leaves the base pinned.

4. **Patched vulnerabilities** — components that target known CVEs. Shows
   how many are patched (returned no result or unavailable) versus unpatched
   (successfully leaked), with CVE identifiers and patch versions.

5. **Compile-time attack surface** — successful components that exploit
   kernel features enabled at compile time (e.g. `CONFIG_E820_TABLE`,
   `CONFIG_EFI`), grouped by address type (physical vs. virtual).

6. **Hardware side-channels** — successful components that exploit CPU
   microarchitectural side channels (prefetch, EntryBleed, ZombieLoad,
   etc.), grouped by hardware mitigation status.

7. **No known mitigation** — successful components with no known sysctl
   gate, lockdown restriction, CVE, or kernel config dependency. These
   represent leak vectors that cannot be blocked by runtime hardening
   alone.

When the kernel-text function order can be determined, the assessment also
prints a **Function layout** block above these sections: `text ordering`
(canonical, or reordered static / per-boot) and `symbol resolution` (whether a
generic `System.map` resolves symbols, or only this build's does). Reordered
text is the [FG-KASLR / reordered-text class](kaslr.md#function-granular-kaslr-fg-kaslr)
(LTO, AutoFDO, Propeller, or FG-KASLR): functions no longer sit at a constant
offset from `_text`, so a leaked address pins only its own symbol and a generic
`System.map` no longer locates the rest.

In JSON, the assessment is the top-level `hardening` object, with fields
`exposure`, `kaslr_posture` (`state` is one of
`active` / `disabled` / `unsupported` / `randomization_failed`),
`active_defenses`, `lockdown`, `available_hardening`,
`patched_vulnerabilities`, `compile_time_surface`,
`hardware_side_channels`, and `no_mitigation`.
Each `active_defenses` and `available_hardening` entry carries a
`surface` — the enforcement lever the change lives on (`sysctl`,
`boot_param`, `lsm`, `file_permissions`, or `seccomp`) — so a report can
route each item to the team that owns it.
When the engine resolves a guaranteed base window, each `available_hardening`
entry also carries `silences` (base-leaks it removes) and a `projected`
object (the residual entropy with every other suggestion applied, and the
bits forfeited by omitting this one), and a top-level `projected_posture`
reports the `current` and `all_suggestions_applied` postures.
Markdown output (`-m -H`) appends the same assessment as a
`## Hardening Assessment` section; each Available-hardening suggestion
ends with its enforcement surface as a trailing `` [`lever`] `` tag
(e.g. `` [`sysctl`] ``, `` [`file_permissions`] ``).

## Continuous integration

KASLD has no built-in pass/fail flag: it *measures*, and the CI script
*decides*. A single `-j` blob carries every value a policy would key on —
including the whole `hardening` object — so a regression gate is a one-line
`jq` predicate, more flexible than a baked-in threshold, and it composes any
policy you like. A distro or kernel builder can fail the build when a freshly
built kernel's KASLR posture regresses below policy. The same blob is the unit
a fleet layer baselines and diffs: capture one per host, compare a later run,
and alert on any guaranteed-bit regression.

The fields a gate keys on:

- `.kaslr.inferred.entropy_bits` — the **guaranteed** residual entropy of the
  kernel base: the bits KASLD could not strip *with certainty*. Gate here for a
  sound "provably ≥ N bits" policy.
- `.kaslr.likely.entropy_bits` — the **speculative** residual (the narrower
  best-guess window). Gate here to also fail when a speculative technique could
  plausibly recover the base, accepting that this window is unproven.
- `.kaslr.disabled` / `.kaslr.unsupported` — booleans: KASLR opted out, or not
  applicable to the arch/config.
- `.hardening.patched_vulnerabilities.possibly_unpatched` — CVE-class components
  that *succeeded*. A behavioural signal, not a version check: KASLD never trusts
  `uname`, so this is "a CVE-class leak worked here", never "the kernel is
  version X". Empty means none did.

Each gate below exits non-zero on a policy breach:

```sh
# Fail if the guaranteed base entropy drops below 12 bits.
bits=$(kasld -j | jq '.kaslr.inferred.entropy_bits')
[ "$bits" -ge 12 ] || { echo "KASLR regressed: $bits guaranteed bits"; exit 1; }

# Fail if KASLR is off (disabled, or unsupported for this arch/config).
if kasld -j | jq -e '.kaslr.disabled or .kaslr.unsupported' >/dev/null; then
  echo "KASLR not active"; exit 1
fi

# Fail if any CVE-class leak succeeded.
n=$(kasld -j | jq '.hardening.patched_vulnerabilities.possibly_unpatched | length')
[ "$n" -eq 0 ] || { echo "$n CVE-class leak(s) succeeded"; exit 1; }
```

Run KASLD **unprivileged** in the target environment for the posture a real
unprivileged attacker sees; running it as root additionally exposes root-gated
sources (e.g. `/proc/iomem`), which measure a different threat model.

### Regression gate (`extra/posture-diff`)

To gate on *drift over time* rather than an absolute threshold, save a `-j`
snapshot as a baseline and compare a later run against it with
[extra/posture-diff](../extra/posture-diff) — a small `jq`-based helper that
exits non-zero if the KASLR posture regressed:

```sh
kasld -j > baseline.json            # once, when the host is known-good
# … later, or in CI …
kasld -j > current.json
extra/posture-diff baseline.json current.json || echo "posture regressed"
```

It compares only the boot-**stable**, security-relevant posture — guaranteed
residual entropy (virtual and physical), the KASLR posture state, unpatched
CVE-class leaks, and which defenses are off. The per-boot **volatile** values
(the resolved base address, slide, direct-map base) are never compared, so a
healthy reboot — which re-randomizes all of them — is *not* flagged; only a
genuine posture regression is. Exit `0` = no regression, `1` = regression
(findings printed), `2` = error. Snapshots can be live `-j` or replayed from an
[extra/collect](../extra/collect) bundle
(`KASLD_SYSROOT=<bundle>/sysroot kasld -j`), so a baseline captured on one host
can be checked from another.

### Fleet summary (`extra/posture-summary`)

To scan a whole estate at once, [extra/posture-summary](../extra/posture-summary)
rolls up many `-j` snapshots into one table — one row per host — instead of
reading N separate reports:

```sh
# one snapshot file per host (the filename is the host label)
for h in $(cat hosts); do ssh "$h" 'kasld -j' > "snap/$h.json"; done
extra/posture-summary snap/*.json
```

```
host     arch    kernel      kaslr   vbits  pbits  leaks  cves  top-fix
cache03  x86_64  6.12.81     active  9b     31b    2/71   0     Set kernel.perf_event_paranoid = 2
db02     aarch64 6.12.90     active  16b    16b    0/68   0     -
web01    x86_64  6.15.6      active  9b     31b    1/70   1     Enable kernel lockdown (integrity mode)
```

Each row carries only the boot-stable posture — KASLR state, guaranteed
residual entropy (virtual/physical), leaks succeeded/total, unpatched CVE-class
count, and the most load-bearing hardening action. The host label is the
snapshot's filename (`-j` carries no hostname), so name each file after its
host when you collect it; this tool does no collection or transport itself.
Output is an aligned text table by default, or `--markdown` (issue trackers),
`--csv` (spreadsheets), or `--json` (further tooling). A file that is not a
valid `kasld -j` snapshot is skipped with a warning rather than aborting the
report.
