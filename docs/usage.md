# Usage

`kasld` recovers a running kernel's memory layout — primarily the kernel text
base — for an unprivileged local user. Run it with no arguments and it prints an
answer: the recovered (or narrowed) virtual and physical image base, the direct
map base, and the leaks the answer was derived from.

Underneath, `kasld` gathers evidence from many small leak components (each a
standalone technique that probes one source) and feeds it to an inference engine
that narrows the layout to the smallest set of placements the evidence supports,
reporting every value with its provenance and any residual entropy. In normal use
that machinery is invisible — a single invocation prints the result. This
document covers the output modes and command-line options; for how the pieces fit
together see [architecture.md](architecture.md).

## Table of Contents

- [Quick start](#quick-start)
- [Command-line options](#command-line-options)
- [Output modes](#output-modes)
  - [Default text mode](#default-text-mode)
  - [Verbose (`-v`)](#verbose--v)
  - [Oneline (`-1`)](#oneline--1)
  - [JSON (`-j`)](#json--j)
  - [Markdown (`-m`)](#markdown--m)
- [Explain mode](#explain-mode)
- [Hardening assessment](#hardening-assessment)

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

Modern fully-patched systems with `kernel.dmesg_restrict=1`,
`kernel.kptr_restrict=1`, `kernel.perf_event_paranoid=2` (or higher), and
`%pK` pointer hashing (on by default) are expected to return limited results.
For testing purposes, the
[extra/weaken-kernel-hardening](../extra/weaken-kernel-hardening) script
can temporarily relax these settings (requires root).

## Command-line options

```
-j, --json          Machine-readable JSON output
-1, --oneline       Single-line summary output (shell-pipeable)
-m, --markdown      Markdown table output (for issue trackers)
-c, --color         Colorize text output (auto-detected for TTYs)
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
-H, --hardening     Append the post-run hardening assessment (composable
                    with any output mode)
-t, --timeout N     Per-component timeout in seconds (default: 30)
-V, --version       Print version and exit
-h, --help          Show this help
```

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

Running 94 components (3 experimental skipped; use -x to enable)...
[####################] 100%  94/94  13.9s

  Virtual image base  0xffffffff8fe00000   slide +0xee00000
  Physical image base 0x0000000034600000   slide +0x33600000
  Direct map base     >= 0xffff800000000000
  Phys/Virt coupling  physical and virtual text randomize independently

Leaks (6):
  virt kernel text    0xffffffff8ff04104 [interior]   (perf_event_open, proc_kallsyms)
  virt kernel image   0xffffffff8fe00000 [base]       (perf_event_open, prefetch, proc_kallsyms)
  virt directmap      0xffff9eeb80000000 [base]       (prefetch_directmap)
  phys kernel image   0x0000000034600000 [base]       (proc_iomem_kernel)
  phys kernel data    0x0000000036000000 [base]       (proc_iomem_kernel)
  phys kernel BSS     0x0000000036b34000 [base]       (proc_iomem_kernel)

[-v: detailed results, memory map, system info]  [-H: hardening assessment]
```

Terms in this readout (slide, directmap, coupling, slot/entropy) are defined in
the [kaslr.md glossary](kaslr.md#glossary); the engine vocabulary behind them
(quantity, estimate, honest top) is in the
[architecture.md glossary](architecture.md#glossary).

### Verbose (`-v`)

`-v` (`--verbose`) restores the full banner, system-config block,
per-component logs, per-region "Results" table, KASLR analysis section,
and a compact bracket-format virtual + physical memory layout:

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
  virt_page_offset_base >= 0xffff800000000000
  virt_vmalloc_base     0xffff810040000000 - 0xffffdcffc0000000  (94206 candidates, 17 bits)
  virt_vmemmap_base     0xffffa10080000000 - 0xfffffd0000000000  (94206 candidates, 17 bits)

----------------------------------------
Virtual memory layout (decoupled):

  0xffffffffffffffff
      modules (no leak)
  0xffffffffc0000000
      . . .  770.0 MiB gap  . . .
  0xffffffff8fe00000
      kernel text (pinned)
        leak hi: 0xffffffff900a9fc9
        leak lo: 0xffffffff8fe00000
  0xffffffff8fe00000
      . . .  128.0 TiB gap  . . .
  0xffff800000000000
      direct map (base; extent unknown)
  0xffff800000000000
      . . .  65408.0 TiB gap  . . .
  0xff00000000000000  (user space + non-canonical hole below)

Physical memory layout:

  0x000000003ffdefff
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

### Oneline (`-1`)

`-1` (`--oneline`) produces a single shell-pipeable line:

```
arch=x86_64 kaslr=on text=0xffffffff8fe00000 slide=+0xee00000(249561088) ptext=0x34600000 pslide=+0x33600000(861929472) dmap=0xffff800000000000 results=27
```

### JSON (`-j`)

`-j` (`--json`) emits the full structured summary. See
[docs/exploitation.md](exploitation.md) for a pwntools template that
consumes the JSON.

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

### Markdown (`-m`)

`-m` (`--markdown`) formats the summary for issue trackers (GitHub /
GitLab markdown tables). The KASLR table includes the inferred text
range and any Memory-KASLR (directmap / vmalloc / vmemmap) bounds, and
the leak table credits the component(s) that produced each address.
With `-H` it also appends the hardening assessment (see below).

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
their machine-readable metadata. The assessment has seven sections:

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
   (`dmesg_restrict`, `kptr_restrict`, `perf_event_paranoid`, `%pK` pointer
   hashing, lockdown mode) and their current values.

3. **Available hardening** — actionable suggestions for settings that are
   not currently active but would block one or more successful components
   (e.g. "Set `kernel.dmesg_restrict` = 1" if dmesg-based leaks succeeded).

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

The hardening assessment is also available in JSON output (`-j -H`),
where it appears in a top-level `"hardening"` object with fields
`exposure`, `kaslr_posture` (always present; `state` is one of
`active` / `disabled` / `unsupported` / `randomization_failed`),
`active_defenses`, `lockdown`, `available_hardening`,
`patched_vulnerabilities`, `compile_time_surface`, and `no_mitigation`.
Markdown output (`-m -H`) appends the same assessment as a
`## Hardening Assessment` section.
