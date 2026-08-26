# Changelog

## [0.3.0] — 2026-06-19

### Results

- **Complete RAM maps now narrow the physical base.** An E820 or device-tree
  memory map covers physical RAM in full, so the useful information is in the
  *gaps* between its extents: a gap is known non-RAM, so the image cannot start
  there.
- **Forbidden physical regions are carved out of the physical text base**, and the
  RAM-gap exclusion generalised to any authoritative map rather than E820 alone.
- **arm32 `PAGE_OFFSET` and text base are derived from the VMSPLIT** rather than
  assumed at the 3G/1G default.
- **The x86_64 direct map is pinned under `CONFIG_KASAN` and `nokaslr`**, where
  the kernel does not randomize it, and the pin takes 4- or 5-level paging from a
  resolved VA-bits fact instead of the build's assumption.
- **An interior sample's text-base ceiling is floored to slot alignment**, so a
  sample inside the image cannot imply a ceiling below the true base.
- **On ppc32 and riscv32 a physical leak now yields the virtual base.** Both
  hold their linear-map base fixed, so the two axes can be synthesised from
  either one.

### Techniques

Seven components added (95 → 102):

- `perf_ksymbol_leak` — BPF JIT, kprobe and ftrace trampoline addresses from
  perf side-band ksymbol records.
- `perf_lbr_sampling` — kernel branch addresses via Last Branch Record sampling.
- `proc_net_sock_ptr` — direct-map addresses from the socket-pointer field of
  `/proc/net/{unix,netlink}`.
- `ioctl_mmio_phys` — physical MMIO bases from framebuffer and serial ioctls, a
  fallback where `/proc/iomem` is masked.
- `btf_struct_page_size` — the exact `sizeof(struct page)` parsed from the
  kernel's own BTF type information.
- `function_order_fingerprint` — detects reordered kernel text (LTO, AutoFDO,
  Propeller, FG-KASLR) by kallsyms clustering.
- `arm64_no_seed` — KASLR-disabled detection on device-tree-booted arm64 whose
  FDT carries no usable seed.

### Interface

- **Component binaries were renamed from kebab-case to snake_case** — 32 of them,
  such as `boot-config` to `boot_config`. A script invoking a component directly
  by filename must be updated; running `kasld` itself is unaffected.
- The text readout places entropy beside status and carries full leak provenance.
- Markdown output shares the hardening model with the text renderer, so `-H`
  reports the same assessment in both.
- `KASLD_DEBUG_CONSTRAINTS` added, dumping engine constraints for debugging.
- Address-range helpers widened to 64-bit bounds.

## [0.2.0] — 2026-06-03

Until this release KASLD collected leaks and reported them. From `0.2.0` it
reasons about them: a layered resolver fuses every observation with the
architecture's own invariants and narrows each layout quantity to a window. The
practical consequence is that a run recovering no leak at all is no longer a
blank result — it still reports how much of the kernel's placement the evidence
ruled out, and how much is left.

### Results

- **63 rules over 13 architecture headers.** Each rule reads the collected
  evidence and the current estimates and emits constraints; the resolver re-runs
  them to a fixpoint, so a bound one rule derives feeds the next. Every quantity
  starts at its honest compile-time bound and only ever narrows, which is what
  makes the result a window rather than a list of candidate addresses.
- **Layout constants became engine inputs.** The per-architecture headers, which
  date from `0.0.4`, now state the bounds the resolver starts from rather than
  only the constants individual techniques consult.

### Techniques

Thirty added (66 → 95), one removed.

- Scalar-fact components — `cpuinfo_facts`, `meminfo_facts`, `devicetree_facts`,
  `fdt_facts`, `boot_params_facts`, `bootconfig_facts`, `kernel_image_facts`,
  `page_size` — which measure system properties rather than leak addresses, and
  exist to feed the new engine.
- VA-width probes: `mmap_arm64_va_bits`, `mmap_riscv64_va_bits`,
  `mmap_s390_va_bits`.
- KASLR-off detectors: `riscv64_no_seed`, `s390_kdump_nokaslr`,
  `loongarch_kexec_file_nokaslr`, `hibernation_nokaslr`.
- Physical-map sources: `proc_iomem_kernel`, `boot_params_e820`,
  `firmware_memmap`, `sysfs_devicetree_*`, `sysfs_iommu_reserved_regions`,
  `sysfs_nd_region`, and the `cmdline_*` family.
- `default` was **removed**: the compile-time text base is no longer reported as
  though it were a finding. It is now the starting estimate the engine narrows
  from.

## [0.1.1] — 2026-04-28

### Techniques

Fifteen added (51 → 66).

- Side channels: `sidt`, `zombieload`, `databounce`, `echoload` and
  `kernelsnitch`.
- `nilfs2_ioctl`, `acpi_mrrm`, `proc_timer_list` and
  `dmesg_acpi_dynamic_ssdt`.
- Several `sysfs_*` map readers.

### Interface

Eight options added.

- `-H`, `--hardening` — show a post-run hardening assessment.
- `-e`, `--explain` — show each technique's explanation before it runs.
- `-x`, `--experimental` — enable experimental components.
- `-s`, `--skip PATTERN` — skip matching components, by comma-separated glob.
- `-t`, `--timeout N` — per-component timeout in seconds.
- `-f`, `--fast` — use a shorter per-component timeout.
- `-w`, `--workers N` — parallel inference workers, defaulting to `nproc`.
- `-q`, `--quiet` — suppress the banner, progress and warnings.

## [0.1.0] — 2026-04-13

### Interface

- **`kasld` becomes a compiled orchestrator.** It had been a shell program since
  `0.0.1` — reporting the environment, then driving each technique in turn; by
  `0.0.4` that meant calling `make run`, with the `Makefile` holding a
  hand-maintained list of technique binaries, so adding a technique meant
  editing that list. From `0.1.0` `kasld` is a compiled program that discovers
  component binaries at run time, runs them, and post-processes their output.
- **First command line**: `--json`, `--markdown`, `--oneline`, `--color`,
  `--verbose`, `--version` and `--help`. Prior releases had no options at all.

### Architectures

- **s390** joined, bringing the supported set to twelve — arm32, arm64,
  loongarch64, mips32, mips64, ppc32, ppc64, riscv32, riscv64, s390, x86_32 and
  x86_64.

### Techniques

Eighteen added (33 → 51), one renamed, and every technique moved from `src/`
into `src/components/`.

- `prefetch` — the prefetch timing side channel.
- A wave of physical memory-map readers: `dmesg_e820_memory_map`,
  `dmesg_efi_memmap`, `sysfs_firmware_memmap`, `sysfs_memory_blocks`,
  `sysfs_devicetree_memory`, `sysfs_pci_resource`, `sysfs_vmcoreinfo`,
  `proc_zoneinfo`, `proc_cpuinfo` and the `dmesg_*` reservation parsers.
- `qemu-tcg-iret-x86_64` was renamed `qemu_tcg_iret`.

## [0.0.5] — 2026-04-10

### Architectures

- **LoongArch 64-bit joined**, and `dmesg_kaslr-disabled` learned to recognise
  the "KASLR is disabled" wording LoongArch uses.

### Techniques

Two added (31 → 33): `dmesg_reserved_mem_opensbi` and `qemu-tcg-iret-x86_64`.

### Interface

`extra/check-hardware-vulnerabilities` gained eleven more CPU vulnerability
checks, among them Gather Data Sampling, GhostWrite, Indirect Target Selection,
Register File Data Sampling, RetBleed, SRBDS, MMIO stale data and VMScape.

## [0.0.4] — 2024-04-12

### Techniques

Eight added (25 → 31), two folded in, one renamed.

- Added: `sysfs-kernel-notes-xen` (CVE-2024-26816), `dmesg_riscv_relocation`,
  `proc-modules`, `dmesg_check_for_initrd`,
  `dmesg_early_init_dt_add_memory_arch`, `dmesg_fake_numa_init`,
  `dmesg_free_area_init_node` and `dmesg_kaslr-disabled`.
- `cmdline` was renamed `proc-cmdline`.
- `syslog_backtrace` and `syslog_free_reserved_area` were folded into their
  `dmesg_*` counterparts rather than dropped. Each contributed its log-file
  reader — the same function, repointed from `/var/log/syslog` to
  `/var/log/dmesg` — so every `dmesg_*` component now reads both the kernel log
  buffer through `klogctl()` and the on-disk log.
- `sysfs-kernel-notes-xen` gained 32-bit x86 support.

### Results

- **riscv64's text range was widened.** Its floor dropped from
  `0xffffffff80000000` to `0xffffffe000000000`, and the module region was moved
  below kernel text rather than above it. The earlier bounds excluded legitimate
  riscv64 layouts.

### Interface

- **The build supports cross-compilation**, and `kasld` handed its list of
  technique binaries to the `Makefile`: the script had invoked each one
  directly, and now calls `make run`. `-static` was dropped from the default
  `LDFLAGS`.

### Architectures

- **`kasld.h` was split into one header per architecture**, so a bound could be
  stated once for a target instead of repeated in every technique. Ten carried
  real layout definitions: arm32, arm64, mips32, mips64, **ppc32**,
  **ppc64**, **riscv32**, **riscv64**, x86_32 and x86_64. PowerPC and RISC-V are
  new here.
- **SPARC is explicitly unsupported.** A `sparc.h` was added alongside the rest,
  but rather than defining a layout it stops the build and records why: Linux on
  sparc is largely abandoned and has no KASLR. It notes where kernel text starts
  on sparc32 and sparc64 so the question does not have to be researched again.

### Internals

The kernel-log reader `mmap_syslog()` was lifted out of eight `dmesg_*`
components into `src/include/syslog.h`, removing 28 duplicated lines from each.

## [0.0.3] — 2022-12-31

### Techniques

Thirteen added (13 → 25), five renamed, one relocated.

- Added: `entrybleed` (CVE-2022-4543), `proc-config`, `mmap-brute-vmsplit`,
  `proc-pid-syscall` (CVE-2020-28588), `sysfs-module-sections`, `sysfs_iscsi_transport_handle`,
  `bcm_msg_head_struct`, `dmesg_ex_handler_msr`, `dmesg_mmu_idmap`,
  `dmesg_mem_init_kernel_layout`, `dmesg_driver_component_ops`,
  `dmesg_android_ion_snapshot` and `syslog_backtrace`.
- **Sources gained a prefix naming where they read from**: `kallsyms` became
  `proc-kallsyms`, `nf_conntrack` became `sysfs_nf_conntrack`, `dmesg` became
  `dmesg_backtrace`, and the two `free_reserved_area_*` files became
  `dmesg_free_reserved_area` and `syslog_free_reserved_area`.
- `tsx-rtm` moved out of the technique set into
  `extra/check-hardware-vulnerabilities`, which also gained a RetBleed check.

### Results

- **arm64 bounds corrected**: the kernel address-space start was adjusted for
  52-bit virtual addressing, and the text-base floor fixed to
  `0xffff000008000000`. The ceiling was lowered.
- `mmap-brute-vmsplit` warns when the split it identifies falls below the
  architecture's kernel address-space start.

### Architectures

- **ARM (armv6, armv7, armv8) and MIPS (mipsel, mips64el) joined x86**, which
  until now had been the only target.

## [0.0.2] — 2020-03-13

### Techniques

Three added (10 → 13), one renamed.

- Added: `free_reserved_area_syslog`, reading `/var/log/syslog` and
  `/var/log/kern.log` — the same technique as its `dmesg` sibling, against the
  on-disk logs rather than the kernel log buffer.
- Added: `dmesg`, which searches the kernel log for splats and returns the first
  address that looks like a kernel pointer.
- Added: `proc-stat-wchan`.
- `syslog` was renamed `free_reserved_area_dmesg`. It was named after the
  syscall it calls, but what it reads is the kernel log buffer; the new name
  states the technique and the source, and frees "syslog" to mean the on-disk
  logs.
- Sources moved from the repository root into `src/`.
- `extra/oops_netlink_getsockbyportid_null_ptr.c` added — an oops trigger, for
  producing the kernel splat the log-reading techniques then parse.

## [0.0.1] — 2019-12-31

Initial release, targeting x86 and x86_64. `kasld` reported the kernel release,
version and architecture, then built and ran each of ten techniques in turn —
one command, one report.

Six recovered an address:

- `kallsyms` — the startup symbol straight from `/proc/kallsyms`, readable
  wherever `kptr_restrict` is 0, which was the default on Debian 9 and earlier.
- `syslog` — the `free_reserved_area()` message the kernel logs when it frees
  its init memory, read out of the log buffer with `klogctl`. Needs
  `dmesg_restrict` 0 or `CAP_SYSLOG`.
- `nf_conntrack` — the address of `init_net`, recovered from the slab
  directory names under `/sys/kernel/slab/nf_conntrack_*`.
- `pppd_kallsyms` — turns a `kptr_restrict` flaw against itself: the `%pK`
  check ran at `open()` rather than at `read()`, so the set-uid-root `pppd`
  would hand a symbol to an unprivileged caller.
- `perf_event_open` — samples kernel events and takes the lowest address seen,
  inferring the base rather than reading it. Needs `perf_event_paranoid` under 2.
- `mincore` — heap page disclosure via CVE-2017-16994.

Four established context instead of leaking, so a result could be read against
what the kernel was actually doing:

- `default` — the architecture's default, non-randomized text base.
- `boot-config` — whether the kernel was built with `CONFIG_RELOCATABLE` and
  `CONFIG_RANDOMIZE_BASE` at all.
- `cmdline` — whether `nokaslr` was passed on the kernel command line.
- `tsx-rtm` — whether the CPU offers TSX/RTM, and so whether a timing approach
  was worth attempting.

[0.3.0]: https://github.com/bcoles/kasld/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/bcoles/kasld/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/bcoles/kasld/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/bcoles/kasld/compare/v0.0.5...v0.1.0
[0.0.5]: https://github.com/bcoles/kasld/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/bcoles/kasld/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/bcoles/kasld/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/bcoles/kasld/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/bcoles/kasld/commits/v0.0.1
