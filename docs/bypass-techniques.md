# KASLR Bypass Techniques

Survey of techniques an unprivileged process can use to recover the kernel
text base — or other layout secrets — across mainstream Linux. This docs
indexes the entire technique space. Techniques KASLD implements are
documented with a link to the component source; everything else points
at the canonical reference.

KASLR bypass techniques broadly fall into several categories: reading kernel
pointers or memory layout details from filesystem interfaces, exploiting
microarchitectural or software side-channels, leaking addresses through
syscalls and kernel interfaces, exploiting ioctl handlers that copy
uninitialized kernel memory to userspace, brute-forcing memory layout
constraints, taking advantage of weak randomization entropy, leveraging
patched kernel info leak bugs, and using arbitrary read primitives.

## Table of Contents

- [Filesystem leaks](#filesystem-leaks)
  - [System logs](#system-logs)
  - [debugfs](#debugfs)
  - [Procfs and sysfs](#procfs-and-sysfs)
  - [Boot configuration](#boot-configuration)
- [Side-channels](#side-channels)
- [Syscall and interface leaks](#syscall-and-interface-leaks)
- [ioctl leaks](#ioctl-leaks)
- [Brute force](#brute-force)
- [Weak entropy](#weak-entropy)
- [Patched kernel bugs](#patched-kernel-bugs)
- [Arbitrary read](#arbitrary-read)

## Filesystem leaks

The kernel exposes a variety of information through pseudo-filesystems
(`/proc`, `/sys`), log files (`/var/log`), and boot configuration files
(`/boot`, `/proc/config.gz`) that can reveal kernel pointers or memory
layout details to unprivileged users.

### System logs

Kernel and system logs (`dmesg` / `syslog`) offer a wealth of information,
including kernel pointers and the layout of virtual and physical memory.

Many KASLD components search the kernel message ring buffer for kernel addresses.
The following KASLD components read from `dmesg` and `/var/log/dmesg`:

* [dmesg_acpi_dynamic_ssdt.c](../src/components/dmesg_acpi_dynamic_ssdt.c)
* [dmesg_android_ion_snapshot.c](../src/components/dmesg_android_ion_snapshot.c)
* [dmesg_backtrace.c](../src/components/dmesg_backtrace.c)
* [dmesg_check_for_initrd.c](../src/components/dmesg_check_for_initrd.c)
* [dmesg_cma_reserved.c](../src/components/dmesg_cma_reserved.c)
* [dmesg_crashkernel.c](../src/components/dmesg_crashkernel.c)
* [dmesg_driver_component_ops.c](../src/components/dmesg_driver_component_ops.c)
* [dmesg_e820_memory_map.c](../src/components/dmesg_e820_memory_map.c)
* [dmesg_early_init_dt_add_memory_arch.c](../src/components/dmesg_early_init_dt_add_memory_arch.c)
* [dmesg_efi_memmap.c](../src/components/dmesg_efi_memmap.c)
* [dmesg_ex_handler_msr.c](../src/components/dmesg_ex_handler_msr.c)
* [dmesg_fake_numa_init.c](../src/components/dmesg_fake_numa_init.c)
* [dmesg_free_area_init_node.c](../src/components/dmesg_free_area_init_node.c)
* [dmesg_free_reserved_area.c](../src/components/dmesg_free_reserved_area.c)
* [dmesg_kaslr_disabled.c](../src/components/dmesg_kaslr_disabled.c)
* [dmesg_last_pfn.c](../src/components/dmesg_last_pfn.c)
* [dmesg_mem_init_kernel_layout.c](../src/components/dmesg_mem_init_kernel_layout.c)
* [dmesg_mmu_idmap.c](../src/components/dmesg_mmu_idmap.c)
* [dmesg_node_data.c](../src/components/dmesg_node_data.c)
* [dmesg_ramdisk.c](../src/components/dmesg_ramdisk.c)
* [dmesg_reserved_mem.c](../src/components/dmesg_reserved_mem.c)
* [dmesg_reserved_mem_opensbi.c](../src/components/dmesg_reserved_mem_opensbi.c)
* [dmesg_riscv_relocation.c](../src/components/dmesg_riscv_relocation.c)
* [dmesg_swiotlb.c](../src/components/dmesg_swiotlb.c)

Historically, raw kernel pointers were frequently printed to the system log
without using the [`%pK` printk format](https://www.kernel.org/doc/html/latest/core-api/printk-formats.html).

* https://github.com/torvalds/linux/search?p=1&q=%25pK&type=Commits

Bugs which trigger a kernel oops can be used to leak kernel pointers by reading
the associated backtrace from system logs (on systems with `kernel.panic_on_oops = 0`).

For testing purposes, a backtrace can be forced using SysRq (requires root):

```
echo l > /proc/sysrq-trigger
```

This prints a backtrace of all CPUs to the kernel log, which the
`dmesg_backtrace` component will then parse. The SysRq `l` command requires
`kernel.sysrq` to include bit 4 (dump-backtrace), which is enabled by default
on most distro kernels (`kernel.sysrq = 1` enables all commands).

Most modern distros ship with `kernel.dmesg_restrict` enabled by default to
prevent unprivileged users from accessing the kernel debug log. Similarly,
grsecurity hardened kernels support `kernel.grsecurity.dmesg` to prevent
unprivileged access.

System log files (i.e., `/var/log/syslog`) are readable only by privileged users
on modern distros. On Debian/Ubuntu systems, users in the `adm` group also have
read permissions on various system log files in `/var/log/`:

```
$ ls -la /var/log/syslog /var/log/kern.log /var/log/dmesg
-rw-r----- 1 root   adm 147726 Jan  8 01:43 /var/log/dmesg
-rw-r----- 1 syslog adm    230 Jan 15 00:00 /var/log/kern.log
-rw-r----- 1 syslog adm   8322 Jan 15 04:26 /var/log/syslog
```

Typically the first user created during installation of an Ubuntu system
is a member of the `adm` group and will have read access to these files.

Additionally, [an initscript bug](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=867747)
present from 2017-2019 caused the `/var/log/dmesg` log file to be generated
with world-readable permissions (`644`) and may still be world-readable on
some systems.

### debugfs

Various areas of [debugfs](https://en.wikipedia.org/wiki/Debugfs)
(`/sys/kernel/debug/*`) may disclose kernel pointers.

debugfs is [no longer readable by unprivileged users by default](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=82aceae4f0d42f03d9ad7d1e90389e731153898f)
since kernel version `v3.7-rc1~174^2~57` on 2012-08-27.

This change pre-dates Linux KASLR by 2 years. However, debugfs may still be
readable in some non-default configurations.

### Procfs and sysfs

The `/proc` and `/sys` pseudo-filesystems expose kernel addresses, memory
layout details, symbol information, and hardware configuration. Many of
these files are readable by unprivileged users by default.

The following KASLD components read from `/proc`:

* [proc_kallsyms.c](../src/components/proc_kallsyms.c) — kernel symbol addresses from `/proc/kallsyms`
* [proc_modules.c](../src/components/proc_modules.c) — loaded module addresses from `/proc/modules`
* [proc_zoneinfo.c](../src/components/proc_zoneinfo.c) — memory zone boundaries from `/proc/zoneinfo`
* [proc_cpuinfo.c](../src/components/proc_cpuinfo.c) — CPU information from `/proc/cpuinfo`
* [proc_pid_syscall.c](../src/components/proc_pid_syscall.c) — kernel stack pointer from `/proc/<pid>/syscall`
* [proc_stat_wchan.c](../src/components/proc_stat_wchan.c) — wait channel address from `/proc/<pid>/stat`
* [proc_timer_list.c](../src/components/proc_timer_list.c) — per-CPU timer base addresses from `/proc/timer_list`

The following KASLD components read from `/sys`:

* [acpi_mrrm.c](../src/components/acpi_mrrm.c) — physical memory range base addresses from the Intel ACPI MRRM table via `/sys/firmware/acpi/memory_ranges/`
* [boot_params_e820.c](../src/components/boot_params_e820.c) — x86 E820 physical memory map and initrd physical address from `/sys/kernel/boot_params/data`
* [sysfs_cbmem_address.c](../src/components/sysfs_cbmem_address.c) — coreboot CBMEM physical memory addresses from `/sys/bus/coreboot/devices/`
* [sysfs_cxl_region.c](../src/components/sysfs_cxl_region.c) — CXL memory region host physical addresses from `/sys/bus/cxl/devices/`
* [sysfs_devicetree_elfcorehdr.c](../src/components/sysfs_devicetree_elfcorehdr.c) — kdump crash kernel ELF core header physical address from `/sys/firmware/devicetree/base/chosen/`
* [sysfs_devicetree_initrd.c](../src/components/sysfs_devicetree_initrd.c) — initrd address from `/sys/firmware/devicetree/`
* [sysfs_devicetree_memory.c](../src/components/sysfs_devicetree_memory.c) — memory regions from `/sys/firmware/devicetree/`
* [sysfs_devicetree_reserved_memory.c](../src/components/sysfs_devicetree_reserved_memory.c) — reserved DRAM region addresses from `/sys/firmware/devicetree/base/reserved-memory/`
* [sysfs_devicetree_uefi_mmap.c](../src/components/sysfs_devicetree_uefi_mmap.c) — EFI memory map buffer physical address from `/sys/firmware/devicetree/base/chosen/linux,uefi-mmap-*` (UEFI-booted device tree platforms)
* [sysfs_efi_runtime_map.c](../src/components/sysfs_efi_runtime_map.c) — EFI runtime map virtual and physical addresses from `/sys/firmware/efi/runtime-map/`
* [sysfs_firmware_memmap.c](../src/components/sysfs_firmware_memmap.c) — firmware memory map from `/sys/firmware/memmap/`
* [sysfs_iommu_reserved_regions.c](../src/components/sysfs_iommu_reserved_regions.c) — physical DRAM addresses of IOMMU reserved regions from `/sys/kernel/iommu_groups/*/reserved_regions`
* [sysfs_iscsi_transport_handle.c](../src/components/sysfs_iscsi_transport_handle.c) — iSCSI transport handle from `/sys/class/iscsi_transport/`
* [sysfs_kernel_notes_xen.c](../src/components/sysfs_kernel_notes_xen.c) — Xen notes from `/sys/kernel/notes`
* [sysfs_memory_blocks.c](../src/components/sysfs_memory_blocks.c) — memory block addresses from `/sys/devices/system/memory/`
* [sysfs_module_sections.c](../src/components/sysfs_module_sections.c) — module section addresses from `/sys/module/*/sections/`
* [sysfs_nd_region.c](../src/components/sysfs_nd_region.c) — NVDIMM/PMem region physical start addresses from `/sys/bus/nd/devices/region*/`
* [sysfs_nf_conntrack.c](../src/components/sysfs_nf_conntrack.c) — netfilter conntrack hash from `/sys/module/nf_conntrack/`
* [sysfs_pci_resource.c](../src/components/sysfs_pci_resource.c) — PCI BAR addresses from `/sys/bus/pci/devices/`
* [sysfs_qcom_rmtfs_mem.c](../src/components/sysfs_qcom_rmtfs_mem.c) — Qualcomm RMTFS reserved physical memory addresses from `/sys/class/rmtfs/`
* [sysfs_uio_map.c](../src/components/sysfs_uio_map.c) — UIO device memory map physical addresses from `/sys/class/uio/`
* [sysfs_vmcoreinfo.c](../src/components/sysfs_vmcoreinfo.c) — vmcoreinfo note physical address from `/sys/kernel/vmcoreinfo`

Most of these are mitigated by `kernel.kptr_restrict` (for `/proc/kallsyms`,
`/proc/modules`, etc.) and root-only permissions on sensitive sysfs entries.

### Boot configuration

Boot configuration and kernel config files can reveal whether KASLR is
enabled, the `PAGE_OFFSET` (vmsplit), and other layout-relevant settings.

The following KASLD components read boot configuration:

* [boot_config.c](../src/components/boot_config.c) — reads `/boot/config-*` for `CONFIG_RELOCATABLE`, `CONFIG_RANDOMIZE_BASE`, and `CONFIG_PAGE_OFFSET`
* [proc_config.c](../src/components/proc_config.c) — reads `/proc/config.gz` for the same configuration options
* [proc_cmdline.c](../src/components/proc_cmdline.c) — reads `/proc/cmdline` to check for `nokaslr`
* [hibernation_nokaslr.c](../src/components/hibernation_nokaslr.c) — checks whether hibernation resume has disabled KASLR

## Side-channels

There are a plethora of viable side-channel attacks which can be used to break
KASLR, including microarchitectural timing attacks, transient execution attacks,
and software side-channels that exploit timing variations in kernel algorithms
and data structures.

The following table catalogues known side-channel KASLR attacks.

| Attack | Year | Status | References |
|---|---|---|---|
| KernelSnitch | 2025 | **Implemented (experimental)**: [kernelsnitch.c](../src/components/kernelsnitch.c)<br>Futex hash-table timing leaks `mm_struct` directmap address (not `_stext`). x86_64, unprivileged. Requires `--experimental` (~1–30 min runtime). Mitigated by `CONFIG_FUTEX_PRIVATE_HASH` (mainline ~v6.14+) which removes `mm_struct` from the private futex hash key. | [KernelSnitch: Side-Channel Attacks on Kernel Data Structures](https://lukasmaar.github.io/papers/ndss25-kernelsnitch.pdf) (Maar et al., 2025) — [NDSS 2025](https://www.ndss-symposium.org/ndss-paper/kernelsnitch-side-channel-attacks-on-kernel-data-structures/)<br>[lukasmaar/kernelsnitch](https://github.com/lukasmaar/kernelsnitch) |
| GhostWrite (CVE-2024-44067) | 2024 | T-Head XuanTie C910/C920 RISC-V only (2 CPU models); kernel ≥6.14 disables vector extension as mitigation. | [GhostWrite](https://www.ghostwriteattack.com/)<br>[RISCover: Differential CPU Fuzz Testing](https://ghostwriteattack.com/riscover_ccs25.pdf) (Thomas et al., 2025)<br>[cispa/GhostWrite](https://github.com/cispa/GhostWrite), [cispa/RISCover](https://github.com/cispa/RISCover) |
| SLAM | 2024 | Requires Intel LAM / AMD UAI (no mainstream kernel support yet); Spectre-based, needs specific gadgets. | [Leaky Address Masking: Exploiting Unmasked Spectre Gadgets with Noncanonical Address Translation](https://download.vusec.net/papers/slam_sp24.pdf) (Hertogh et al., 2024)<br>[vusec.net/projects/slam](https://www.vusec.net/projects/slam/), [vusec/slam](https://github.com/vusec/slam) |
| SLUBStick (CVE-2024-26808) | 2024 | Achieves arbitrary kernel read/write (enabling KASLR bypass) via allocator timing side-channel, but requires a pre-existing heap vulnerability (UAF, heap overflow). Not a standalone KASLR bypass. | [SLUBStick: Arbitrary Memory Writes through Practical Software Cross-Cache Attacks within the Linux Kernel](https://www.usenix.org/system/files/usenixsecurity24-maar-slubstick.pdf) (Maar et al., 2024) — [USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/maar-slubstick) |
| GhostRace (CVE-2024-2193) | 2024 | Intel and AMD x86_64. Speculative Race Conditions — serialization primitives (mutexes, spinlocks, RCU read locks) can be bypassed under speculative execution. The CPU speculatively traverses kernel data structures while the protecting lock is speculatively considered unheld, enabling speculative reads from kernel memory. Not a standalone bypass; requires a suitable speculative window in the kernel. Mitigated by inserting `lfence` after every potentially-speculatively-bypassed conditional branch in affected synchronization primitives. | [GhostRace: Exploiting and Mitigating Speculative Race Conditions](https://download.vusec.net/papers/ghostrace_sec24.pdf) (Ragab, Barberis, Bos & Giuffrida, 2024) — [USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/ragab)<br>[vusec/ghostrace](https://github.com/vusec/ghostrace) |
| Downfall (CVE-2022-40982) | 2023 | Mitigated by microcode on affected Intel CPUs (6th-11th gen); Gather Data Sampling, complex setup. | [Downfall: Exploiting Speculative Data Gathering](https://downfall.page/media/downfall.pdf) (Moghimi, 2023) |
| Timing Transient Execution | 2023 | Depends on Meltdown-type transient execution; mitigated by KPTI on all affected Intel CPUs. | [Timing the Transient Execution: A New Side-Channel Attack on Intel CPUs](https://arxiv.org/pdf/2304.10877.pdf) (Jin et al., 2023) |
| Inception / SRSO (CVE-2023-20569) | 2023 | AMD x86_64 only; Zen 3 and Zen 4. Speculative Return Stack Overflow — phantom calls inserted by the branch predictor poison the return address predictor, causing return instructions to speculate to attacker-controlled targets in kernel context. Demonstrated end-to-end KASLR bypass via speculative reads of kernel memory. Mitigated by `IBPB-on-entry` or `safe-ret` (a retpoline variant that breaks speculative return chaining) on affected CPUs. | [Inception: Exposing New Attack Surfaces with Training in Transient Execution](https://comsec.ethz.ch/wp-content/files/inception_sec23.pdf) (Trujillo, Wikner & Razavi, 2023) — [USENIX Security 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/trujillo)<br>[comsec-group/inception](https://github.com/comsec-group/inception) |
| AMD Prefetch Attacks (CVE-2021-26318) | 2022 | Mitigated on Zen 3+ via microcode (AMD-SB-1017); redundant on older AMD / VMs where `prefetch.c` also works. | [AMD Prefetch Attacks through Power and Time](https://www.usenix.org/system/files/sec22-lipp.pdf) (Lipp et al., 2022) — [USENIX Security 2022](https://www.youtube.com/watch?v=bTV-9-B26_w)<br>[AMD-SB-1017](https://www.amd.com/en/corporate/product-security/bulletin/amd-sb-1017)<br>[amdprefetch/amd-prefetch-attacks](https://github.com/amdprefetch/amd-prefetch-attacks/tree/master/case-studies/kaslr-break) |
| AMD RAPL power side-channel (CVE-2021-26318) | 2022 | Unprivileged RAPL access blocked since Linux 5.10; requires `amd_energy` module (not loaded by default); mitigated by same microcode as timing variant. | [AMD Prefetch Attacks through Power and Time](https://www.usenix.org/system/files/sec22-lipp.pdf) (Lipp et al., 2022) |
| EntryBleed (CVE-2022-4543) | 2022 | **Implemented**: [entrybleed.c](../src/components/entrybleed.c)<br>Intel x86_64 with KPTI enabled or disabled; AMD x86_64 with KPTI disabled. Requires kernel-version-specific offsets. Patched in kernel ~v6.2 (randomized per-CPU entry areas). | [EntryBleed: Breaking KASLR under KPTI with Prefetch (CVE-2022-4543)](https://www.willsroot.io/2022/12/entrybleed.html) (willsroot, 2022)<br>[EntryBleed: A Universal KASLR Bypass against KPTI on Linux](https://dl.acm.org/doi/pdf/10.1145/3623652.3623669) (William Liu, Joseph Ravichandran, Mengjia Yan, 2023) |
| RETBLEED | 2022 | Kernel mitigated (IBRS/eIBRS, retpoline); requires specific Intel (6th-8th gen) or AMD (Zen 1/1+/2) CPUs. | [RETBLEED: Arbitrary Speculative Code Execution with Return Instructions](https://comsec.ethz.ch/wp-content/files/retbleed_sec22.pdf) (Wikner & Razavi, 2022)<br>[comsec-group/retbleed](https://github.com/comsec-group/retbleed) |
| SLS (CVE-2021-26341) | 2022 | AMD Zen 1/2 only; requires eBPF JIT (restricted since Linux 5.8); mitigated by INT3/LFENCE after every unconditional branch. | [The AMD Branch (Mis)predictor Part 2: Where No CPU has Gone Before](https://grsecurity.net/amd_branch_mispredictor_part_2_where_no_cpu_has_gone_before) (Wieczorkiewicz, 2022)<br>[Straight-line Speculation Whitepaper](https://developer.arm.com/documentation/102825/0100/?lang=en) (ARM, 2020) |
| ThermalBleed | 2022 | Thermal side-channel operates at ms-second timescale; far too slow/noisy for KASLR (needs sub-µs resolution). | [ThermalBleed: A Practical Thermal Side-Channel Attack](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=9727162) (Kim & Shin, 2022) |
| Hertzbleed (CVE-2022-23823, CVE-2022-24436) | 2022 | Dynamic-frequency (DVFS) side-channel: under a power/thermal cap, core frequency depends on the data being processed, turning nominally constant-time code into data-dependent wall-clock time (observable via `cpufreq` or a reference-workload timer). Demonstrated against cryptographic keys (SIKE), not KASLR — no known unprivileged kernel operation has a frequency reaction that depends on a KASLR-placed address, so a KASLR application is unproven. Requires DVFS-observable bare metal (a VM guest cannot see real frequency reactions) and is slow (≈bits/hour). Intel 8th-gen+; AMD Zen 2/3. Mitigated by disabling Turbo / Precision Boost or capping frequency. | [Hertzbleed: Turning Power Side-Channel Attacks Into Remote Timing Attacks on x86](https://www.hertzbleed.com/hertzbleed.pdf) (Wang, Paccagnella, He, Shacham, Fletcher, Kohlbrenner, 2022) — [USENIX Security 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/wang-yingchen)<br>[hertzbleed.com](https://www.hertzbleed.com/) |
| MMIO Stale Data (CVE-2022-21123, CVE-2022-21125, CVE-2022-21127, CVE-2022-21166) | 2022 | Intel x86_64; Intel CPUs from Skylake through Alder Lake. MMIO read completions propagate stale data through shared microarchitectural buffers (fill buffers, load ports, store buffers) where it can be sampled cross-privilege. Four variants: SBDR (Shared Buffer Data Read), SBDS (Shared Buffer Data Sampling), SRBDS update (Special Register Buffer), and DRPW (Device Register Partial Write). Mitigated by `VERW` in kernel entry/exit paths (same mechanism as MDS) plus microcode update. | [Processor MMIO Stale Data Vulnerabilities](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/processor-mmio-stale-data-vulnerabilities.html) (Intel, 2022)<br>[kernel.org: Processor MMIO Stale Data Vulnerabilities](https://docs.kernel.org/admin-guide/hw-vuln/processor_mmio_stale_data.html) |
| Spectre-BHB / Native BHI (CVE-2022-0001, CVE-2022-0002) | 2022 | Intel x86_64; bypasses eIBRS and Retpoline by poisoning the Branch History Buffer (BHB) from userspace before a syscall, causing indirect branches in kernel context to speculate to attacker-chosen targets. "InSpectre Gadget" (Hermans et al., 2024) provides a systematic framework for finding Native BHI gadgets in the Linux kernel and demonstrated end-to-end KASLR bypass via speculative kernel memory reads. Mitigated by `BHI_DIS_S` microcode feature and `CLEAR_BHB` instruction sequences in kernel entry/exit paths (≥v6.8). | [Branch History Injection](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/branch-history-injection.html) (Intel, 2022)<br>[InSpectre Gadget: Inspecting the Residual Attack Surface of Cross-privilege Spectre v2](https://download.vusec.net/papers/inspectre_sp24.pdf) (Hermans et al., 2024) — [IEEE S&P 2024](https://www.ieee-security.org/TC/SP2024/program.html)<br>[vusec/inspectre-gadget](https://github.com/vusec/inspectre-gadget) |
| Spectre-BHB on ARM (CVE-2022-23960) | 2022 | ARM aarch64; affects Cortex-A57, A72, A73, A75, A76, A77, A78, Cortex-X1, Cortex-X2, Neoverse-N1, Neoverse-N2. Same primitive as Intel Native BHI — userspace poisons the Branch History Buffer before a syscall so indirect branches in EL1 speculate to attacker-controlled targets, enabling speculative reads of kernel memory. Naturally-occurring gadgets in upstream Linux are sufficient (no kernel patch needed); the InSpectre-Gadget framework finds them. Mitigated by `CLEAR_BHB`-equivalent loop sequences in kernel entry/exit paths (≥v6.8) and the `CSV2`/`CSV3` ID feature reporting. Requires a userspace cycle counter; on hardened ARM64 kernels `PMUSERENR_EL0.EN` is clear by default and `pmccntr_el0` traps to SIGILL — `cntvct_el0` is too coarse (~50 ns) for the timing channel. Decode `CPU part` from `/proc/cpuinfo`: `0xd07` A57, `0xd08` A72, `0xd09` A73, `0xd0a` A75, `0xd0b` A76, `0xd0d` A77, `0xd0e` A78, `0xd44` X1, `0xd0c` N1, `0xd49` N2. | [Spectre-BHB / Branch History Injection on Arm CPUs](https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/branch-history-injection-and-intra-mode-branch-target-injection) (Arm, 2022)<br>[kernel.org: Spectre Side Channels](https://docs.kernel.org/admin-guide/hw-vuln/spectre.html#mitigation-control-on-the-kernel-command-line) (Arm-specific section)<br>[InSpectre Gadget: Inspecting the Residual Attack Surface of Cross-privilege Spectre v2](https://download.vusec.net/papers/inspectre_sp24.pdf) (Hermans et al., 2024) — applicable to Arm targets via the same gadget-finder framework |
| Memory deduplication timing | 2021 | Requires KSM enabled (disabled by default on most distros); primarily a VM-to-VM attack. | [Memory deduplication as a threat to the guest OS](https://kth.diva-portal.org/smash/get/diva2:1060434/FULLTEXT01) (Suzaki et al., 2011)<br>[Breaking KASLR Using Memory Deduplication in Virtualized Environments](https://www.mdpi.com/2079-9292/10/17/2174) (Kim et al., 2021)<br>[Remote Memory-Deduplication Attacks](https://pure.tugraz.at/ws/portalfiles/portal/38441480/main.pdf) (Schwarzl et al., 2022) |
| VDSO sidechannel | 2021 | ARM64 only; requires custom kernel gadget in VDSO; mitigated by Spectre barriers in VDSO code. | [VDSO As A Potential KASLR Oracle](https://www.longterm.io/vdso_sidechannel.html) (Pettersson & Radocea, 2021) |
| EchoLoad | 2020 | **Implemented (experimental)**: [echoload.c](../src/components/echoload.c)<br>Intel x86_64 only; relies on Meltdown zero-return behavior. Supports TSX, speculation, and signal-handler transient modes. No signal on non-vulnerable hardware (AMD, modern Intel with in-silicon Meltdown fix). Mitigated by KPTI on patched kernels. Requires `--experimental`. | [KASLR: Break It, Fix It, Repeat](https://gruss.cc/files/kaslrbfr.pdf) (Claudio Canella, Michael Schwarz, Martin Haubenwallner, 2020)<br>[Store-to-Leak Forwarding: There and Back Again](https://i.blackhat.com/asia-20/Friday/asia-20-Canella-Store-To-Leak-Forwarding-There-And-Back-Again-wp.pdf) (Canella et al., 2020) — [Slides](https://misc0110.net/files/store2leak_blackhat_slides.pdf), [Blackhat Asia 2020](https://www.youtube.com/watch?v=Yc1AXkCu2AA)<br>[cc0x1f/store-to-leak-forwarding/echoload](https://github.com/cc0x1f/store-to-leak-forwarding-there-and-back-again/tree/master/echoload) |
| PLATYPUS | 2020 | Unprivileged RAPL access restricted since Linux 5.10 (`powercap` driver); requires Intel CPU with specific RAPL interface. | [PLATYPUS: Software-based Power Side-Channel Attacks on x86](https://platypusattack.com/platypus.pdf) (Lipp et al., 2020) |
| TagBleed | 2020 | Requires Intel CPU with tagged TLBs and a VMM environment; narrow applicability. | [TagBleed: Breaking KASLR on the Isolated Kernel Address Space using Tagged TLBs](https://download.vusec.net/papers/tagbleed_eurosp20.pdf) (Koschel et al., 2020)<br>[renorobert/tagbleedvmm](https://github.com/renorobert/tagbleedvmm) |
| SRBDS / CrossTalk (CVE-2020-0543) | 2020 | Intel x86_64; Intel CPUs from Core 6th gen through some 10th gen. The Special Register Buffer used by `RDRAND`, `RDSEED`, and SGX `EGETKEY` is shared across all logical cores on the same physical core. Data from one logical core's `RDRAND` result can be sampled by another via a Flush+Reload side-channel on the shared buffer. On kernels that use `RDRAND` for KASLR seeding, leaked values can constrain or reveal the KASLR seed. Demonstrated cross-VM leakage. Mitigated by serializing the Special Register Buffer with a microcode-injected fence around affected instructions. | [CrossTalk: Speculative Data Leaks Across Cores Are Real](https://download.vusec.net/papers/crosstalk_sp21.pdf) (Ragab, Milburn, Razavi, Bos & Giuffrida, 2021) — [IEEE S&P 2021](https://www.vusec.net/projects/crosstalk/)<br>[vusec/crosstalk](https://github.com/vusec/crosstalk)<br>[kernel.org: SRBDS](https://docs.kernel.org/admin-guide/hw-vuln/special-register-buffer-data-sampling.html) |
| MDS / ZombieLoad / RIDL / Fallout (CVE-2018-12130) | 2019 | **Implemented (experimental)**: [zombieload.c](../src/components/zombieload.c)<br>Intel x86_64 only; requires TSX (RTM) and an MDS-vulnerable CPU (pre-Ice Lake). Leaks kernel text base from stale line fill buffer (LFB) data after a syscall. Samples all 64 cache-line byte offsets and reconstructs kernel pointers from Flush+Reload histograms. Mitigated by MDS buffer clearing (VERW) on supported microcode; hardware fix in Ice Lake+. TSX disabled via microcode on most consumer CPUs since 2019. AMD CPUs are not affected. Requires `--experimental`. | [ZombieLoad: Cross-Privilege-Boundary Data Sampling](https://zombieloadattack.com/zombieload.pdf) (Schwarz, Lipp, Moghimi, Van Bulck, Stecklina, Prescher, Gruss, 2019) — [CCS 2019](https://zombieloadattack.com/)<br>[RIDL: Rogue In-Flight Data Load](https://mdsattacks.com/files/ridl.pdf) (van Schaik, Milburn, Österlund, Frigo, Maisuradze, Razavi, Bos, Giuffrida, 2019) — [S&P 2019](https://mdsattacks.com/), [vusec/ridl](https://github.com/vusec/ridl)<br>[Fallout: Leaking Data on Meltdown-resistant CPUs](https://mdsattacks.com/files/fallout.pdf) (Canella et al., 2019) — [fallout_kaslr.c](https://github.com/wbowling/cpu.fail/blob/master/fallout_kaslr.c)<br>[IAIK/ZombieLoad](https://github.com/IAIK/ZombieLoad), [zombieload_kaslr.c](https://github.com/wbowling/cpu.fail/blob/master/zombieload_kaslr.c) |
| Data Bounce | 2019 | **Implemented**: [databounce.c](../src/components/databounce.c)<br>Intel x86_64 only; requires TSX (RTM). Exploits store-to-load forwarding within a TSX transaction. Works with KPTI enabled or disabled, bare metal and VMs. TSX deprecated by Intel, disabled via microcode on most consumer CPUs since 2019 (TAA mitigation). | [Store-to-Leak Forwarding: Leaking Data on Meltdown-resistant CPUs](https://cpu.fail/store_to_leak_forwarding.pdf) (Michael Schwarz, Claudio Canella, Lukas Giner, Daniel Gruss, 2019)<br>[cc0x1f/store-to-leak-forwarding/data_bounce](https://github.com/cc0x1f/store-to-leak-forwarding-there-and-back-again/tree/master/data_bounce) |
| TAA / TSX Asynchronous Abort (CVE-2019-11135) | 2019 | Intel x86_64 only; requires an MDS-vulnerable CPU (pre-Ice Lake) with TSX enabled. A TSX transaction abort triggered asynchronously by the microcode fills the Line Fill Buffer with stale data from other logical cores' recent operations, which can then be sampled via a Flush+Reload channel. Distinct from ZombieLoad (which uses synchronous fault-based LFB sampling) — TAA uses the TSX asynchronous abort mechanism to trigger LFB fill. Shares the same `VERW` mitigation as MDS/ZombieLoad, shipped together in the November 2019 microcode release. TSX disabled via microcode on most consumer CPUs since 2019. | [TSX Asynchronous Abort](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/tsx-async-abort.html) (Intel, 2019)<br>[kernel.org: TSX Async Abort](https://docs.kernel.org/admin-guide/hw-vuln/tsx_async_abort.html) |
| Meltdown | 2018 | Fully mitigated by KPTI on all vulnerable CPUs; KPTI enabled by default since 2018. | [Meltdown: Reading Kernel Memory from User Space](https://meltdownattack.com/meltdown.pdf) (Lipp et al., 2018) — [USENIX Security 2018](https://www.usenix.org/conference/usenixsecurity18/presentation/lipp)<br>[IAIK/meltdown](https://github.com/IAIK/meltdown), [paboldin/meltdown-exploit](https://github.com/paboldin/meltdown-exploit) |
| Spectre v1 / v2 | 2018 | Heavily mitigated (retpoline, IBRS/eIBRS, eBPF verifier hardening). KASLR break requires eBPF JIT or specific kernel gadgets; eBPF restricted to `CAP_BPF` since Linux 5.8. | [Spectre Attacks: Exploiting Speculative Execution](https://spectreattack.com/spectre.pdf) (Kocher et al., 2018)<br>[Reading privileged memory with a side-channel](https://googleprojectzero.blogspot.com/2018/01/reading-privileged-memory-with-side.html) (Jann Horn, 2018)<br>[speed47/spectre-meltdown-checker](https://github.com/speed47/spectre-meltdown-checker) |
| SPECULOSE | 2018 | Equivalent to prefetch-style probing via speculative execution; fully mitigated by KPTI. | [SPECULOSE: Analyzing the Security Implications of Speculative Execution in CPUs](https://arxiv.org/pdf/1801.04084v1.pdf) (Maisuradze & Rossow, 2018) |
| Prefetch side-channel | 2016 | **Implemented**: [prefetch.c](../src/components/prefetch.c)<br>Intel and AMD x86_64. Requires KPTI to be disabled (kernel auto-disables KPTI on non-Meltdown-vulnerable CPUs: all AMD, Intel Ice Lake+). Does not require kernel-version-specific offsets. On some newer AMD microarchitectures (Zen 3+) the kernel-text prefetch timing differential is absent; the component reports no signal rather than emitting a false positive. | [Prefetch Side-Channel Attacks: Bypassing SMAP and Kernel ASLR](https://gruss.cc/files/prefetch.pdf) (Daniel Gruss, Clémentine Maurice, Anders Fogh, 2016)<br>[Using Undocumented CPU Behaviour to See into Kernel Mode and Break KASLR in the Process](https://www.blackhat.com/docs/us-16/materials/us-16-Fogh-Using-Undocumented-CPU-Behaviour-To-See-Into-Kernel-Mode-And-Break-KASLR-In-The-Process.pdf) (Anders Fogh, Daniel Gruss, 2016) — [Blackhat USA](https://www.youtube.com/watch?v=Pwq0vv4X7m4)<br>[xairy/kernel-exploits/prefetch-side-channel](https://github.com/xairy/kernel-exploits/tree/master/prefetch-side-channel)<br>[Fetching the KASLR slide with prefetch](https://googleprojectzero.blogspot.com/2022/12/exploiting-CVE-2022-42703-bringing-back-the-stack-attack.html) (Seth Jenkins, 2022) — [prefetch_poc.zip](https://bugs.chromium.org/p/project-zero/issues/detail?id=2351) |
| Prefetch direct-map (`page_offset_base`) | 2016 | **Implemented**: [prefetch_directmap.c](../src/components/prefetch_directmap.c)<br>The same prefetch primitive applied to the direct map (the linear mapping of all physical RAM), whose base `page_offset_base` is randomized independently of kernel text by `CONFIG_RANDOMIZE_MEMORY` on x86_64. Scans the 1 GiB (PUD)-aligned candidate bases and locates the mapped region's left edge, recovering `page_offset_base` — which resolves the virtual↔physical translation (physical leaks then map to virtual addresses and vice versa). Intel and AMD x86_64; 4-level paging only (the 5-level window spans tens of petabytes, too large for a flat scan, so it declines under `la57`). The 1 GiB-huge-page mapping produces a weaker differential than 2 MiB kernel text, so a run that cannot resolve the edge reports a weak/no signal rather than emitting a false base. | [Prefetch Side-Channel Attacks: Bypassing SMAP and Kernel ASLR](https://gruss.cc/files/prefetch.pdf) (Daniel Gruss, Clémentine Maurice, Anders Fogh, 2016) |
| BTB side-channel | 2016 | Complex implementation; largely superseded by simpler prefetch / EntryBleed techniques. | [Jump Over ASLR: Attacking Branch Predictors to Bypass ASLR](https://www.cs.ucr.edu/~nael/pubs/micro16.pdf) (Evtyushkin et al., 2016)<br>[felixwilhelm/mario_baslr](https://github.com/felixwilhelm/mario_baslr) |
| DRAMA | 2016 | DRAM row-buffer conflict timing reverse-engineers the memory-controller addressing function, then recovers physical-address bits of a target page — read-only and non-destructive (distinct from RAMBleed/rowhammer below, which is a slow destructive write primitive). Combined with the kernel linear map, recovered physical bits of a pinned kernel object constrain the physical text base / `PAGE_OFFSET`. Not implemented. Requires bare metal (a VM guest's physical addresses are decoupled from host DRAM rows), a way to obtain buffers with known physical bits without `pagemap` (THP / contiguous allocation), and per-platform DRAM-geometry reverse-engineering. | [DRAMA: Exploiting DRAM Addressing for Cross-CPU Attacks](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_pessl.pdf) (Pessl, Gruss, Maurice, Schwarz, Mangard, 2016) — [USENIX Security 2016](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/pessl)<br>[IAIK/drama](https://github.com/IAIK/drama) |
| TSX/RTM abort timing (DrK) | 2016 | TSX deprecated by Intel, disabled via microcode on most consumer CPUs since 2019 (TAA mitigation). Redundant with Data Bounce on TSX-capable hardware. | [TSX improves timing attacks against KASLR](http://web.archive.org/web/20141107045306/http://labs.bromium.com/2014/10/27/tsx-improves-timing-attacks-against-kaslr/) (Rafal Wojtczuk, 2014)<br>[DrK: Breaking KASLR with Intel TSX](https://www.blackhat.com/docs/us-16/materials/us-16-Jang-Breaking-Kernel-Address-Space-Layout-Randomization-KASLR-With-Intel-TSX.pdf) (Jang et al., 2016) — [Blackhat USA](https://www.youtube.com/watch?v=rtuXG28g0CU)<br>[vnik5287/kaslr_tsx_bypass](https://github.com/vnik5287/kaslr_tsx_bypass) |
| Double page fault timing | 2013 | Precursor to prefetch side-channel; fully mitigated by KPTI (Meltdown patches). Superseded by prefetch / EntryBleed. | [Practical Timing Side Channel Attacks Against Kernel Space ASLR](https://openwall.info/wiki/_media/archive/TR-HGI-2013-001.pdf) (Hund et al., 2013) |
| SIDT/SGDT IDT/GDT base leak | 2004 | **Implemented**: [sidt.c](../src/components/sidt.c)<br>x86/x86_64. Unprivileged `SIDT` instruction reads IDT register containing kernel pointer. Only works on pre-3.10 kernels where `idt_table` was in kernel BSS. Mitigated by IDT-to-fixmap remapping (v3.10, 2013; predates KASLR v3.14), KPTI (v4.15, 2018), and UMIP hardware (Intel Cannon Lake+ / AMD Zen 2+). Never viable against vanilla KASLR kernels. Originally used for VM detection (Red Pill, 2004); later demonstrated as a KASLR bypass against out-of-tree patches (Hund, 2013). | [KASLR is Dead: Long Live KASLR](https://gruss.cc/files/kaiser.pdf) (Gruss et al., 2017) — Section 2 lists SIDT as a known KASLR bypass<br>[Practical Timing Side Channel Attacks Against Kernel Space ASLR](https://www.ieee-security.org/TC/SP2013/papers/4977a191.pdf) (Hund et al., 2013)<br>[Red Pill](http://web.archive.org/web/20110726182809/http://invisiblethings.org/papers/redpill.html) (Joanna Rutkowska, 2004) |

Note: Several related attacks (LVI, RAMBleed) are omitted from the table
because they are not KASLR bypass techniques. LVI targets SGX enclaves;
RAMBleed is a general memory read primitive (rowhammer-based, hours-slow).

The [extra/check-hardware-vulnerabilities](../extra/check-hardware-vulnerabilities)
script performs rudimentary checks for several known hardware vulnerabilities,
but does not implement these techniques.

See also:

* [google/safeside](https://github.com/google/safeside) — project to understand and mitigate software-observable side-channels (Google)
* [Hardening the Kernel Against Unprivileged Attacks](https://www.cc0x1f.net/publications/thesis.pdf) (Claudio Canella, 2022)
* [Exploiting Microarchitectural Optimizations from Software](https://diglib.tugraz.at/download.php?id=61adc85670183&location=browse) (Moritz Lipp. 2021)
* [transient.fail](https://transient.fail/) — overview of speculative / transient execution attacks (Graz University of Technology, 2020)
* [LVI: Hijacking Transient Execution through Microarchitectural Load Value Injection](https://www.semanticscholar.org/paper/LVI:-Hijacking-Transient-Execution-through-Load-Bulck-Moghimi/5cbf634d4308a30b2cddb4c769056750233ddaf6) (Jo Van Bulck, Daniel Moghimi, Michael Schwarz, Moritz Lipp, Marina Minkin, Daniel Genkin, Yuval Yarom, Berk Sunar, Daniel Gruss, and Frank Piessens, 2020)
* [A Systematic Evaluation of Transient Execution Attacks and Defenses](https://www.cc0x1f.net/publications/transient_sytematization.pdf) (Claudio Canella, Jo Van Bulck, Michael Schwarz, Moritz Lipp, Benjamin von Berg, Philipp Ortner, Frank Piessens, Dmitry Evtyushkin, Daniel Gruss, 2019)
* [RAMBleed: Reading Bits in Memory Without Accessing Them](https://rambleed.com/docs/20190603-rambleed-web.pdf) (Andrew Kwong, Daniel Genkin, Daniel Gruss, Yuval Yarom, 2019) — [google/rowhammer-test](https://github.com/google/rowhammer-test)
* [Micro architecture attacks on KASLR](https://cyber.wtf/2016/10/25/micro-architecture-attacks-on-kasrl/) (Anders Fogh, 2016)

## Syscall and interface leaks

The syscall boundary is the primary channel through which kernel data reaches
userspace, making it a structurally significant source of KASLR bypass
primitives. Several fundamental properties drive this attack surface:

**Uninitialized bytes in copy-to-user paths.** Every syscall that writes
structured data to a user buffer — output parameters, queried state, socket
message payloads, event records, notification packets — is a potential
information channel. Bytes that are never explicitly written (alignment padding
between struct members, trailing bytes in under-filled allocations, fields
skipped on error paths) retain their stale kernel content and cross the trust
boundary as part of the copy. The kernel's ABI stability requirement compounds
this: struct layouts, including their padding holes, cannot be changed without
breaking existing userspace, so a hole that exists in one release persists
indefinitely. The ioctl interface is a concentrated instance of this pattern
(see [ioctl leaks](#ioctl-leaks)), but it applies across all copy-to-user
paths.

**Kernel-pointer-derived values exposed by design.** Many interfaces predate
KASLR or were not designed with pointer exposure in mind and legitimately return
values derived from kernel virtual addresses — event handles, timer IDs, object
references, perf sample instruction pointers. The kernel address is never
directly returned, but the value is a deterministic function of it. Whether
this constitutes a leak depends entirely on the access controls applied —
removing access control, or finding a bypass, converts a by-design interface
into a KASLR oracle.

**Access controls applied at the wrong abstraction level.** A check that guards
a kernel address from unprivileged access is only as strong as the assumption
that the check and the data transfer happen in the same privilege context. When
`kptr_restrict` is enforced at `read()` rather than `open()`, a privileged
process can satisfy the `open()` and hand the descriptor to an unprivileged
reader. When a syscall applies access controls to the calling process's
credentials but not to an intermediate privileged agent acting on its behalf,
the check is bypassed without being subverted.

**Privilege delegation via set-uid executables.** The Unix set-uid mechanism
exists to let unprivileged processes perform specific privileged operations as
a side-effect of legitimate functionality. When that functionality involves
reading a restricted kernel interface, the unprivileged caller can observe the
elevated-privilege result. This is not a vulnerability in the set-uid binary
— it is working as designed — but the composition of set-uid execution with
a `kptr_restrict`-bypass-able interface produces an effective leak primitive.

**Hypervisor and emulator transparency failures.** A virtualization layer that
emulates kernel instructions or system calls must faithfully replicate guest
kernel behavior without exposing host kernel state to guest user processes.
Bugs in the emulation of privilege-transitioning instructions — instructions
that change the CPU privilege level or access a different address space — can
cause the emulator to operate on host kernel memory while the guest believes
it is in user space. The leak is not a kernel vulnerability; the kernel is
never involved. The attack surface exists entirely within the emulation layer.

The following KASLD components exploit syscall and interface leaks:

* [perf_event_open.c](../src/components/perf_event_open.c) — samples kernel instruction pointer addresses via `perf_event_open()` (requires `kernel.perf_event_paranoid < 2`)
* [mincore.c](../src/components/mincore.c) — `mincore()` heap page disclosure via uninitialized memory (CVE-2017-16994; patched in v4.15)
* [bcm_msg_head_struct.c](../src/components/bcm_msg_head_struct.c) — CAN BCM `bcm_msg_head` struct uninitialized 4-byte padding hole leaks kernel stack pointer via `recvmsg()` (CVE-2021-34693; patched in v5.12)
* [pppd_kallsyms.c](../src/components/pppd_kallsyms.c) — set-uid-root `pppd` opens `/proc/kallsyms` as root, bypassing the `kptr_restrict` open-time check in pre-v4.8 kernels
* [qemu_tcg_iret.c](../src/components/qemu_tcg_iret.c) — QEMU TCG `iret` emulation bug causes the hypervisor to read from the host kernel stack instead of the guest user stack, leaking a kernel address (patched in QEMU 9.1; not a kernel bug)

## ioctl leaks

`ioctl(2)` is a catch-all syscall that dispatches through `file_operations.unlocked_ioctl`
into subsystem-specific handlers spread across drivers, filesystems, networking,
and IPC. The handler receives a request code (encoding direction, type, number,
and argument size via `_IO`/`_IOR`/`_IOW`/`_IOWR`) and a pointer to a userspace
buffer. The response path — copying data back to userspace — has historically
been a prolific source of kernel info leaks.

Four distinct mechanisms account for most ioctl info leaks:

**Struct padding holes.** C compiler-inserted alignment padding between struct
members is never initialized by assignment or by individual `put_user()` writes.
When the kernel copies a struct wholesale to userspace with `copy_to_user()`,
the padding bytes contain stale stack or heap data. This is the most common
class, covered by CERT C rule DCL39-C. Kernel-wide tools like KMSAN catch new
instances; many historical examples were fixed by inserting explicit `memset()`
before population, or by restructuring the struct to eliminate holes.

**Uninitialized buffer copies.** The handler allocates a buffer with `kmalloc()`,
`__get_free_pages()`, or a stack array, fills only part of it (e.g. because the
actual payload is smaller than the allocation, or because the write callback
leaves a trailing region untouched), then copies the full allocation to userspace.
The unfilled bytes contain stale slab or page allocator data, which frequently
holds kernel pointers from previously freed objects. The nilfs2
`nilfs_ioctl_wrap_copy()` path is a canonical example.

**Stack variable leaks.** The handler declares a struct or scalar on the stack
and passes it to a helper that may return early without initializing all fields
(e.g. on an unsupported index or error branch). The handler then copies the
partially-initialized stack variable back to userspace. KVM `do_get_msr_feature()`
is a canonical example: the `msr.data` field on the stack was never zeroed
before the early return on an unrecognized MSR index.

**Unsanitized kernel pointer values.** Some ioctl commands intentionally return
values derived from kernel virtual addresses — object handles, DMA buffer
identifiers, timer IDs — without applying `kptr_restrict`-equivalent masking.
These are not uninitialized-memory bugs but deliberate design choices later
recognized as leaks.

The ioctl attack surface is wide because:

* Handlers are scattered across hundreds of drivers and subsystems, each with its
  own review history and padding discipline.
* Many ioctls are only exercised on specific hardware or mounted filesystems,
  reducing the chance that automated testing catches the leak.
* The `copy_to_user()` size argument is often computed from the ABI-fixed struct
  size, not from how much was actually written, making it structurally easy to
  under-fill.

The following KASLD components exploit ioctl info leaks:

* [nilfs2_ioctl.c](../src/components/nilfs2_ioctl.c) — `NILFS_IOCTL_GET_SUINFO` copies an uninitialized `__get_free_pages()` buffer; trailing page bytes contain stale kernel data (v2.6.30–v6.3)

See also:

* [DCL39-C. Avoid information leakage when passing a structure across a trust boundary](https://wiki.sei.cmu.edu/confluence/display/c/DCL39-C.+Avoid+information+leakage+when+passing+a+structure+across+a+trust+boundary)
* [Exploiting Uses of Uninitialized Stack Variables in Linux Kernels to Leak Kernel Pointers](https://sefcom.asu.edu/publications/leak-kptr-woot20.pdf) (Haehyun Cho et al., 2020)

## Brute force

Some memory layout properties can be determined by probing the address
space directly, without reading any files or exploiting vulnerabilities.

The following KASLD components use brute-force probing:

* [mmap_brute_vmsplit.c](../src/components/mmap_brute_vmsplit.c) — determines `PAGE_OFFSET` (vmsplit) on 32-bit systems by mapping pages across the address space until failure

## Weak entropy

The kernel is loaded at an aligned memory address, usually between `PAGE_SIZE`
(4 KiB) and 2 MiB on modern systems (see `IMAGE_ALIGN` definitions in
[kasld/api.h](../src/include/kasld/api.h)).

This limits the number of possible kernel locations to the values in the
[KASLR slots table](kaslr.md#default-text-base-and-kaslr-alignment) above.

The slot counts in that table are upper bounds. The kernel's KASLR placement code
enforces `slot + kernel_size ≤ range_end`, so positions near the top of the
randomization region where the image would overflow are never selected. Every
additional `IMAGE_ALIGN` bytes of kernel image size removes one trailing slot.
On architectures with tight entropy budgets — x86_64 and x86_32 (~500 slots,
~9 bits) and RISC-V64 (~512 slots) — a typical production kernel reduces the
effective slot count by 3–8%. On arm64 (~33M slots) and s390 (~131K slots) the
reduction is negligible.

Weaknesses in randomization can decrease entropy, further limiting the possible kernel
locations in memory and making the kernel easier to locate.

### Randomization failure at boot

Beyond the slot-count ceiling, KASLR can fail to apply *any* random
offset at boot. The kernel emits a `KASLR disabled` dmesg line but
continues to relocate the image to a firmware- or boot-stub-determined
position — *not* the link-time default. The result is 0 bits of KASLR
slot entropy, with the kernel landing at the same address on every
boot of the same (firmware, kernel build, hardware) tuple. Known
trigger conditions:

| Arch | Trigger | dmesg line |
|---|---|---|
| arm64 | EFI stub finds no `EFI_RNG_PROTOCOL` and no FDT `/chosen/kaslr-seed` (`kaslr_get_seed()` returns 0) | `KASLR disabled due to lack of seed` |
| arm64 | FDT remap failure during early KASLR init | `KASLR disabled due to FDT remapping failure` |
| s390 | CPU lacks the PRNG (`prng_seed()` failure) | `KASLR disabled: CPU has no PRNG` |
| s390 | Boot stub cannot allocate enough memory to apply the random offset | `KASLR disabled: not enough memory` |
| riscv64 EFI | No `EFI_RNG_PROTOCOL` (same shape as arm64) | — (not always emitted) |

This state is materially different from a deliberate opt-out
(`nokaslr` / `CONFIG_RANDOMIZE_BASE=n` / hibernation resume):
- Opt-out → kernel at `KERNEL_VIRT_TEXT_DEFAULT`. Predictable from the
  compile-time linker layout alone.
- Randomization failed → kernel at firmware-determined position.
  Predictable per-host (re-use a previously captured slide), but
  not from compile-time information.

KASLD emits a distinct scalar fact for each. The
`dmesg_kaslr_disabled` component classifies each `KASLR disabled` line
by its reason and emits `SF_VIRT_KASLR_DISABLED` +
`SF_PHYS_KASLR_DISABLED` (opt-out — both axes off) or
`SF_VIRT_KASLR_RANDOMIZATION_FAILED` + `SF_PHYS_KASLR_RANDOMIZATION_FAILED` (machinery failed). Only the former
pair drives the engine's `virt_kaslr_disabled_pin` and
`phys_kaslr_disabled_pin` rules. See
[docs/kaslr.md — KASLR runtime states](kaslr.md#kaslr-runtime-states)
for the full state taxonomy.

### Slide baseline

The renderer reports `KERNEL_VIRT_TEXT_DEFAULT` (the per-arch compile-time
default kernel text base) as the slide baseline, sourced from
`layout.kernel_text_default`. When KASLR is disabled (opt-out), this
is the kernel's actual load address on arches that set
`KASLR_DISABLED_PINS_VIRT_TEXT`; on relocating arches the bootloader may
still place the image elsewhere, and the rule's window-containment
check catches that case. When KASLR randomization failed, the kernel
is NOT at `KERNEL_VIRT_TEXT_DEFAULT` — the engine resolves the actual
position from observable evidence rather than pinning to default.

See also:

* [Linux KASLR Entropy](https://u1f383.github.io/linux/2025/01/02/linux-kaslr-entropy.html) (u1f383, 2025) — code-level walkthrough of x86_64 ktext slot calculation (`find_random_virt_addr`) and kheap randomization (`kernel_randomize_memory`)
* [Another look at two Linux KASLR patches](https://www.kryptoslogic.com/blog/2020/03/another-look-at-two-linux-kaslr-patches/index.html) (Kryptos Logic, 2020)
* [arm64: efi: kaslr: Fix occasional random alloc (and boot) failure](https://github.com/torvalds/linux/commit/4152433c397697acc4b02c4a10d17d5859c2730d)
* [Defeating KASLR by Doing Nothing at All](https://projectzero.google/2025/11/defeating-kaslr-by-doing-nothing-at-all.html) (Seth Jenkins, 2025) - arm64 linear map is not randomized due to memory hotplug support; Pixel bootloader loads kernel at static physical address, making kernel virtual addresses fully predictable even with KASLR enabled.

## Patched kernel bugs

There have been many kernel bugs which leaked kernel addresses to unprivileged
users via uninitialized memory, missing pointer sanitization, using kernel
pointers as a basis for "random" strings in userland, and many other weird and
wonderful flaws. These bugs are regularly discovered and patched.

Patched kernel info leak bugs:

  * [https://github.com/torvalds/linux/search?p=1&type=Commits&q=kernel-infoleak](https://github.com/torvalds/linux/search?p=1&type=Commits&q=kernel-infoleak)
  * `git clone https://github.com/torvalds/linux && cd linux && git log | grep 'kernel-infoleak'`

Patched kernel info leak bugs caught by KernelMemorySanitizer (KMSAN):

  * [https://github.com/torvalds/linux/search?p=1&type=Commits&q=BUG: KMSAN: kernel-infoleak](https://github.com/torvalds/linux/search?p=1&type=Commits&q=BUG:%20KMSAN:%20kernel-infoleak)
  * `git clone https://github.com/torvalds/linux && cd linux && git log | grep "BUG: KMSAN: kernel-infoleak"`

Netfilter info leak (CVE-2022-1972):

  * [Yet another bug into Netfilter](https://www.randorisec.fr/yet-another-bug-netfilter/)
    * https://github.com/randorisec/CVE-2022-1972-infoleak-PoC

Remote uninitialized stack variables leaked via Bluetooth:

  * [BadChoice: Stack-Based Information Leak (BleedingTooth)](https://github.com/google/security-research/security/advisories/GHSA-7mh3-gq28-gfrq) (CVE-2020-12352)
  * [Linux Kernel: Infoleak in Bluetooth L2CAP Handling](https://seclists.org/oss-sec/2022/q4/188) (CVE-2022-42895)
  * [Info Leak in the Linux Kernel via Bluetooth](https://seclists.org/oss-sec/2017/q4/357) (CVE-2017-1000410)

Remote kernel pointer leak via IP packet headers (CVE-2019-10639):

  * [From IP ID to Device ID and KASLR Bypass](https://arxiv.org/pdf/1906.10478.pdf)

floppy block driver `show_floppy` kernel function pointer leak (CVE-2018-7273) (requires `floppy` driver and access to `dmesg`).

  * [Linux Kernel < 4.15.4 - 'show_floppy' KASLR Address Leak](https://www.exploit-db.com/exploits/44325) (Gregory Draperi. 2018)
  * https://xorl.wordpress.com/2018/03/18/cve-2018-7273-linux-kernel-floppy-information-leak/

`kernel_waitid` leak (CVE-2017-14954) (affects kernels 4.13-rc1 to 4.13.4):

  * [wait_for_kaslr_to_be_effective.c](https://grsecurity.net/~spender/exploits/wait_for_kaslr_to_be_effective.c) (spender, 2017)
  * https://github.com/salls/kernel-exploits/blob/master/CVE-2017-5123/exploit_no_smap.c (salls, 2017)

`snd_timer_user_read` uninitialized kernel heap memory disclosure (CVE-2017-1000380):

  * [Linux kernel 2.6.0 to 4.12-rc4 infoleak due to a data race in ALSA timer](https://seclists.org/oss-sec/2017/q2/455) (Alexander Potapenko, 2017)
    * [snd_timer_c.bin](https://seclists.org/oss-sec/2017/q2/att-529/snd_timer_c.bin) (Alexander Potapenko, 2017)

Uninitialized kernel heap memory in ELF core dumps (CVE-2020-10732). `fill_thread_core_info()` in `fs/binfmt_elf.c` allocated regset data buffers with `kmalloc()`, which were not fully initialized by regset `get()` callbacks. Several kilobytes of stale kernel heap data (potentially containing kernel pointers) could be written to the core file and read by an unprivileged user. Trivially exploitable by crashing any program:

  * [google/kmsan#76: Uninitialized memory in ELF core dump](https://github.com/google/kmsan/issues/76)
  * [Bug 1831399 - CVE-2020-10732 kernel: uninitialized kernel data leak in userspace coredumps](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-10732)
  * [fs/binfmt_elf.c: allocate initialized memory in fill_thread_core_info()](https://github.com/ruscur/linux/commit/a95cdec9fa0c08e6eeb410d461c03af8fd1fef0a) (Alexander Potapenko, 2020)

Uninitialized x86 FPU/xstate data in core dumps. `copy_xstate_to_kernel()` only copied enabled xstate features, leaving gaps between features uninitialized. Stale kernel memory was leaked through the `NT_X86_XSTATE` ELF core dump note:

  * [copy_xstate_to_kernel(): don't leave parts of destination uninitialized](https://github.com/torvalds/linux/commit/9e4636545933131de15e1ecd06733538ae939b2f) (Al Viro, 2020)

RISC-V kernel `gp` register leaked to userland (CVE-2024-35871) (affects kernels 4.15 to 6.8.5). The kernel `__global_pointer$` was exposed via `childregs->gp` in user_mode_helper threads (PID 1, `core_pattern` pipe handlers, etc), observable through `kernel_execve` register state, `ptrace(PTRACE_GETREGSET)`, and `PERF_SAMPLE_REGS_USER`:

  * [riscv: process: Fix kernel gp leakage](https://git.kernel.org/stable/c/d14fa1fcf69db9d070e75f1c4425211fa619dfc8)

PPTP sockets `pptp_bind()` / `pptp_connect()` kernel stack leak (CVE-2015-8569):
  * https://lkml.org/lkml/2015/12/14/252

Exploiting uninitialized stack variables:

  * [Structure holes and information leaks](https://lwn.net/Articles/417989/) (Jonathan Corbet. 2010)
  * [C Structure Padding Initialization](https://interrupt.memfault.com/blog/c-struct-padding-initialization) (Noah Pendleton. 2022)
  * [DCL39-C. Avoid information leakage when passing a structure across a trust boundary - SEI CERT C Coding Standard](https://wiki.sei.cmu.edu/confluence/display/c/DCL39-C.+Avoid+information+leakage+when+passing+a+structure+across+a+trust+boundary)
  * [Exploiting Uses of Uninitialized Stack Variables in Linux Kernels to Leak Kernel Pointers](https://sefcom.asu.edu/publications/leak-kptr-woot20.pdf) (Haehyun Cho, Jinbum Park, Joonwon Kang, Tiffany Bao, Ruoyu Wang, Yan Shoshitaishvili, Adam Doupé, Gail-Joon Ahn. 2020)
    * [Leak kernel pointer by exploiting uninitialized uses in Linux kernel](https://jinb-park.github.io/leak-kptr.html)
    * [jinb-park/leak-kptr](https://github.com/jinb-park/leak-kptr)
    * [compat_get_timex kernel stack pointer leak](https://github.com/jinb-park/leak-kptr/blob/master/exploit/CVE-2018-11508/poc.c) (CVE-2018-11508).
    * [sctp_af_inet kernel pointer leak](https://github.com/jinb-park/leak-kptr/tree/master/exploit/sctp-leak) (CVE-2017-7558) (requires `libsctp-dev`).
    * [rtnl_fill_link_ifmap kernel stack pointer leak](https://github.com/jinb-park/leak-kptr/tree/master/exploit/CVE-2016-4486) (CVE-2016-4486).
    * [snd_timer_user_params kernel stack pointer leak](https://github.com/jinb-park/leak-kptr/tree/master/exploit/CVE-2016-4569) (CVE-2016-4569).

VT console font uninitialized heap leak. `con_font_get()` in `drivers/tty/vt/vt.c` allocated a font data buffer with `kmalloc()` and copied it to userspace without fully initializing it when the font width is not byte-aligned. Stale slab data could be read by any user with access to a virtual terminal (tty group). Affects v6.3 to v6.12:

  * [drivers: tty: vt: Fix a font data leak](https://github.com/torvalds/linux/commit/f956052e00de14f22e4b01766c7f2780a7e4a737) (2024)

AMD IBS (Instruction-Based Sampling) uninitialized perf stack leak. `perf_ibs_handle_irq()` in `arch/x86/events/amd/ibs.c` did not fully initialize the `struct perf_ibs_data` on-stack buffer before copying it to the perf ring buffer. On AMD CPUs with IBS support, stale kernel stack data (potentially containing kernel pointers) leaked to unprivileged perf readers. Affects v6.13 to v6.15 (AMD CPUs only):

  * [perf/x86/amd/ibs: Fix stack uninit access](https://github.com/torvalds/linux/commit/50a53b60e141b36e316dd1d1f5a4231486c8dc2d) (2025)

memfd hugetlb non-zeroed folio leak. `memfd_alloc_folio()` in `mm/memfd.c` allocated hugetlb pool folios for memfds without zeroing, bypassing the page-fault path's normal `folio_zero_user()` call. Folios allocated via `memfd_pin_folios()` (currently only invoked by the `udmabuf` driver's `UDMABUF_CREATE` / `UDMABUF_CREATE_LIST` ioctls) retained whatever the prior hugetlb pool occupant left on them — up to 2 MiB of stale kernel or user data per folio, readable by any process holding the memfd via `mmap()` or `read()`. Requires `vm.nr_hugepages > 0` (root sysctl, common on KVM hosts and DPDK / SPDK servers) and `/dev/udmabuf` RW access (default mode 0600; widened by some compositor / video udev rules). Affects v6.11 to v6.18:

  * [mm/memfd: fix information leak in hugetlb folios](https://github.com/torvalds/linux/commit/de8798965fd0d9a6c47fc2ac57767ec32de12b49) (2025)

## Arbitrary read

Kernel vulnerabilities which provide arbitrary read (or write) primitives can
be leveraged to leak kernel pointers and defeat KASLR, even when direct info
leak vectors are unavailable.

Leaking kernel addresses using `msg_msg` struct for arbitrary read (for `KMALLOC_CGROUP` objects):

  * [Four Bytes of Power: Exploiting CVE-2021-26708 in the Linux kernel | Alexander Popov](https://a13xp0p0v.github.io/2021/02/09/CVE-2021-26708.html)
  * [CVE-2021-22555: Turning \x00\x00 into 10000$ | security-research](https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html)
  * [Exploiting CVE-2021-43267 - Haxxin](https://haxx.in/posts/pwning-tipc/)
  * [Will's Root: pbctf 2021 Nightclub Writeup: More Fun with Linux Kernel Heap Notes!](https://www.willsroot.io/2021/10/pbctf-2021-nightclub-writeup-more-fun.html)
  * [Will's Root: corCTF 2021 Fire of Salvation Writeup: Utilizing msg_msg Objects for Arbitrary Read and Arbitrary Write in the Linux Kernel](https://www.willsroot.io/2021/08/corctf-2021-fire-of-salvation-writeup.html)
  * [[corCTF 2021] Wall Of Perdition: Utilizing msg_msg Objects For Arbitrary Read And Arbitrary Write In The Linux Kernel](https://syst3mfailure.io/wall-of-perdition)
  * [[CVE-2021-42008] Exploiting A 16-Year-Old Vulnerability In The Linux 6pack Driver](https://syst3mfailure.io/sixpack-slab-out-of-bounds)

Leaking kernel addresses using privileged arbitrary read (or write) in kernel space:

  * [kptr_restrict – Finding kernel symbols for shell code](https://ryiron.wordpress.com/2013/09/05/kptr_restrict-finding-kernel-symbols-for-shell-code/) (ryiron, 2013)
  * CVE-2017-18344: Exploiting an arbitrary-read vulnerability in the Linux kernel timer subsystem (xairy, 2017):
    * https://www.openwall.com/lists/oss-security/2018/08/09/6
    * https://xairy.io/articles/cve-2017-18344
    * [xairy/kernel-exploits/CVE-2017-18344](https://github.com/xairy/kernel-exploits/tree/master/CVE-2017-18344)
