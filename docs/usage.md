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

Running 83 components (10 experimental skipped; use -x to enable)...
[####################] 100%  83/83  5.3s

  Virtual image base  0xffffffff83800000   slide +0x2800000
  Physical image base not derandomized     ~9 bits
                      0x0000000001000000 - 0x000000003c20ca00   (473 x 2.0 MiB)
  Direct map base     >= 0xffff800000000000
  Phys/Virt Coupling  physical and virtual text randomize independently

Leaks (1):
  virt kernel text    0xffffffff83800000   (prefetch)

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
kernel.perf_event_paranoid:   2
Kernel lockdown:              (unavailable)

Readable /var/log/dmesg:      no
Readable /var/log/kern.log:   no
Readable /var/log/syslog:     no
Readable debugfs:             yes
Readable /boot/System.map:    no
Readable /boot/config:        no

--- boot_config ---
[-] could not find kernel config

--- boot_params_e820 ---
[.] reading E820 memory map and initrd address from /sys/kernel/boot_params/data ...
[.] E820 RAM: 0x0000000000000000 - 0x000000000009fbff
[.] E820 RAM: 0x0000000000100000 - 0x000000003ffdefff
[+] leaked E820 DRAM low:  0x0000000000100000
P ram pos=base conf=parsed lo=0x100000
[+] leaked E820 DRAM high: 0x000000003ffdefff
P ram pos=top conf=parsed hi=0x3ffdefff
[.] note: phys and virt KASLR are decoupled on this arch; cannot derive kernel text virtual address from physical leak
[+] leaked initrd physical start: 0x000000003eff3000
[+] leaked initrd physical end:   0x000000003ffcf651
P initrd pos=base conf=parsed lo=0x3eff3000 hi=0x3ffcf651

--- boot_params_facts ---
S init_size conf=parsed value=0x288d000
S phys_kernel_align conf=parsed value=0x200000

--- bootconfig_facts ---

--- btf_struct_page_size ---
[-] /sys/kernel/btf/vmlinux unavailable (no CONFIG_DEBUG_INFO_BTF?)

--- cmdline_hugepages ---
[-] no `hugepages=` on /proc/cmdline

--- cmdline_mem ---
[-] no `mem=` token on /proc/cmdline

--- cmdline_memmap ---
[-] no avoidance `memmap=` reservations on cmdline

--- cmdline_region ---
P cmdline pos=base conf=parsed lo=0x20000 hi=0x207fe

--- cpuinfo_facts ---
S phys_addr_bits conf=parsed value=0x2d

--- devicetree_facts ---

--- dmesg_acpi_dynamic_ssdt ---
[.] searching dmesg for ACPI dynamic OEM table loads ...
[-] no ACPI dynamic OEM table load with a direct-map virtual address found in dmesg

--- dmesg_android_ion_snapshot ---
[.] searching dmesg for 'ion_snapshot: ' ...
[-] ion_snapshot not found in dmesg

--- dmesg_backtrace ---
[.] searching dmesg for kernel oops information ...
[-] no kernel oops information found in dmesg

--- dmesg_check_for_initrd ---
[.] searching dmesg for check_for_initrd() info ...
[-] check_for_initrd info not found in dmesg

--- dmesg_cma_reserved ---
[.] searching dmesg for CMA/DMA reserved memory pools ...
[-] No CMA/DMA reserved memory pools found in dmesg

--- dmesg_crashkernel ---
[.] searching dmesg for crashkernel reservation ...
[-] crashkernel reservation not found in dmesg

--- dmesg_driver_component_ops ---
[.] searching dmesg for driver component ops pointers ...
[-] driver component ops pointers not found in dmesg

--- dmesg_e820_memory_map ---
[.] searching dmesg for e820 physical memory map ...
[+] leaked e820 DRAM low:  0x000000000009fc00
P ram pos=base conf=parsed lo=0x9fc00
[+] leaked e820 DRAM high: 0x000000003fffffff
P ram pos=top conf=parsed hi=0x3fffffff
[.] note: phys and virt KASLR are decoupled on this arch; cannot derive kernel text virtual address from physical leak

--- dmesg_early_init_dt_add_memory_arch ---
[.] [.] searching dmesg for early_init_dt_add_memory_arch() ignored memory ranges ...
[-] early_init_dt_add_memory_arch info not found in dmesg

--- dmesg_efi_memmap ---
[.] searching dmesg for EFI memory map (requires efi=debug) ...
[-] EFI memory map not found in dmesg
[.]     (requires efi=debug kernel boot parameter)

--- dmesg_ex_handler_msr ---
[.] searching dmesg for native_[read|write]_msr function pointer ...
[-] ex_handler_msr function pointer not found in dmesg

--- dmesg_fake_numa_init ---
[.] searching dmesg for fake_numa_init() info ...
[-] fake_numa_init info not found in dmesg

--- dmesg_free_area_init_node ---
[.] searching dmesg for mm_init physical memory info ...
[.] lowest physical address:  0x0000000000001000
P ram pos=interior conf=parsed sample=0x1000
[.] highest physical address: 0x000000003ffdefff
P ram pos=top conf=parsed hi=0x3ffdefff
[.] note: phys and virt KASLR are decoupled on this arch; cannot derive kernel text virtual address from physical leak

--- dmesg_free_reserved_area ---
[.] searching dmesg for free_reserved_area() info ...

--- dmesg_kaslr_disabled ---
[.] searching dmesg for 'KASLR disabled' or 'KASLR is disabled' ...
[.] searching dmesg for 'EFI_RNG_PROTOCOL unavailable' ...
[-] KASLR disabled indicator not found in dmesg

--- dmesg_last_pfn ---
[.] searching dmesg for last_pfn ...
[+] leaked last_pfn: 0x3ffdf (last valid byte: 0x000000003ffdefff)
P ram pos=top conf=parsed hi=0x3ffdefff

--- dmesg_mem_init_kernel_layout ---
[.] searching dmesg for kernel memory layout sections ...
[-] kernel memory layout sections not found in dmesg

--- dmesg_mmu_idmap ---
[.] searching dmesg for ' static identity map for ' ...
[-] MMU identity map info not found in dmesg

--- dmesg_node_data ---
[.] searching dmesg for NODE_DATA allocations ...
[.] lowest NODE_DATA physical address:  0x000000003ffdb800
[.] highest NODE_DATA physical address: 0x000000003ffdefff
P numa_node pos=interior conf=parsed sample=0x3ffdefff
[.] note: phys and virt KASLR are decoupled on this arch; cannot derive kernel text virtual address from physical leak

--- dmesg_ramdisk ---
[.] searching dmesg for RAMDISK physical addresses ...
[+] leaked RAMDISK physical address: 0x000000003eff3000
P initrd pos=interior conf=parsed sample=0x3eff3000

--- dmesg_reserved_mem ---
[.] searching dmesg for device tree reserved memory regions ...
[-] no device tree reserved memory regions found in dmesg

--- dmesg_swiotlb ---
[.] searching dmesg for SWIOTLB bounce buffer info ...
[-] SWIOTLB not found in dmesg (may not be enabled)

--- efi_present ---
S efi_present conf=parsed value=0x0

--- fdt_facts ---

--- firmware_memmap ---
P ram pos=extent conf=parsed lo=0x100000 hi=0x3ffdefff
P ram pos=extent conf=parsed lo=0x0 hi=0x9fbff

--- function_order_fingerprint ---
[.] function order: kernel/sys.c span 0.1% below 30% threshold; abstaining (not a canonical-order assertion)

--- hibernation_nokaslr ---

--- ioctl_mmio_phys ---
[.] querying framebuffer / serial ioctls for physical MMIO bases ...
[-] no MMIO bases from fb/serial ioctls (no accessible device, or port-I/O only)

--- kernel_image_facts ---
S image_size conf=parsed value=0x2de6600

--- kernel_notes_buildid ---
[.] reading /sys/kernel/notes ...
[.] kernel.lto: 0
[.] kernel.build_salt: ""
[.] kernel.build_id: 4b471aa7689b36a0c9ad6d7fff278fdc2dd94dcb

--- meminfo_facts ---
S phys_memtotal conf=parsed value=0x3cb40000
S phys_max_pfn conf=parsed value=0x3ffdf

--- page_size ---
S page_size conf=parsed value=0x1000

--- perf_event_open ---
[.] trying perf_event_open sampling ...
[-] perf_event_open: Permission denied
[-] no kernel address found via perf_event_open

--- perf_ksymbol_leak ---
[-] perf_event_open EACCES — perf_event_paranoid > 0

--- perf_lbr_sampling ---
[.] trying perf LBR sampling on a busy-syscall child ...
[-] perf_event_open EACCES — needs perf_event_paranoid<=1 or CAP_PERFMON

--- proc_cmdline ---
[.] trying /proc/cmdline ...
[-] Kernel was not booted with nokaslr flag.

--- proc_config ---
[.] checking /proc/config.gz ...
[-] Could not read /proc/config.gz

--- proc_cpuinfo ---
[.] checking /proc/cpuinfo ...
[.] Address sizes: 45 bits physical, 48 bits virtual
[.] Paging level 4: PAGE_OFFSET floor -> 0xffff800000000000
V virt_page_offset pos=base conf=parsed lo=0xffff800000000000

--- proc_iomem_kernel ---
[-] /proc/iomem appears masked (kptr_restrict?); addresses read as 0

--- proc_kallsyms ---

--- proc_modules ---
[.] reading /proc/modules ...
[-] no kernel address found in /proc/modules

--- proc_net_sock_ptr ---
[.] scanning /proc/net/unix for direct-map sock pointers ...
[.] scanning /proc/net/netlink for direct-map sock pointers ...
[-] no real sock pointers in /proc/net/* (pointers hashed, or kptr_restrict denies the value)

--- proc_stat_wchan ---
[.] checking /proc/159/stat 'wchan' field ...
[-] no kernel address found in /proc/pid/stat wchan

--- proc_timer_list ---
[.] scanning /proc/timer_list for timer base addresses ...
[-] fopen: Permission denied

--- proc_zoneinfo ---
[.] searching /proc/zoneinfo for zone start_pfn and spanned ...
[.] lowest zone start PFN:  1 (phys 0x0000000000001000)
P ram pos=interior conf=parsed sample=0x1000
[.] highest zone end PFN:   262111 (phys 0x000000003ffdefff)
P ram pos=top conf=parsed hi=0x3ffdefff
[.] note: phys and virt KASLR are decoupled on this arch; cannot derive directmap virtual address from physical leak

--- qemu_tcg_iret ---
[.] trying QEMU TCG iret leak ...
[-] QEMU TCG IRET fault not triggered

--- sidt ---
[.] trying SIDT leak ...
[.] IDT base:  0xffffffffffff0000
[.] IDT limit: 0x0000 (1 bytes, 0 entries)
[-] UMIP active — kernel returned dummy IDT value, no leak

--- sysfs_devicetree_initrd ---
[-] device tree chosen node not found or no initrd properties

--- sysfs_devicetree_kernel_end ---
[-] linux,kernel-end not present (non-PowerPC platform or no DT)

--- sysfs_devicetree_memory ---
[-] device tree not available (not a DT platform?)

--- sysfs_devicetree_memory_limit ---
[-] linux,memory-limit not present (non-PowerPC platform or no DT)

--- sysfs_devicetree_reserved_memory ---
[-] device tree not available (not a DT platform?)

--- sysfs_devicetree_uefi_mmap ---
[-] device tree chosen node not found or no linux,uefi-mmap-start property

--- sysfs_firmware_memmap ---
[.] searching /sys/firmware/memmap for System RAM entries ...
[.] firmware memmap: 1 System RAM entries
[.] lowest System RAM start:  0x0000000000100000
P ram pos=base conf=parsed lo=0x100000
[.] highest System RAM end:   0x000000003ffdefff
P ram pos=top conf=parsed hi=0x3ffdefff
[.] note: phys and virt KASLR are decoupled on this arch; cannot derive directmap virtual address from physical leak

--- sysfs_iscsi_transport_handle ---
[-] Failed to get a NETLINK_ISCSI socket: Protocol not supported
[.] checking /sys/class/iscsi_transport/tcp/handle ...
[-] fopen: No such file or directory

--- sysfs_kernel_notes_xen ---
[.] checking /sys/kernel/notes ...
[-] no kernel addresses found in ELF notes

--- sysfs_memory_blocks ---
[.] searching /sys/devices/system/memory for memory block info ...
[-] cannot read block_size_bytes: No such file or directory

--- sysfs_module_sections ---
[.] trying /sys/modules/*/sections/.text ...
[-] no kernel address found in /sys/module sections

--- sysfs_nd_region ---
[.] trying /sys/bus/nd/devices/ndregionN/resource ...
[-] /sys/bus/nd/devices not present (CONFIG_LIBNVDIMM=n or no nd bus)

--- sysfs_nf_conntrack ---
[.] trying /sys/kernel/slab/nf_contrack_* ...
[-] no kernel address found in sysfs nf_conntrack

--- sysfs_pci_resource ---
[.] searching /sys/bus/pci/devices for PCI device MMIO BAR addresses ...
[.] PCI devices: 6, memory BARs: 8
[.] lowest PCI MMIO start:  0x00000000000c0000
P pci_mmio pos=interior conf=parsed sample=0xc0000
[.] highest PCI MMIO end:   0x00000000febd5fff
P pci_mmio pos=interior conf=parsed sample=0xfebd5fff

--- sysfs_uio_map ---
[.] searching /sys/class/uio for UIO device map addresses ...

--- sysfs_vmcoreinfo ---
[.] trying /sys/kernel/vmcoreinfo ...
[.] vmcoreinfo_note physical address: 0x00000000011ee000
P vmcoreinfo pos=interior conf=parsed sample=0x11ee000
[.] note: phys and virt KASLR are decoupled on this arch; cannot derive directmap virtual address from physical leak

--- bcm_msg_head_struct ---
[.] trying bcm_msg_head struct stack pointer leak ...
[-] no kernel address leaked via BCM socket

--- databounce ---
[-] databounce: not an Intel CPU; attack not applicable

--- entrybleed ---
[.] trying EntryBleed (CVE-2022-4543) ...
[.] AMD CPU with KPTI disabled
[-] kernel version '6.15.6 #1 SMP PREEMPT_DYNAMIC Wed Jun 17 13:04:17 EDT 2026' not recognized
[-] EntryBleed (CVE-2022-4543) not exploitable

--- mincore ---
[.] trying mincore info leak...
[-] timeout after 28672 iterations (5s); likely patched
[-] kernel base not found in mincore info leak

--- mmap_arm64_va_bits ---

--- mmap_brute_vmsplit ---
[.] searching 32-bit address space for kernel virtual address space start ...
[-] Could not locate kernel virtual address space

--- mmap_riscv64_va_bits ---

--- nilfs2_ioctl ---
[.] trying nilfs2 NILFS_IOCTL_GET_SUINFO heap leak ...
[-] no nilfs2 mount found

--- prefetch ---
[.] trying prefetch side-channel ...
[.] AMD CPU detected
[.] KPTI is not detected
[.] possible kernel base: ffffffff83800000
V kernel_text pos=base conf=timing lo=0xffffffff83800000

[engine] virt_image_base: constrained by 3 independent sources: ceiling_from_image_size physical_start_lower_bound text_pin_from_observation
[engine] phys_image_base: constrained by 9 independent sources: ceiling_from_image_size phys_ceiling_from_memtotal phys_bits_ceiling phys_hole_filter initrd_phys_exclude ram_map_phys_exclude initrd_above_kernel cmdline_phys_exclude physical_start_lower_bound
[engine] virt_kaslr_align: constrained by 2 independent sources: kaslr_align_arch_default boot_params_kaslr_align
[engine] phys_kaslr_align: constrained by 2 independent sources: kaslr_align_arch_default boot_params_kaslr_align
Components: 83 total, 20 succeeded, 14 unavailable, 4 access denied, 45 no result

========================================
 Results
========================================

Kernel text (virtual) / kernel_text [1]:
  0xffffffff83800000  kernel_text (prefetch, timing)
  ==> 0xffffffff83800000  (timing, 1 source)

----------------------------------------
Physical DRAM / ram [4]:
  0x0000000000000000  ram (firmware_memmap, parsed)
  0x0000000000001000  ram (dmesg_free_area_init_node, proc_zoneinfo, parsed)
  0x0000000000100000  ram (firmware_memmap, parsed)
  0x0000000000100000  ram (boot_params_e820, dmesg_e820_memory_map, dmesg_free_area_init_node, dmesg_last_pfn, proc_zoneinfo, sysfs_firmware_memmap, parsed)
  ==> 0x0000000000100000  (parsed, 2 sources, 2 conflicts)
      range: 0x0000000000000000 - 0x0000000000100000  (1.0 MiB)

----------------------------------------
Physical DRAM / initrd [1]:
  0x000000003eff3000  initrd (boot_params_e820, dmesg_ramdisk, parsed)
  ==> 0x000000003eff3000  (parsed, 1 source)

----------------------------------------
Physical DRAM / cmdline [1]:
  0x0000000000020000  cmdline (cmdline_region, parsed)
  ==> 0x0000000000020000  (parsed, 1 source)

----------------------------------------
Physical DRAM / numa_node [1]:
  0x000000003ffdefff  numa_node (dmesg_node_data, parsed)
  ==> 0x000000003ffdefff  (parsed, 1 source)

----------------------------------------
Physical DRAM / vmcoreinfo [1]:
  0x00000000011ee000  vmcoreinfo (sysfs_vmcoreinfo, parsed)
  ==> 0x00000000011ee000  (parsed, 1 source)

----------------------------------------
Physical MMIO / pci_mmio [2]:
  0x00000000000c0000  pci_mmio (sysfs_pci_resource, parsed)
  0x00000000febd5fff  pci_mmio (sysfs_pci_resource, parsed)
  ==> 0x00000000000c0000  (parsed, 1 source, 1 conflict)
      range: 0x00000000000c0000 - 0x00000000febd5fff  (4.0 GiB)

----------------------------------------
KASLR analysis:
  Virtual image base:   0xffffffff83800000
  Default image base:   0xffffffff81000000
  KASLR slide:          +0x2800000 (41943040)
  KASLR text entropy:   0 bits (pinned)

  Inferred phys text range:  0x0000000001000000 - 0x000000003c20ca00
  Remaining phys slots:      473 (9 bits, step 0x200000)

Memory KASLR (directmap / vmalloc / vmemmap):
  virt_page_offset_base >= 0xffff800000000000
  virt_vmalloc_base    0xffff8b0040000000 - 0xffffdcffc0000000  (83966 candidates, 17 bits)
  virt_vmemmap_base    0xffffab0080000000 - 0xfffffd0000000000  (83966 candidates, 17 bits)

----------------------------------------
Virtual memory layout (decoupled):

  0xffffffffffffffff
      modules (no leak)
  0xffffffffc0000000
      . . .  968.0 MiB gap  . . .
  0xffffffff83800000
      kernel text (pinned) -- leak 0xffffffff83800000
  0xffffffff83800000
      . . .  128.0 TiB gap  . . .
  0xffff800000000000
      direct map (pinned)
  0xffff800000000000
      . . .  65408.0 TiB gap  . . .
  0xff00000000000000  (user space + non-canonical hole below)

Physical memory layout:

  0x000000003ffdefff
      above DRAM
        0x00000000febd5fff  [mmio] pci_mmio
  0x000000003ffdefff
      in DRAM
        0x000000003eff3000  [dram] initrd
  0x000000003c20ca00
      phys kernel text
        (no leak)
  0x0000000001000000
      in DRAM
        0x00000000000c0000  [mmio] pci_mmio
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
arch=x86_64 kaslr=on text=0xffffffff83800000 slide=+0x2800000(41943040) results=12
```

### JSON (`-j`)

`-j` (`--json`) emits the full structured summary. See
[docs/exploitation.md](exploitation.md) for a pwntools template that
consumes the JSON.

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
