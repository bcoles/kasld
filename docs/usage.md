# Usage

Each component in `src/components/` is a standalone leak component using
a different technique to retrieve or infer kernel addresses. The `kasld`
orchestrator discovers and executes all components, displays results in
real-time, and produces a section-aware summary with validated addresses
grouped by kernel section (text, modules, direct map, …).

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
KASLD 0.2.0  --  Kernel ASLR derandomisation
Target: x86_64 / 6.12.38+deb13-amd64

Running 77 components (10 experimental skipped; use -x to enable)...
[####################] 100%  77/77  10.5s

  Virtual text base   0xffffffffa7a00000   slide +0x26a00000
  Physical text base  not derandomized     ~9 bits
                      0x0000000001000000 - 0x000000002eedbce0   (367 x 2.0 MiB)
  Direct map base     >= 0xffff800000000000

  Coupling            virt and phys text are independent on this arch.
                      A phys leak does NOT reveal the virt text base.

Leaks (1):
  virt kernel text    0xffffffffa7a00000   (prefetch)

[-v: detailed results, memory map, system info]  [-H: hardening assessment]
```

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
    ▀                                   ▀ v0.2.0

Kernel release:               6.12.38+deb13-amd64
Kernel version:               #1 SMP PREEMPT_DYNAMIC Debian 6.12.38-1 (2025-07-16)
Kernel arch:                  x86_64

kernel.kptr_restrict:         0
kernel.dmesg_restrict:        1
kernel.panic_on_oops:         0
kernel.perf_event_paranoid:   3
Kernel lockdown:              none

Readable /var/log/dmesg:      no
Readable /var/log/kern.log:   no
Readable /var/log/syslog:     no
Readable debugfs:             no
Readable /boot/System.map:    yes
Readable /boot/config:        yes

--- boot_config ---
[.] checking for CONFIG_VMSPLIT_1G... 
[.] checking for CONFIG_VMSPLIT_2G... 
[.] checking for CONFIG_VMSPLIT_2G_OPT... 
[.] checking for CONFIG_VMSPLIT_3G... 
[.] checking for CONFIG_VMSPLIT_3G_OPT... 
[.] CONFIG_PHYSICAL_START: 0x1000000
S physical_start conf=parsed value=0x1000000
[.] CONFIG_PHYSICAL_ALIGN: 0x200000
S phys_kernel_align conf=parsed value=0x200000
[.] checking for CONFIG_RANDOMIZE_BASE... 

--- boot_params_facts ---
S init_size conf=parsed value=0x37ed000
S phys_kernel_align conf=parsed value=0x200000

--- boot_params_e820 ---
[.] reading E820 memory map and initrd address from /sys/kernel/boot_params/data ...
E820 RAM: 0x0000000000000000 - 0x000000000009e7ff
E820 RAM: 0x0000000000100000 - 0x000000007fedffff
E820 RAM: 0x000000007ff00000 - 0x000000007fffffff
leaked E820 DRAM low:  0x0000000000100000
P ram pos=base conf=parsed lo=0x100000
leaked E820 DRAM high: 0x000000007fffffff
P ram pos=top conf=parsed hi=0x7fffffff
note: phys and virt KASLR are decoupled on this arch; cannot derive kernel text virtual address from physical leak
leaked initrd physical start: 0x000000003173d000
leaked initrd physical end:   0x0000000034b95ea8
P initrd pos=base conf=parsed lo=0x3173d000 hi=0x34b95ea8

--- bootconfig_facts ---

--- cmdline_hugepages ---
[-] no `hugepages=` on /proc/cmdline

--- cmdline_mem ---
[-] no `mem=` token on /proc/cmdline

--- cmdline_memmap ---
[-] no avoidance `memmap=` reservations on cmdline

--- cmdline_region ---
P cmdline pos=base conf=parsed lo=0x8f000 hi=0x8f7fe

--- cpuinfo_facts ---
S phys_addr_bits conf=parsed value=0x2d

--- devicetree_facts ---

--- dmesg_acpi_dynamic_ssdt ---
[.] searching dmesg for ACPI dynamic OEM table loads ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted
[-] fopen(/var/log/dmesg): No such file or directory
[-] dmesg: access denied (klogctl and /var/log/dmesg both inaccessible)
[-] no ACPI dynamic OEM table load with a direct-map virtual address found in dmesg

--- dmesg_android_ion_snapshot ---
[.] searching dmesg for 'ion_snapshot: ' ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted
[-] fopen(/var/log/dmesg): No such file or directory
[-] dmesg: access denied (klogctl and /var/log/dmesg both inaccessible)

--- dmesg_backtrace ---
[.] searching dmesg for kernel oops information ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted
[-] fopen(/var/log/dmesg): No such file or directory
[-] dmesg: access denied (klogctl and /var/log/dmesg both inaccessible)

--- dmesg_check_for_initrd ---
[.] searching dmesg for check_for_initrd() info ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted
[-] fopen(/var/log/dmesg): No such file or directory
[-] dmesg: access denied (klogctl and /var/log/dmesg both inaccessible)

--- dmesg_cma_reserved ---
[.] searching dmesg for CMA/DMA reserved memory pools ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted
[-] fopen(/var/log/dmesg): No such file or directory
[-] dmesg: access denied (klogctl and /var/log/dmesg both inaccessible)

--- dmesg_crashkernel ---
[.] searching dmesg for crashkernel reservation ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted
[-] fopen(/var/log/dmesg): No such file or directory
[-] dmesg: access denied (klogctl and /var/log/dmesg both inaccessible)

--- dmesg_driver_component_ops ---
[.] searching dmesg for driver component ops pointers ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted
[-] fopen(/var/log/dmesg): No such file or directory
[-] dmesg: access denied (klogctl and /var/log/dmesg both inaccessible)

--- dmesg_e820_memory_map ---
[.] searching dmesg for e820 physical memory map ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted
[-] fopen(/var/log/dmesg): No such file or directory
[-] dmesg: access denied (klogctl and /var/log/dmesg both inaccessible)

--- dmesg_early_init_dt_add_memory_arch ---
[.] searching dmesg for early_init_dt_add_memory_arch() ignored memory ranges ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted
[-] fopen(/var/log/dmesg): No such file or directory
[-] dmesg: access denied (klogctl and /var/log/dmesg both inaccessible)

--- dmesg_efi_memmap ---
[.] searching dmesg for EFI memory map (requires efi=debug) ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted
[-] fopen(/var/log/dmesg): No such file or directory
[-] dmesg: access denied (klogctl and /var/log/dmesg both inaccessible)

--- dmesg_ex_handler_msr ---
[.] searching dmesg for native_[read|write]_msr function pointer ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted
[-] fopen(/var/log/dmesg): No such file or directory
[-] dmesg: access denied (klogctl and /var/log/dmesg both inaccessible)

--- dmesg_fake_numa_init ---
[.] searching dmesg for fake_numa_init() info ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted
[-] fopen(/var/log/dmesg): No such file or directory
[-] dmesg: access denied (klogctl and /var/log/dmesg both inaccessible)

--- dmesg_free_area_init_node ---
[.] searching dmesg for mm_init physical memory info ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted
[-] fopen(/var/log/dmesg): No such file or directory
[-] dmesg: access denied (klogctl and /var/log/dmesg both inaccessible)

--- dmesg_free_reserved_area ---
[.] searching dmesg for free_reserved_area() info ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted
[-] fopen(/var/log/dmesg): No such file or directory
[-] dmesg: access denied (klogctl and /var/log/dmesg both inaccessible)

--- dmesg_kaslr_disabled ---
[.] searching dmesg for 'KASLR disabled' or 'KASLR is disabled' ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted
[-] fopen(/var/log/dmesg): No such file or directory
[-] dmesg: access denied (klogctl and /var/log/dmesg both inaccessible)

--- dmesg_last_pfn ---
[.] searching dmesg for last_pfn ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted
[-] fopen(/var/log/dmesg): No such file or directory
[-] dmesg: access denied (klogctl and /var/log/dmesg both inaccessible)

--- dmesg_mem_init_kernel_layout ---
[.] searching dmesg for kernel memory layout sections ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted
[-] fopen(/var/log/dmesg): No such file or directory
[-] dmesg: access denied (klogctl and /var/log/dmesg both inaccessible)

--- dmesg_mmu_idmap ---
[.] searching dmesg for ' static identity map for ' ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted
[-] fopen(/var/log/dmesg): No such file or directory
[-] dmesg: access denied (klogctl and /var/log/dmesg both inaccessible)

--- dmesg_node_data ---
[.] searching dmesg for NODE_DATA allocations ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted
[-] fopen(/var/log/dmesg): No such file or directory
[-] dmesg: access denied (klogctl and /var/log/dmesg both inaccessible)
[-] no NODE_DATA allocation info found in dmesg

--- dmesg_ramdisk ---
[.] searching dmesg for RAMDISK physical addresses ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted
[-] fopen(/var/log/dmesg): No such file or directory
[-] dmesg: access denied (klogctl and /var/log/dmesg both inaccessible)

--- dmesg_reserved_mem ---
[.] searching dmesg for device tree reserved memory regions ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted
[-] fopen(/var/log/dmesg): No such file or directory
[-] dmesg: access denied (klogctl and /var/log/dmesg both inaccessible)
[-] no device tree reserved memory regions found in dmesg

--- dmesg_swiotlb ---
[.] searching dmesg for SWIOTLB bounce buffer info ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted
[-] fopen(/var/log/dmesg): No such file or directory
[-] dmesg: access denied (klogctl and /var/log/dmesg both inaccessible)

--- efi_present ---
S efi_present conf=parsed value=0x0

--- fdt_facts ---

--- firmware_memmap ---
P ram pos=base conf=parsed lo=0x100000 hi=0x7fedffff
P ram pos=base conf=parsed lo=0x7ff00000 hi=0x7fffffff
P ram pos=base conf=parsed lo=0x0 hi=0x9e7ff

--- hibernation_nokaslr ---

--- kernel_image_facts ---
S image_size conf=parsed value=0x2861320

--- kernel_notes_buildid ---
[.] reading /sys/kernel/notes ...
kernel.lto: 0
kernel.build_salt: "6.12.38+deb13-amd64"
kernel.build_id: 5783470ea1883c7d668e98f3c2928751600ccd28

--- meminfo_facts ---
S memtotal conf=parsed value=0x78fa7000
S max_pfn conf=parsed value=0x80000

--- page_size ---
S page_size conf=parsed value=0x1000

--- perf_event_open ---
[.] trying perf_event_open sampling ...
[-] syscall(SYS_perf_event_open): Permission denied
[-] no kernel address found via perf_event_open

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

--- proc_stat_wchan ---
[.] checking /proc/173583/stat 'wchan' field ...
[-] no kernel address found in /proc/pid/stat wchan

--- proc_zoneinfo ---
[.] searching /proc/zoneinfo for zone start_pfn and spanned ...
lowest zone start PFN:  1 (phys 0x0000000000001000)
P ram pos=interior conf=parsed sample=0x1000
highest zone end PFN:   524288 (phys 0x000000007fffffff)
P ram pos=top conf=parsed hi=0x7fffffff
note: phys and virt KASLR are decoupled on this arch; cannot derive directmap virtual address from physical leak

--- proc_timer_list ---
[.] scanning /proc/timer_list for timer base addresses ...
[-] fopen: Permission denied

--- qemu_tcg_iret ---
[.] trying QEMU TCG iret leak ...
[-] QEMU TCG IRET fault not triggered

--- sidt ---
[.] trying SIDT leak ...
IDT base:  0xfffffe0000000000
IDT limit: 0x0fff (4096 bytes, 256 entries)
[-] IDT is in the CPU entry area (CONFIG_PAGE_TABLE_ISOLATION=y) — no leak

--- sysfs_kernel_notes_xen ---
[.] checking /sys/kernel/notes ...
[-] Xen notes appear stale (unrelocated); discarding
[-] no kernel addresses found in ELF notes

--- sysfs_module_sections ---
[.] trying /sys/modules/*/sections/.text ...
[-] no kernel address found in /sys/module sections

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
firmware memmap: 2 System RAM entries
lowest System RAM start:  0x0000000000100000
P ram pos=base conf=parsed lo=0x100000
highest System RAM end:   0x000000007fffffff
P ram pos=top conf=parsed hi=0x7fffffff
note: phys and virt KASLR are decoupled on this arch; cannot derive directmap virtual address from physical leak

--- sysfs_iscsi_transport_handle ---
[.] checking /sys/class/iscsi_transport/iser/handle ...
[-] fopen: No such file or directory
[.] checking /sys/class/iscsi_transport/tcp/handle ...
[-] fopen: No such file or directory

--- sysfs_memory_blocks ---
[.] searching /sys/devices/system/memory for memory block info ...
memory block size: 0x8000000 (128 MB)
memory blocks: 16 online
lowest memory block start:  0x0000000000000000
P ram pos=interior conf=parsed sample=0x0
highest memory block end:   0x000000007fffffff
P ram pos=top conf=parsed hi=0x7fffffff
note: phys and virt KASLR are decoupled on this arch; cannot derive directmap virtual address from physical leak

--- sysfs_nd_region ---
[.] trying /sys/bus/nd/devices/ndregionN/resource ...
[-] /sys/bus/nd/devices not present (CONFIG_LIBNVDIMM=n or no nd bus)

--- sysfs_nf_conntrack ---
[.] trying /sys/kernel/slab/nf_contrack_* ...
[-] no kernel address found in sysfs nf_conntrack

--- sysfs_pci_resource ---
[.] searching /sys/bus/pci/devices for PCI device MMIO BAR addresses ...
PCI devices: 46, memory BARs: 79
lowest PCI MMIO start:  0x00000000000c0000
P pci_mmio pos=interior conf=parsed sample=0xc0000
highest PCI MMIO end:   0x00000000febfffff
P pci_mmio pos=interior conf=parsed sample=0xfebfffff

--- sysfs_uio_map ---
[.] searching /sys/class/uio for UIO device map addresses ...

--- sysfs_vmcoreinfo ---
[.] trying /sys/kernel/vmcoreinfo ...
vmcoreinfo_note physical address: 0x000000007c944000
P vmcoreinfo pos=interior conf=parsed sample=0x7c944000
note: phys and virt KASLR are decoupled on this arch; cannot derive directmap virtual address from physical leak

--- bcm_msg_head_struct ---
[.] trying bcm_msg_head struct stack pointer leak ...
[-] no kernel address leaked via BCM socket

--- databounce ---
[-] databounce: not an Intel CPU; attack not applicable

--- entrybleed ---
[.] trying EntryBleed (CVE-2022-4543) ...
[.] AMD CPU with KPTI disabled
[-] kernel version '6.12.38+deb13-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.38-1 (2025-07-16)' not recognized
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
possible kernel base: ffffffffa7a00000
V kernel_text pos=base conf=timing lo=0xffffffffa7a00000

Components: 77 total, 17 succeeded, 11 unavailable, 24 access denied, 25 no result

========================================
 Results
========================================

Kernel text (virtual) / kernel_text [1]:
  0xffffffffa7a00000  kernel_text (prefetch, timing)
  ==> 0xffffffffa7a00000  (timing, 1 source)

----------------------------------------
Physical DRAM / ram [4]:
  0x0000000000000000  ram (sysfs_memory_blocks, parsed)
  0x0000000000001000  ram (firmware_memmap, parsed)
  0x0000000000100000  ram (boot_params_e820, parsed)
  0x000000007ff00000  ram (firmware_memmap, parsed)
  ==> 0x0000000000100000  (parsed, 1 source, 3 conflicts)
      range: 0x0000000000000000 - 0x000000007ff00000  (2.0 GiB)

----------------------------------------
Physical DRAM / initrd [1]:
  0x000000003173d000  initrd (boot_params_e820, parsed)
  ==> 0x000000003173d000  (parsed, 1 source)

----------------------------------------
Physical DRAM / cmdline [1]:
  0x000000000008f000  cmdline (cmdline_region, parsed)
  ==> 0x000000000008f000  (parsed, 1 source)

----------------------------------------
Physical DRAM / vmcoreinfo [1]:
  0x000000007c944000  vmcoreinfo (sysfs_vmcoreinfo, parsed)
  ==> 0x000000007c944000  (parsed, 1 source)

----------------------------------------
Physical MMIO / pci_mmio [2]:
  0x00000000000c0000  pci_mmio (sysfs_pci_resource, parsed)
  0x00000000febfffff  pci_mmio (sysfs_pci_resource, parsed)
  ==> 0x00000000000c0000  (parsed, 1 source, 1 conflict)
      range: 0x00000000000c0000 - 0x00000000febfffff  (4.0 GiB)

----------------------------------------
KASLR analysis:
  Virtual text base:    0xffffffffa7a00000
  Default text base:    0xffffffff81000000
  KASLR slide:          +0x26a00000 (648019968)
  KASLR text entropy:   0 bits (pinned)

  Inferred phys text range:  0x0000000001000000 - 0x000000002eedbce0
  Remaining phys slots:      367 (9 bits, step 0x200000)

Memory KASLR (directmap / vmalloc / vmemmap):
  virt_page_offset_base     >= 0xffff800000000000
  virt_vmalloc_base         0xffff8b0040000000 - 0xffffdcffc0000000  (83966 candidates, 17 bits)
  virt_vmemmap_base         0xffffab0080000000 - 0xfffffd0000000000  (83966 candidates, 17 bits)

----------------------------------------
Virtual memory layout (decoupled):

  0xffffffffffffffff
      modules (no leak)
  0xffffffffc0000000
      . . .  390.0 MiB gap  . . .
  0xffffffffa7a00000
      kernel text (pinned) -- leak 0xffffffffa7a00000
  0xffffffffa7a00000
      . . .  128.0 TiB gap  . . .
  0xffff800000000000
      direct map (pinned)
  0xffff800000000000
      . . .  65408.0 TiB gap  . . .
  0xff00000000000000  (user space + non-canonical hole below)

Physical memory layout:

  0x000000007fffffff
      above DRAM
        0x00000000febfffff  [mmio] pci_mmio
  0x000000007fffffff
      in DRAM
        0x000000007c944000  [dram] vmcoreinfo
        0x000000003173d000  [dram] initrd
  0x000000002eedbce0
      phys kernel text
        (no leak)
  0x0000000001000000
      in DRAM
        0x00000000000c0000  [mmio] pci_mmio
        0x000000000008f000  [dram] cmdline
  0x0000000000000000
```

</details>

### Oneline (`-1`)

`-1` (`--oneline`) produces a single shell-pipeable line:

```
arch=x86_64 kaslr=on text=0xffffffffa7a00000 slide=+0x26a00000(648019968) results=11
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
   opt-out, which the main results banner already reports. Omitted
   when KASLR is healthy or opted out.

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

The hardening assessment is also available in JSON output (`-j -H`),
where it appears in a top-level `"hardening"` object with fields
`exposure`, `kaslr_posture` (always present; `state` is one of
`active` / `disabled` / `unsupported` / `randomization_failed`),
`active_defenses`, `lockdown`, `available_hardening`,
`patched_vulnerabilities`, `compile_time_surface`, and `no_mitigation`.
Markdown output (`-m -H`) appends the same assessment as a
`## Hardening Assessment` section.
