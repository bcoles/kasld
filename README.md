<p align="center">
 <img src="logo.png" alt="KASLD logo generated with Copilot (cropped)"/>
</p>

<p align="center">
  <img src="https://github.com/bcoles/kasld/actions/workflows/build-and-test.yml/badge.svg" alt="Build Status"/>
  <img src="https://img.shields.io/github/v/release/bcoles/kasld" alt="Release"/>
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"/>
</p>


# Kernel Address Space Layout Derandomization (KASLD)

A collection of various techniques to infer the Linux kernel virtual address
layout and physical memory map as an unprivileged local user, for the purpose
of bypassing Kernel Address Space Layout Randomization (KASLR).

Supports:

* x86 (i386+, amd64)
* ARM (armv6, armv7, armv8)
* MIPS (mipsbe, mipsel, mips64el)
* PowerPC (ppc, ppc64)
* RISC-V (riscv32, riscv64)
* LoongArch (loongarch64)

## Table of Contents

* [Usage](#usage)
  * [Example Output](#example-output)
* [Building](#building)
* [Configuration](#configuration)
* [KASLR and Kernel Memory Layout](#kaslr-and-kernel-memory-layout)
  * [Function Offsets](#function-offsets)
  * [Function Granular KASLR (FG-KASLR)](#function-granular-kaslr-fg-kaslr)
  * [Linux KASLR History and Implementation](#linux-kaslr-history-and-implementation)
  * [Physical and Virtual KASLR](#physical-and-virtual-kaslr)
  * [Kernel Sections and Cross-Section Inference](#kernel-sections-and-cross-section-inference)
  * [Virtual Memory Split (vmsplit)](#virtual-memory-split-vmsplit)
* [KASLR Bypass Techniques](#kaslr-bypass-techniques)
  * [Filesystem Leaks](#filesystem-leaks)
    * [System Logs](#system-logs)
    * [DebugFS](#debugfs)
    * [Procfs and Sysfs](#procfs-and-sysfs)
    * [Boot Configuration](#boot-configuration)
  * [Side-Channels](#side-channels)
  * [Syscall and Interface Leaks](#syscall-and-interface-leaks)
  * [Brute Force](#brute-force)
  * [Weak Entropy](#weak-entropy)
  * [Patched Kernel Bugs](#patched-kernel-bugs)
  * [Arbitrary Read](#arbitrary-read)
* [License](#license)


## Usage

```
sudo apt install libc-dev make gcc binutils git
git clone https://github.com/bcoles/kasld
cd kasld
make run
```

Each component in the `src/` directory is a standalone leak component using
a different technique to retrieve or infer kernel addresses. The `kasld`
orchestrator discovers and executes all components, displays results in
real-time, and produces a section-aware summary with validated addresses
grouped by kernel section (text, modules, direct map, etc).

After building, the `build/<arch>/` directory is self-contained and can be
deployed to a target system:

```
build/<arch>/
  kasld              <- run this
  components/        <- leak components
```

Modern fully-patched systems with `kernel.dmesg_restrict=1`,
`kernel.kptr_restrict=1`, and `kernel.perf_event_paranoid=2` (or higher)
are expected to return limited results. For testing purposes, the
[extra/weaken-kernel-hardening](extra/weaken-kernel-hardening) script
can temporarily relax these settings (requires root).


### Example Output

The following is example output from a default Debian 13 (x86-64) system:

<details>
<summary>Click to expand</summary>

```

     ▄█   ▄█▄    ▄████████    ▄████████  ▄█       ████████▄
    ███ ▄███▀   ███    ███   ███    ███ ███       ███   ▀███
    ███▐██▀     ███    ███   ███    █▀  ███       ███    ███
   ▄█████▀      ███    ███   ███        ███       ███    ███
  ▀▀█████▄    ▀███████████ ▀███████████ ███       ███    ███
    ███▐██▄     ███    ███          ███ ███       ███    ███
    ███ ▀███▄   ███    ███    ▄█    ███ ███▌    ▄ ███   ▄███
    ███   ▀█▀   ███    █▀   ▄████████▀  █████▄▄██ ████████▀
    ▀                                   ▀ v0.1.0

Kernel release:               6.12.38+deb13-amd64
Kernel version:               #1 SMP PREEMPT_DYNAMIC Debian 6.12.38-1 (2025-07-16)
Kernel arch:                  x86_64

kernel.kptr_restrict:         0
kernel.dmesg_restrict:        1
kernel.panic_on_oops:         0
kernel.perf_event_paranoid:   3

Readable /var/log/dmesg:      no
Readable /var/log/kern.log:   no
Readable /var/log/syslog:     no
Readable DebugFS:             no
Readable /boot/System.map:    yes
Readable /boot/config:        yes

Running 49 components...
[####################] 100%  49/49  11.1s

========================================
 Results
========================================

  Kernel text (virtual)     0xffffffffa7a00000  (1 source)
  Physical DRAM             0x0000000000000000 - 0x0000000080000000  (2.0 GiB, 7 sources)
  Physical MMIO             0x00000000000c0000 - 0x00000000febfffff  (4.0 GiB, 2 sources)

----------------------------------------
KASLR analysis:
  Virtual text base:    0xffffffffa7a00000
  Default text base:    0xffffffff81000000
  KASLR slide:          +648019968 (618.0 MiB)
  KASLR text entropy:   8 bits (504 slots of 0x200000)
  Observed slot index:  309 / 504

----------------------------------------
Virtual memory layout (decoupled):

  0xffffffffffffffff
  +------------------------------------------------------------------+
  |  modules                                                         |
  |  (no leak)                                                       |
  +------------------------------------------------------------------+
  0xffffffffc0000000
  +------------------------------------------------------------------+
  |  kernel text                                                     |
  |    0xffffffffa7a00000                                            |
  +------------------------------------------------------------------+
  0xffffffff80000000
  +------------------------------------------------------------------+
  |                                                                  |
  |  ...  128.0 TiB                                                  |
  |                                                                  |
  +------------------------------------------------------------------+
  |  direct map                                                      |
  |  (no leak)                                                       |
  +------------------------------------------------------------------+
  0xffff800000000000

Physical memory layout:

  0x00000000febfffff
  +------------------------------------------------------------------+
  |  0x00000000febfffff  [mmio] sysfs_pci_resource:hi                |
  |  0x0000000080000000  [dram] proc-zoneinfo:hi                     |
  |  0x000000007fffffff  [dram] sysfs_firmware_memmap:hi             |
  |  0x000000007c944000  [dram] sysfs_vmcoreinfo                     |
  |  0x00000000000c0000  [mmio] sysfs_pci_resource:lo                |
  |  0x0000000000001000  [dram] proc-zoneinfo:lo                     |
  |  0x0000000000000000  [dram] sysfs_firmware_memmap:lo             |
  +------------------------------------------------------------------+
  0x0000000000000000
```

</details>

## Building

A compiler which supports the `_GNU_SOURCE` macro is required due to
use of non-portable code (`MAP_ANONYMOUS`, `getline()`, `popen()`, ...).

```
make              # build kasld + components
make run          # build and run
make test         # build and run unit tests
make cross        # cross-compile for all supported architectures
make install      # install to /usr/local (PREFIX=/usr/local)
make uninstall    # remove installed files
make clean        # remove build directory
make help         # show all targets and options
```

Command-line options:

```
-j, --json      Machine-readable JSON output
-1, --oneline   Single-line summary output
-m, --markdown  Markdown table output
-c, --color     Colorize text output (auto-detected for TTYs)
-v, --verbose   Show component output
-V, --version   Print version and exit
-h, --help      Show this help
```

KASLD can be cross-compiled with `make` by specifying the appropriate
compiler (`CC`). Static linking is applied automatically when cross-compiling:

```
make CC=aarch64-linux-musl-gcc
```

Build all supported cross-compilation targets (toolchains must be in `PATH`):

```
make cross
```


## Configuration

Architecture-specific kernel memory layout constants are defined in
[kasld.h](src/include/kasld.h). The default values should work on all systems,
but may need to be adjusted for very old kernels, embedded devices, or systems
with unusual configurations.

The orchestrator automatically aligns leaked addresses to `KERNEL_ALIGN`
boundaries and adjusts for `TEXT_OFFSET`. If a component detects a non-default
`PAGE_OFFSET` at runtime (e.g. on a 32-bit system with a 2G/2G vmsplit),
the orchestrator adjusts all layout boundaries before validation.

Refer to the comment headers in [kasld.h](src/include/kasld.h) for
documentation of each configuration option.


## KASLR and Kernel Memory Layout

### Function Offsets

As the entire kernel code text is mapped with only the base address randomized,
a single kernel pointer leak can be used to infer the location of the kernel
virtual address space and offset of the kernel base address.

Offsets to useful kernel functions (`commit_creds`, `prepare_kernel_cred`, etc)
from the base address can be pre-calculated on other systems with the same
kernel - an easy task for publicly available kernels (ie, distro kernels).

Function offsets may also be retrieved from various file system locations
(`/proc/kallsyms`, `vmlinux`, `System.map`, etc) depending on file system
permissions. [jonoberheide/ksymhunter](https://github.com/jonoberheide/ksymhunter)
automates this process.


### Function Granular KASLR (FG-KASLR)

Function Granular KASLR (aka "finer grained KASLR") patches for the 5.5.0-rc7
kernel were [proposed in February 2020](https://lwn.net/Articles/811685/)
(but have not been merged as of 2026-01-01).

This optional non-mainline mitigation ["rearranges your kernel code at load time on a per-function level granularity"](https://lwn.net/Articles/811685/)
and can be enabled with the [CONFIG_FG_KASLR](https://patchwork.kernel.org/project/linux-hardening/patch/20211223002209.1092165-8-alexandr.lobakin@intel.com/) flag.

FG-KASLR ensures the location of kernel and module functions are independently
randomized and no longer located at a constant offset from the kernel `.text`
base.

On systems which support FG-KASLR patches (x86_64 from 2020, arm64 from 2023),
this makes calculating offsets to useful functions more difficult and renders
kernel pointer leaks significantly less useful.

However, some regions of the kernel are not randomized (such as symbols before
`__startup_secondary_64` on x86_64) and offsets remain consistent across reboots.
Additionally, FG-KASLR randomizes only kernel functions, leaving other useful
kernel data (such as [modprobe_path](https://sam4k.com/like-techniques-modprobe_path/)
and `core_pattern` usermode helpers) unchanged at a static offset.

See also:

* [[PATCH v10 00/15] Function Granular KASLR](https://lore.kernel.org/lkml/20220209185752.1226407-1-alexandr.lobakin@intel.com/)
* [CONFIG_FG_KASLR](https://patchwork.kernel.org/project/linux-hardening/patch/20211223002209.1092165-8-alexandr.lobakin@intel.com/)
* [FGKASLR - CTF Wiki](https://ctf-wiki.org/pwn/linux/kernel-mode/defense/randomization/fgkaslr/)


### Linux KASLR History and Implementation

Not all architectures support KASLR (`CONFIG_RANDOMIZE_BASE`) or enable it by default:

| Architecture | KASLR Added | Date | Default On | Notes |
|---|---|---|---|---|
| x86_32 | v3.14 ([`8ab3820fd5b2`](https://github.com/torvalds/linux/commit/8ab3820fd5b2)) | 2013-10-13 | v4.12 ([`09e43968fc6c`](https://github.com/torvalds/linux/commit/09e43968fc6c)) | Kconfig `default y` since v4.12 |
| x86_64 | v3.14 ([`8ab3820fd5b2`](https://github.com/torvalds/linux/commit/8ab3820fd5b2)) | 2013-10-13 | v4.12 ([`09e43968fc6c`](https://github.com/torvalds/linux/commit/09e43968fc6c)) | Kconfig `default y` since v4.12 |
| arm64 | v4.6 ([`f80fb3a3d508`](https://github.com/torvalds/linux/commit/f80fb3a3d508)) | 2016-02-24 | Yes (defconfig) | Enabled in upstream arm64 defconfig |
| MIPS | v4.7 ([`405bc8fd12f5`](https://github.com/torvalds/linux/commit/405bc8fd12f5)) | 2016-05-13 | No | |
| s390 | v5.2 ([`b2d24b97b2a9`](https://github.com/torvalds/linux/commit/b2d24b97b2a9)) | 2019-04-29 | v5.2 | Kconfig `default y` from initial commit |
| PowerPC | v5.5 ([`2b0e86cc5de6`](https://github.com/torvalds/linux/commit/2b0e86cc5de6)) | 2019-11-13 | No | BookE/e500 (PPC_85xx) 32-bit only; not available on PPC64/Book3S |
| LoongArch | v6.3 ([`e5f02b51fa0c`](https://github.com/torvalds/linux/commit/e5f02b51fa0c)) | 2023-02-25 | No | |
| RISC-V | v6.6 ([`84fe419dc757`](https://github.com/torvalds/linux/commit/84fe419dc757)) | 2023-07-22 | No | 64-bit only |
| arm32 | — | — | — | Not supported |
| sparc | — | — | — | Not supported |

See also:

* [grsecurity - KASLR: An Exercise in Cargo Cult Security](https://grsecurity.net/kaslr_an_exercise_in_cargo_cult_security) (grsecurity, 2013)
* [An Info-Leak Resistant Kernel Randomization for Virtualized Systems | IEEE Journals & Magazine | IEEE Xplore](https://ieeexplore.ieee.org/document/9178757) (Fernando Vano-Garcia, Hector Marco-Gisbert, 2020)
* Kernel Address Space Layout Randomization (LWN.net)
  * [Kernel address space layout randomization [LWN.net]](https://lwn.net/Articles/569635/)
  * [Randomize kernel base address on boot [LWN.net]](https://lwn.net/Articles/444556/)
  * [arm64: implement support for KASLR [LWN.net]](https://lwn.net/Articles/673598/)
* [Kernel load address randomization · Linux Inside](https://0xax.gitbooks.io/linux-insides/content/Booting/linux-bootstrap-6.html)
* KASLR Kconfig options:
  * [CONFIG_RANDOMIZE_BASE: Randomize the address of the kernel image (KASLR)](https://cateee.net/lkddb/web-lkddb/RANDOMIZE_BASE.html)
  * [CONFIG_RANDOMIZE_BASE_MAX_OFFSET: Maximum kASLR offset](https://cateee.net/lkddb/web-lkddb/RANDOMIZE_BASE_MAX_OFFSET.html)
  * [CONFIG_RANDOMIZE_MEMORY: Randomize the kernel memory sections](https://cateee.net/lkddb/web-lkddb/RANDOMIZE_MEMORY.html)
  * [CONFIG_RANDOMIZE_MEMORY_PHYSICAL_PADDING: Physical memory mapping padding](https://cateee.net/lkddb/web-lkddb/RANDOMIZE_MEMORY_PHYSICAL_PADDING.html)
  * [CONFIG_RELOCATABLE: Build a relocatable kernel](https://cateee.net/lkddb/web-lkddb/RELOCATABLE.html)


### Physical and Virtual KASLR

Linux KASLR randomizes the kernel location in both physical memory (where the
kernel image resides in RAM) and virtual memory (where the kernel is mapped in
the address space). Depending on the architecture, these may be randomized
together using a single offset (coupled) or independently using separate offsets
(decoupled).

On architectures where physical and virtual randomization are coupled (i.e.
the same offset), leaking either a physical or virtual kernel address
trivially reveals the other. On architectures where they are decoupled,
a physical address leak does not directly reveal the virtual address
(and vice versa), providing stronger isolation.

| Architecture | Phys/Virt Relationship | Since | Notes |
|---|---|---|---|
| x86_64 | Decoupled | v4.8 | Separate `find_random_phys_addr` / `find_random_virt_addr`; also `CONFIG_RANDOMIZE_MEMORY` for memory sections |
| x86_32 | Coupled | v3.14 | Virtual offset equals physical offset |
| arm64 | Decoupled | v4.6 | EFI stub randomizes physical; `kaslr_early_init` randomizes virtual; linear map has limited entropy |
| MIPS | Coupled | v4.7 | Single relocation offset; fixed kseg0 virt-to-phys mapping |
| LoongArch | Coupled | v6.3 | Single relocation offset; direct-mapped windows |
| RISC-V (64-bit) | Virtual only | v6.6 | Only virtual address randomized; physical depends on bootloader |
| s390 | Coupled (identity) | v5.2 | 1:1 virtual = physical mapping |
| PowerPC (32-bit) | Coupled | v5.5 | Same offset applied to both addresses |

See also:

* [security things in Linux v4.8](https://outflux.net/blog/archives/2016/10/04/security-things-in-linux-v4-8/) (Kees Cook, 2016) — describes x86_64 physical/virtual decoupling and `CONFIG_RANDOMIZE_MEMORY`
* [x86, boot: KASLR memory randomization [LWN.net]](https://lwn.net/Articles/687353/) (Thomas Garnier, 2016) — `CONFIG_RANDOMIZE_MEMORY` patch series
* [Kernel load address randomization · Linux Inside](https://0xax.gitbooks.io/linux-insides/content/Booting/linux-bootstrap-6.html) — detailed walkthrough of `choose_random_location()` on x86


### Kernel Sections and Cross-Section Inference

The kernel virtual address space contains distinct sections (text, modules,
direct map, etc.) mapped at different address ranges. KASLR randomizes the
kernel text base address, but not all sections are randomized together —
depending on the architecture, other sections may be at fixed addresses,
use the same KASLR offset, or be randomized independently.

| Architecture | Text ↔ Phys | Text ↔ Direct map | Text ↔ Modules | Notes |
|---|---|---|---|---|
| x86_64 | Independent | Independent | Independent | Three separate randomizations (`CONFIG_RANDOMIZE_MEMORY`) |
| x86_32 | Coupled | Coupled | Fixed module region | Single KASLR offset |
| arm64 | Independent | Independent | Fixed module region | Separate phys/virt randomization |
| arm32 | — | Coupled | Fixed (PAGE_OFFSET - 16M) | No KASLR |
| MIPS 32/64 | Coupled | Coupled (kseg0) | Fixed module region | Hardware-defined mapping |
| RISC-V 64 | Virtual only | Decoupled | Coupled (shifts with kernel) | Module region anchored to kernel `_end`; text ↔ directmap coupled on legacy pre-v5.10 kernels (no KASLR) |
| RISC-V 32 | — | Coupled | Same as PAGE_OFFSET | No KASLR |
| LoongArch 64 | Coupled | Coupled | Fixed module region | Direct-mapped windows |
| PowerPC 32 | Coupled | Coupled | Fixed (PAGE_OFFSET - 256M) | |
| PowerPC 64 | — | Coupled | Shared VAS | No KASLR |

On coupled architectures, all sections are at fixed offsets from each other:
a physical address reveals the virtual text base via `phys_to_virt()`, the
direct map is at a known offset (`TEXT_OFFSET`) from the text base, and
modules are either at a fixed address or a constant offset from `PAGE_OFFSET`.
A single leak from any section is sufficient to derive the others — KASLD
implements this for coupled architectures (e.g. physical text ↔ virtual text
↔ direct map via `phys_to_virt()` and `TEXT_OFFSET` arithmetic). On
decoupled architectures like x86_64, each section is randomized independently
— a physical address tells you nothing about the virtual text base, and the
direct map base (`page_offset_base`) is randomized separately. As a result,
the "Derived addresses" section in KASLD output only appears on coupled
architectures; on decoupled architectures a note is printed instead when
physical results exist that would have been derivable on a coupled system.

RISC-V 64 is notable: the module region is anchored to the kernel image
(`MODULES_VADDR = PFN_ALIGN(&_end) - SZ_2G`, `MODULES_END = PFN_ALIGN(&_start)`),
so modules shift with the randomized kernel. If module addresses are known
but the text base is not, a text range can be derived:

```
_end   ≈ lowest_module_addr + 2 GiB
_start ≈ highest_module_addr          (MODULES_END = PFN_ALIGN(&_start))
text_base ∈ [_end - 64 MiB, _end - 4 MiB]   (loose, from typical image size)
text_base ≈ _start                          (tight, if any module addr is near MODULES_END)
```

With `KERNEL_ALIGN` of 2 MiB and a 60 MiB uncertainty window, the loose
bound yields ~30 possible KASLR slots. In practice, module addresses near
`MODULES_END` directly approximate `_start`, reducing this to one slot.


### Virtual Memory Split (vmsplit)

On 32-bit systems, the 4 GiB virtual address space is divided between
userspace and the kernel. The boundary — `PAGE_OFFSET` (also known as
the "vmsplit") — determines where the kernel virtual address space begins.

The most common configuration is a 3G/1G split (`PAGE_OFFSET=0xC0000000`),
but embedded systems and custom kernels may use different splits:

| Split | `PAGE_OFFSET` | User / Kernel | Notes |
|---|---|---|---|
| 1G/3G | `0x40000000` | 1 GiB / 3 GiB | Rare |
| 2G(opt)/2G | `0x78000000` | ~1.9 GiB / ~2.1 GiB | x86_32 only |
| 2G/2G | `0x80000000` | 2 GiB / 2 GiB | Common on embedded ARM |
| 3G(opt)/1G | `0xB0000000` | ~2.75 GiB / ~1.25 GiB | x86_32 only |
| 3G/1G | `0xC0000000` | 3 GiB / 1 GiB | Default for most distros |

The vmsplit affects nearly all kernel virtual address boundaries: the kernel
text base, direct map, and (on some architectures) the module region all
shift with `PAGE_OFFSET`. This means KASLR analysis, address validation,
and memory layout interpretation depend on knowing the correct vmsplit.

Since KASLD is typically compiled on one system and deployed to another,
the compile-time `PAGE_OFFSET` assumption may not match the target system.
KASLD handles this at runtime: components that detect the actual `PAGE_OFFSET`
(e.g. `mmap-brute-vmsplit`, `boot-config`) emit a `pageoffset` tagged result,
and the orchestrator automatically adjusts all layout boundaries before
performing validation and analysis.

| Architecture | Configurable vmsplit | Config option | Default |
|---|---|---|---|
| x86_32 | Yes | `CONFIG_VMSPLIT_*` | `0xC0000000` (3G/1G) |
| arm32 | Yes | `CONFIG_PAGE_OFFSET` / `CONFIG_VMSPLIT_*` | `0xC0000000` (3G/1G) |
| PowerPC 32 | Yes | `CONFIG_PAGE_OFFSET` | `0xC0000000` (3G/1G) |
| MIPS 32 | No | — | `0x80000000` (hardware kseg0) |
| RISC-V 32 | No | — | `0xC0000000` |
| x86_64 | No | — | `0xFF00000000000000` (5-level) / `0xFFFF800000000000` (4-level) |
| arm64 | No | — | `0xFFF0000000000000` (52-bit VA) |
| MIPS 64 | No | — | `0xFFFFFFFF80000000` (xkseg) |
| PowerPC 64 | No | — | `0xC000000000000000` |
| RISC-V 64 | No | — | `0xFF60000000000000` (SV57) |
| LoongArch 64 | No | — | `0x9000000000000000` |

See also:

* [0xAX/linux-insides](https://github.com/0xAX/linux-insides)
  * https://github.com/0xAX/linux-insides/tree/master/Initialization
  * https://github.com/0xAX/linux-insides/blob/master/Theory/linux-theory-1.md
  * https://github.com/0xAX/linux-insides/tree/master/MM
* [Virtual Memory and Linux](https://elinux.org/images/b/b0/Introduction_to_Memory_Management_in_Linux.pdf) (Matt Porter, 2016)
* [Understanding the Linux Virtual Memory Manager](https://www.kernel.org/doc/gorman/html/understand/index.html) (Mel Gorman, 2004)
* Linux Kernel Programming (Kaiwan N Billimoria, 2021)


## KASLR Bypass Techniques

KASLR bypass techniques broadly fall into several categories: reading kernel
pointers or memory layout details from filesystem interfaces, exploiting
microarchitectural or software side-channels, leaking addresses through
syscalls and kernel interfaces, brute-forcing memory layout constraints,
taking advantage of weak randomization entropy, leveraging patched kernel
info leak bugs, and using arbitrary read primitives.

### Filesystem Leaks

The kernel exposes a variety of information through pseudo-filesystems
(`/proc`, `/sys`), log files (`/var/log`), and boot configuration files
(`/boot`, `/proc/config.gz`) that can reveal kernel pointers or memory
layout details to unprivileged users.

#### System Logs

Kernel and system logs (`dmesg` / `syslog`) offer a wealth of information,
including kernel pointers and the layout of virtual and physical memory.

Many KASLD components search the kernel message ring buffer for kernel addresses.
The following KASLD components read from `dmesg` and `/var/log/dmesg`:

* [dmesg_android_ion_snapshot.c](src/components/dmesg_android_ion_snapshot.c)
* [dmesg_backtrace.c](src/components/dmesg_backtrace.c)
* [dmesg_check_for_initrd.c](src/components/dmesg_check_for_initrd.c)
* [dmesg_cma_reserved.c](src/components/dmesg_cma_reserved.c)
* [dmesg_crashkernel.c](src/components/dmesg_crashkernel.c)
* [dmesg_driver_component_ops.c](src/components/dmesg_driver_component_ops.c)
* [dmesg_e820_memory_map.c](src/components/dmesg_e820_memory_map.c)
* [dmesg_early_init_dt_add_memory_arch.c](src/components/dmesg_early_init_dt_add_memory_arch.c)
* [dmesg_efi_memmap.c](src/components/dmesg_efi_memmap.c)
* [dmesg_ex_handler_msr.c](src/components/dmesg_ex_handler_msr.c)
* [dmesg_fake_numa_init.c](src/components/dmesg_fake_numa_init.c)
* [dmesg_free_area_init_node.c](src/components/dmesg_free_area_init_node.c)
* [dmesg_free_reserved_area.c](src/components/dmesg_free_reserved_area.c)
* [dmesg_kaslr-disabled.c](src/components/dmesg_kaslr-disabled.c)
* [dmesg_last_pfn.c](src/components/dmesg_last_pfn.c)
* [dmesg_mem_init_kernel_layout.c](src/components/dmesg_mem_init_kernel_layout.c)
* [dmesg_mmu_idmap.c](src/components/dmesg_mmu_idmap.c)
* [dmesg_node_data.c](src/components/dmesg_node_data.c)
* [dmesg_ramdisk.c](src/components/dmesg_ramdisk.c)
* [dmesg_reserved_mem.c](src/components/dmesg_reserved_mem.c)
* [dmesg_reserved_mem_opensbi.c](src/components/dmesg_reserved_mem_opensbi.c)
* [dmesg_riscv_relocation.c](src/components/dmesg_riscv_relocation.c)
* [dmesg_swiotlb.c](src/components/dmesg_swiotlb.c)

Historically, raw kernel pointers were frequently printed to the system log
without using the [`%pK` printk format](https://www.kernel.org/doc/html/latest/core-api/printk-formats.html).

* https://github.com/torvalds/linux/search?p=1&q=%25pK&type=Commits

Bugs which trigger a kernel oops can be used to leak kernel pointers by reading
the associated backtrace from system logs (on systems with `kernel.panic_on_oops = 0`).

There are countless examples. A few simple examples are available in the [extra](extra/) directory:

* [extra/oops_inet_csk_listen_stop.c](extra/oops_inet_csk_listen_stop.c)
* [extra/oops_netlink_getsockbyportid_null_ptr.c](extra/oops_netlink_getsockbyportid_null_ptr.c)

Most modern distros ship with `kernel.dmesg_restrict` enabled by default to
prevent unprivileged users from accessing the kernel debug log. Similarly,
grsecurity hardened kernels support `kernel.grsecurity.dmesg` to prevent
unprivileged access.

System log files (ie, `/var/log/syslog`) are readable only by privileged users
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


#### DebugFS

Various areas of [DebugFS](https://en.wikipedia.org/wiki/Debugfs)
(`/sys/kernel/debug/*`) may disclose kernel pointers.

DebugFS is [no longer readable by unprivileged users by default](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=82aceae4f0d42f03d9ad7d1e90389e731153898f)
since kernel version `v3.7-rc1~174^2~57` on 2012-08-27.

This change pre-dates Linux KASLR by 2 years. However, DebugFS may still be
readable in some non-default configurations.


#### Procfs and Sysfs

The `/proc` and `/sys` pseudo-filesystems expose kernel addresses, memory
layout details, symbol information, and hardware configuration. Many of
these files are readable by unprivileged users by default.

The following KASLD components read from `/proc`:

* [proc-kallsyms.c](src/components/proc-kallsyms.c) — kernel symbol addresses from `/proc/kallsyms`
* [proc-modules.c](src/components/proc-modules.c) — loaded module addresses from `/proc/modules`
* [proc-zoneinfo.c](src/components/proc-zoneinfo.c) — memory zone boundaries from `/proc/zoneinfo`
* [proc-cpuinfo.c](src/components/proc-cpuinfo.c) — CPU information from `/proc/cpuinfo`
* [proc-pid-syscall.c](src/components/proc-pid-syscall.c) — kernel stack pointer from `/proc/<pid>/syscall`
* [proc-stat-wchan.c](src/components/proc-stat-wchan.c) — wait channel address from `/proc/<pid>/stat`
* [proc-cmdline.c](src/components/proc-cmdline.c) — kernel command line from `/proc/cmdline` (checks for `nokaslr`)
* [proc-config.c](src/components/proc-config.c) — kernel configuration from `/proc/config.gz`

The following KASLD components read from `/sys`:

* [sysfs_firmware_memmap.c](src/components/sysfs_firmware_memmap.c) — firmware memory map from `/sys/firmware/memmap/`
* [sysfs_memory_blocks.c](src/components/sysfs_memory_blocks.c) — memory block addresses from `/sys/devices/system/memory/`
* [sysfs_pci_resource.c](src/components/sysfs_pci_resource.c) — PCI BAR addresses from `/sys/bus/pci/devices/`
* [sysfs_vmcoreinfo.c](src/components/sysfs_vmcoreinfo.c) — kernel addresses from `/sys/kernel/vmcoreinfo`
* [sysfs_devicetree_initrd.c](src/components/sysfs_devicetree_initrd.c) — initrd address from `/sys/firmware/devicetree/`
* [sysfs_devicetree_memory.c](src/components/sysfs_devicetree_memory.c) — memory regions from `/sys/firmware/devicetree/`
* [sysfs_iscsi_transport_handle.c](src/components/sysfs_iscsi_transport_handle.c) — iSCSI transport handle from `/sys/class/iscsi_transport/`
* [sysfs-kernel-notes-xen.c](src/components/sysfs-kernel-notes-xen.c) — Xen notes from `/sys/kernel/notes`
* [sysfs-module-sections.c](src/components/sysfs-module-sections.c) — module section addresses from `/sys/module/*/sections/`
* [sysfs_nf_conntrack.c](src/components/sysfs_nf_conntrack.c) — netfilter conntrack hash from `/sys/module/nf_conntrack/`

Most of these are mitigated by `kernel.kptr_restrict` (for `/proc/kallsyms`,
`/proc/modules`, etc.) and root-only permissions on sensitive sysfs entries.


#### Boot Configuration

Boot configuration and kernel config files can reveal whether KASLR is
enabled, the `PAGE_OFFSET` (vmsplit), and other layout-relevant settings.

The following KASLD components read boot configuration:

* [boot-config.c](src/components/boot-config.c) — reads `/boot/config-*` for `CONFIG_RELOCATABLE`, `CONFIG_RANDOMIZE_BASE`, and `CONFIG_PAGE_OFFSET`
* [proc-config.c](src/components/proc-config.c) — reads `/proc/config.gz` for the same configuration options
* [proc-cmdline.c](src/components/proc-cmdline.c) — reads `/proc/cmdline` to check for `nokaslr`


### Side-Channels

There are a plethora of viable side-channel attacks which can be used to break
KASLR, including microarchitectural timing attacks, transient execution attacks,
and software side-channels that exploit timing variations in kernel algorithms
and data structures.

The following table catalogues known side-channel KASLR attacks.

| Attack | Year | Status | References |
|---|---|---|---|
| KernelSnitch | 2025 | **Implemented (experimental)**: [kernelsnitch.c](src/components/kernelsnitch.c)<br>Futex hash-table timing leaks `mm_struct` directmap address (not `_stext`). x86_64, unprivileged. Requires `KASLD_EXPERIMENTAL=1` (~1–30 min runtime). Mitigated by `CONFIG_FUTEX_PRIVATE_HASH` (mainline ~v6.14+) which removes `mm_struct` from the private futex hash key. | [KernelSnitch: Side-Channel Attacks on Kernel Data Structures](https://lukasmaar.github.io/papers/ndss25-kernelsnitch.pdf) (Maar et al., 2025) — [NDSS 2025](https://www.ndss-symposium.org/ndss-paper/kernelsnitch-side-channel-attacks-on-kernel-data-structures/)<br>[lukasmaar/kernelsnitch](https://github.com/lukasmaar/kernelsnitch) |
| GhostWrite (CVE-2024-44067) | 2024 | T-Head XuanTie C910/C920 RISC-V only (2 CPU models); kernel ≥6.14 disables vector extension as mitigation. | [GhostWrite](https://www.ghostwriteattack.com/)<br>[RISCover: Differential CPU Fuzz Testing](https://ghostwriteattack.com/riscover_ccs25.pdf) (Thomas et al., 2025)<br>[cispa/GhostWrite](https://github.com/cispa/GhostWrite), [cispa/RISCover](https://github.com/cispa/RISCover) |
| SLAM | 2024 | Requires Intel LAM / AMD UAI (no mainstream kernel support yet); Spectre-based, needs specific gadgets. | [Leaky Address Masking: Exploiting Unmasked Spectre Gadgets with Noncanonical Address Translation](https://download.vusec.net/papers/slam_sp24.pdf) (Hertogh et al., 2024)<br>[vusec.net/projects/slam](https://www.vusec.net/projects/slam/), [vusec/slam](https://github.com/vusec/slam) |
| SLUBStick (CVE-2024-26808) | 2024 | Achieves arbitrary kernel read/write (enabling KASLR bypass) via allocator timing side-channel, but requires a pre-existing heap vulnerability (UAF, heap overflow). Not a standalone KASLR bypass. | [SLUBStick: Arbitrary Memory Writes through Practical Software Cross-Cache Attacks within the Linux Kernel](https://www.usenix.org/system/files/usenixsecurity24-maar-slubstick.pdf) (Maar et al., 2024) — [USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/maar-slubstick) |
| Downfall (CVE-2022-40982) | 2023 | Mitigated by microcode on affected Intel CPUs (6th-11th gen); Gather Data Sampling, complex setup. | [Downfall: Exploiting Speculative Data Gathering](https://downfall.page/media/downfall.pdf) (Moghimi, 2023) |
| Timing Transient Execution | 2023 | Depends on Meltdown-type transient execution; mitigated by KPTI on all affected Intel CPUs. | [Timing the Transient Execution: A New Side-Channel Attack on Intel CPUs](https://arxiv.org/pdf/2304.10877.pdf) (Jin et al., 2023) |
| AMD Prefetch Attacks (CVE-2021-26318) | 2022 | Mitigated on Zen 3+ via microcode (AMD-SB-1017); redundant on older AMD / VMs where `prefetch.c` also works. | [AMD Prefetch Attacks through Power and Time](https://www.usenix.org/system/files/sec22-lipp.pdf) (Lipp et al., 2022) — [USENIX Security 2022](https://www.youtube.com/watch?v=bTV-9-B26_w)<br>[AMD-SB-1017](https://www.amd.com/en/corporate/product-security/bulletin/amd-sb-1017)<br>[amdprefetch/amd-prefetch-attacks](https://github.com/amdprefetch/amd-prefetch-attacks/tree/master/case-studies/kaslr-break) |
| AMD RAPL power side-channel (CVE-2021-26318) | 2022 | Unprivileged RAPL access blocked since Linux 5.10; requires `amd_energy` module (not loaded by default); mitigated by same microcode as timing variant. | [AMD Prefetch Attacks through Power and Time](https://www.usenix.org/system/files/sec22-lipp.pdf) (Lipp et al., 2022) |
| EntryBleed (CVE-2022-4543) | 2022 | **Implemented**: [entrybleed.c](src/components/entrybleed.c)<br>Intel x86_64 with KPTI enabled or disabled; AMD x86_64 with KPTI disabled. Requires kernel-version-specific offsets. Patched in kernel ~v6.2 (randomized per-CPU entry areas). | [EntryBleed: Breaking KASLR under KPTI with Prefetch (CVE-2022-4543)](https://www.willsroot.io/2022/12/entrybleed.html) (willsroot, 2022)<br>[EntryBleed: A Universal KASLR Bypass against KPTI on Linux](https://dl.acm.org/doi/pdf/10.1145/3623652.3623669) (William Liu, Joseph Ravichandran, Mengjia Yan, 2023) |
| RETBLEED | 2022 | Kernel mitigated (IBRS/eIBRS, retpoline); requires specific Intel (6th-8th gen) or AMD (Zen 1/1+/2) CPUs. | [RETBLEED: Arbitrary Speculative Code Execution with Return Instructions](https://comsec.ethz.ch/wp-content/files/retbleed_sec22.pdf) (Wikner & Razavi, 2022)<br>[comsec-group/retbleed](https://github.com/comsec-group/retbleed) |
| SLS (CVE-2021-26341) | 2022 | AMD Zen 1/2 only; requires eBPF JIT (restricted since Linux 5.8); mitigated by INT3/LFENCE after every unconditional branch. | [The AMD Branch (Mis)predictor Part 2: Where No CPU has Gone Before](https://grsecurity.net/amd_branch_mispredictor_part_2_where_no_cpu_has_gone_before) (Wieczorkiewicz, 2022)<br>[Straight-line Speculation Whitepaper](https://developer.arm.com/documentation/102825/0100/?lang=en) (ARM, 2020) |
| ThermalBleed | 2022 | Thermal side-channel operates at ms-second timescale; far too slow/noisy for KASLR (needs sub-µs resolution). | [ThermalBleed: A Practical Thermal Side-Channel Attack](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=9727162) (Kim & Shin, 2022) |
| Memory deduplication timing | 2021 | Requires KSM enabled (disabled by default on most distros); primarily a VM-to-VM attack. | [Memory deduplication as a threat to the guest OS](https://kth.diva-portal.org/smash/get/diva2:1060434/FULLTEXT01) (Suzaki et al., 2011)<br>[Breaking KASLR Using Memory Deduplication in Virtualized Environments](https://www.mdpi.com/2079-9292/10/17/2174) (Kim et al., 2021)<br>[Remote Memory-Deduplication Attacks](https://pure.tugraz.at/ws/portalfiles/portal/38441480/main.pdf) (Schwarzl et al., 2022) |
| VDSO sidechannel | 2021 | ARM64 only; requires custom kernel gadget in VDSO; mitigated by Spectre barriers in VDSO code. | [VDSO As A Potential KASLR Oracle](https://www.longterm.io/vdso_sidechannel.html) (Pettersson & Radocea, 2021) |
| EchoLoad | 2020 | **Implemented (experimental)**: [echoload.c](src/components/echoload.c)<br>Intel x86_64 only; relies on Meltdown zero-return behavior. Supports TSX, speculation, and signal-handler transient modes. No signal on non-vulnerable hardware (AMD, modern Intel with in-silicon Meltdown fix). Mitigated by KPTI on patched kernels. Requires `KASLD_EXPERIMENTAL=1`. | [KASLR: Break It, Fix It, Repeat](https://gruss.cc/files/kaslrbfr.pdf) (Claudio Canella, Michael Schwarz, Martin Haubenwallner, 2020)<br>[Store-to-Leak Forwarding: There and Back Again](https://i.blackhat.com/asia-20/Friday/asia-20-Canella-Store-To-Leak-Forwarding-There-And-Back-Again-wp.pdf) (Canella et al., 2020) — [Slides](https://misc0110.net/files/store2leak_blackhat_slides.pdf), [Blackhat Asia 2020](https://www.youtube.com/watch?v=Yc1AXkCu2AA)<br>[cc0x1f/store-to-leak-forwarding/echoload](https://github.com/cc0x1f/store-to-leak-forwarding-there-and-back-again/tree/master/echoload) |
| PLATYPUS | 2020 | Unprivileged RAPL access restricted since Linux 5.10 (`powercap` driver); requires Intel CPU with specific RAPL interface. | [PLATYPUS: Software-based Power Side-Channel Attacks on x86](https://platypusattack.com/platypus.pdf) (Lipp et al., 2020) |
| TagBleed | 2020 | Requires Intel CPU with tagged TLBs and a VMM environment; narrow applicability. | [TagBleed: Breaking KASLR on the Isolated Kernel Address Space using Tagged TLBs](https://download.vusec.net/papers/tagbleed_eurosp20.pdf) (Koschel et al., 2020)<br>[renorobert/tagbleedvmm](https://github.com/renorobert/tagbleedvmm) |
| MDS / ZombieLoad / RIDL / Fallout | 2019 | Mitigated by microcode + kernel (MDS buffer clearing on context switch). Requires specific vulnerable Intel CPU generations (pre-Cascade Lake). | [Fallout: Leaking Data on Meltdown-resistant CPUs](https://mdsattacks.com/files/fallout.pdf) (Canella et al., 2019) — [fallout_kaslr.c](https://github.com/wbowling/cpu.fail/blob/master/fallout_kaslr.c)<br>[RIDL: Rogue In-Flight Data Load](https://mdsattacks.com/files/ridl.pdf) (van Schaik et al., 2019) — [vusec/ridl](https://github.com/vusec/ridl)<br>[ZombieLoad](https://zombieloadattack.com/) — [IAIK/ZombieLoad](https://github.com/IAIK/ZombieLoad), [zombieload_kaslr.c](https://github.com/wbowling/cpu.fail/blob/master/zombieload_kaslr.c) |
| Data Bounce | 2019 | **Implemented (experimental)**: [databounce.c](src/components/databounce.c)<br>Intel x86_64 only; requires TSX (RTM). Exploits store-to-load forwarding within a TSX transaction. Works with KPTI enabled or disabled, bare metal and VMs. TSX deprecated by Intel, disabled via microcode on most consumer CPUs since 2019 (TAA mitigation). Requires `KASLD_EXPERIMENTAL=1`. | [Store-to-Leak Forwarding: Leaking Data on Meltdown-resistant CPUs](https://cpu.fail/store_to_leak_forwarding.pdf) (Michael Schwarz, Claudio Canella, Lukas Giner, Daniel Gruss, 2019)<br>[cc0x1f/store-to-leak-forwarding/data_bounce](https://github.com/cc0x1f/store-to-leak-forwarding-there-and-back-again/tree/master/data_bounce) |
| Meltdown | 2018 | Fully mitigated by KPTI on all vulnerable CPUs; KPTI enabled by default since 2018. | [Meltdown: Reading Kernel Memory from User Space](https://meltdownattack.com/meltdown.pdf) (Lipp et al., 2018) — [USENIX Security 2018](https://www.usenix.org/conference/usenixsecurity18/presentation/lipp)<br>[IAIK/meltdown](https://github.com/IAIK/meltdown), [paboldin/meltdown-exploit](https://github.com/paboldin/meltdown-exploit) |
| Spectre v1 / v2 | 2018 | Heavily mitigated (retpoline, IBRS/eIBRS, eBPF verifier hardening). KASLR break requires eBPF JIT or specific kernel gadgets; eBPF restricted to `CAP_BPF` since Linux 5.8. | [Spectre Attacks: Exploiting Speculative Execution](https://spectreattack.com/spectre.pdf) (Kocher et al., 2018)<br>[Reading privileged memory with a side-channel](https://googleprojectzero.blogspot.com/2018/01/reading-privileged-memory-with-side.html) (Jann Horn, 2018)<br>[speed47/spectre-meltdown-checker](https://github.com/speed47/spectre-meltdown-checker) |
| SPECULOSE | 2018 | Equivalent to prefetch-style probing via speculative execution; fully mitigated by KPTI. | [SPECULOSE: Analyzing the Security Implications of Speculative Execution in CPUs](https://arxiv.org/pdf/1801.04084v1.pdf) (Maisuradze & Rossow, 2018) |
| Prefetch side-channel | 2016 | **Implemented**: [prefetch.c](src/components/prefetch.c)<br>Intel and AMD x86_64. Requires KPTI to be disabled (kernel auto-disables KPTI on non-Meltdown-vulnerable CPUs: all AMD, Intel Ice Lake+). Does not require kernel-version-specific offsets. May fail silently on some newer AMD microarchitectures (Zen 3+) where the prefetch timing differential is absent. | [Prefetch Side-Channel Attacks: Bypassing SMAP and Kernel ASLR](https://gruss.cc/files/prefetch.pdf) (Daniel Gruss, Clémentine Maurice, Anders Fogh, 2016)<br>[Using Undocumented CPU Behaviour to See into Kernel Mode and Break KASLR in the Process](https://www.blackhat.com/docs/us-16/materials/us-16-Fogh-Using-Undocumented-CPU-Behaviour-To-See-Into-Kernel-Mode-And-Break-KASLR-In-The-Process.pdf) (Anders Fogh, Daniel Gruss, 2016) — [Blackhat USA](https://www.youtube.com/watch?v=Pwq0vv4X7m4)<br>[xairy/kernel-exploits/prefetch-side-channel](https://github.com/xairy/kernel-exploits/tree/master/prefetch-side-channel)<br>[Fetching the KASLR slide with prefetch](https://googleprojectzero.blogspot.com/2022/12/exploiting-CVE-2022-42703-bringing-back-the-stack-attack.html) (Seth Jenkins, 2022) — [prefetch_poc.zip](https://bugs.chromium.org/p/project-zero/issues/detail?id=2351) |
| BTB side-channel | 2016 | Complex implementation; largely superseded by simpler prefetch / EntryBleed techniques. | [Jump Over ASLR: Attacking Branch Predictors to Bypass ASLR](https://www.cs.ucr.edu/~nael/pubs/micro16.pdf) (Evtyushkin et al., 2016)<br>[felixwilhelm/mario_baslr](https://github.com/felixwilhelm/mario_baslr) |
| TSX/RTM abort timing (DrK) | 2016 | TSX deprecated by Intel, disabled via microcode on most consumer CPUs since 2019 (TAA mitigation). Redundant with Data Bounce on TSX-capable hardware. | [TSX improves timing attacks against KASLR](http://web.archive.org/web/20141107045306/http://labs.bromium.com/2014/10/27/tsx-improves-timing-attacks-against-kaslr/) (Rafal Wojtczuk, 2014)<br>[DrK: Breaking KASLR with Intel TSX](https://www.blackhat.com/docs/us-16/materials/us-16-Jang-Breaking-Kernel-Address-Space-Layout-Randomization-KASLR-With-Intel-TSX.pdf) (Jang et al., 2016) — [Blackhat USA](https://www.youtube.com/watch?v=rtuXG28g0CU)<br>[vnik5287/kaslr_tsx_bypass](https://github.com/vnik5287/kaslr_tsx_bypass) |
| Double page fault timing | 2013 | Precursor to prefetch side-channel; fully mitigated by KPTI (Meltdown patches). Superseded by prefetch / EntryBleed. | [Practical Timing Side Channel Attacks Against Kernel Space ASLR](https://openwall.info/wiki/_media/archive/TR-HGI-2013-001.pdf) (Hund et al., 2013) |
| SIDT/SGDT IDT/GDT base leak | 2004 | **Implemented**: [sidt.c](src/components/sidt.c)<br>x86/x86_64. Unprivileged `SIDT` instruction reads IDT register containing kernel pointer. Only works on pre-3.10 kernels where `idt_table` was in kernel BSS. Mitigated by IDT-to-fixmap remapping (v3.10, 2013; predates KASLR v3.14), KPTI (v4.15, 2018), and UMIP hardware (Intel Cannon Lake+ / AMD Zen 2+). Never viable against vanilla KASLR kernels. Originally used for VM detection (Red Pill, 2004); later demonstrated as a KASLR bypass against out-of-tree patches (Hund, 2013). | [KASLR is Dead: Long Live KASLR](https://gruss.cc/files/kaiser.pdf) (Gruss et al., 2017) — Section 2 lists SIDT as a known KASLR bypass<br>[Practical Timing Side Channel Attacks Against Kernel Space ASLR](https://www.ieee-security.org/TC/SP2013/papers/4977a191.pdf) (Hund et al., 2013)<br>[Red Pill](http://web.archive.org/web/20110726182809/http://invisiblethings.org/papers/redpill.html) (Joanna Rutkowska, 2004) |

Note: Several related attacks (LVI, RAMBleed) are omitted from the table
because they are not KASLR bypass techniques. LVI targets SGX enclaves;
RAMBleed is a general memory read primitive (rowhammer-based, hours-slow).

The [extra/check-hardware-vulnerabilities](extra/check-hardware-vulnerabilities)
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

### Syscall and Interface Leaks

Kernel syscalls and device interfaces can leak kernel addresses through
return values, uninitialized memory in structures, or sampling kernel events.

The following KASLD components exploit syscall and interface leaks:

* [perf_event_open.c](src/components/perf_event_open.c) — samples kernel event addresses via `perf_event_open()` (requires `kernel.perf_event_paranoid < 2`)
* [mincore.c](src/components/mincore.c) — `mincore()` heap page disclosure via uninitialized memory (CVE-2017-16994; patched in v4.15)
* [bcm_msg_head_struct.c](src/components/bcm_msg_head_struct.c) — CAN BCM `bcm_msg_head` struct uninitialized 4-byte hole leaks kernel stack pointer (CVE-2021-34693)
* [pppd_kallsyms.c](src/components/pppd_kallsyms.c) — exploits set-uid `pppd` to read `/proc/kallsyms` bypassing `kptr_restrict` open-time check
* [qemu-tcg-iret.c](src/components/qemu-tcg-iret.c) — leaks kernel stack address inside QEMU TCG guests via `iret` instruction (patched in QEMU 9.1)


### Brute Force

Some memory layout properties can be determined by probing the address
space directly, without reading any files or exploiting vulnerabilities.

The following KASLD components use brute-force probing:

* [mmap-brute-vmsplit.c](src/components/mmap-brute-vmsplit.c) — determines `PAGE_OFFSET` (vmsplit) on 32-bit systems by mapping pages across the address space until failure


### Weak Entropy

The kernel is loaded at an aligned memory address, usually between `PAGE_SIZE` (4 KiB)
and 2 MiB on modern systems (see `KERNEL_ALIGN` definitions in [kasld.h](src/include/kasld.h)).
This limits the number of possible kernel locations. For example, on x86_64 with
`RANDOMIZE_BASE_MAX_OFFSET` of 1 GiB and 2 MiB alignment, this limits the kernel load
address to `0x4000_0000 / 0x20_0000 = 512` possible locations.

Weaknesses in randomisation can decrease entropy, further limiting the possible kernel
locations in memory and making the kernel easier to locate.

KASLR may be disabled if insufficient randomness is generated during boot
(for example, if `get_kaslr_seed()` fails on ARM64).

The following KASLD component provides a baseline reference:

* [default.c](src/components/default.c) — reports the hardcoded default kernel text base address for the target architecture, used as the baseline for KASLR slide calculation

See also:

* [Another look at two Linux KASLR patches](https://www.kryptoslogic.com/blog/2020/03/another-look-at-two-linux-kaslr-patches/index.html) (Kryptos Logic, 2020)
* [arm64: efi: kaslr: Fix occasional random alloc (and boot) failure](https://github.com/torvalds/linux/commit/4152433c397697acc4b02c4a10d17d5859c2730d)
* [Defeating KASLR by Doing Nothing at All](https://projectzero.google/2025/11/defeating-kaslr-by-doing-nothing-at-all.html) (Seth Jenkins, 2025) - arm64 linear map is not randomized due to memory hotplug support; Pixel bootloader loads kernel at static physical address, making kernel virtual addresses fully predictable even with KASLR enabled.


### Patched Kernel Bugs

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


### Arbitrary Read

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


## License

KASLD is MIT licensed but borrows heavily from modified
third-party code snippets and proof of concept code.

Various code snippets were taken from third-parties and may
have different license restrictions. Refer to the reference
URLs in the comment headers available in each file for credits
and more information.
