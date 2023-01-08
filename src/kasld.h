// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Expected kernel address space values for supported architectures.
//
// - KERNEL_VAS_START:    Expected virtual address for start of the kernel
//                        virtual address space (VAS).
//                        (eg. 0xc0000000 for 32-bit systems with 3GB vmsplit)
//
// - KERNEL_BASE_MIN:     Expected minimum possible kernel base virtual address.
//
// - KERNEL_BASE_MAX:     Expected maximum possible kernel base virtual address.
//
// - KERNEL_ALIGN:        Expected kernel address alignment.
//                        (usually 2MB on modern systems)
//
// - KERNEL_BASE_MASK:    Bitmask when guessing base address.
//                        Used to bitmask-off least significant bits.
//
// - KERNEL_TEXT_DEFAULT: Default kernel base virtual address when KASLR is
//                        disabled (including text offset). This value is
//                        calculated automatically based on above values.
//
// The default values should work on most systems, but may need
// to be tweaked for the target system - especially old kernels,
// embedded devices (ie, armv7), or systems with a non-default
// memory layout.
// ---
// <bcoles@gmail.com>

/* -----------------------------------------------------------------------------
 * x86_64 (amd64)
 * -----------------------------------------------------------------------------
 * https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
 */
#if defined(__x86_64__) || defined(__amd64__)

// VAS start with 5-level page tables (CONFIG_X86_5LEVEL): 0xff000000_00000000
// VAS start with 4-level page tables: 0xffff8000_00000000
// https://www.kernel.org/doc/html/latest/x86/x86_64/mm.html
// https://www.cateee.net/lkddb/web-lkddb/X86_5LEVEL.html
#define KERNEL_VAS_START 0xff00000000000000ul

// Old <= 4.4 era kernels used the RANDOMIZE_BASE_MAX_OFFSET config option
// which limited the maximum offset to 1 GiB (0x40_000_000), yielding 512
// possible base addresses (between 0xffffffff_80000000 and
// 0xffffffff_c0000000). The RANDOMIZE_BASE_MAX_OFFSET option was later removed.
// We use a larger range with a max of 0xffffffff_f0000000.
#define KERNEL_BASE_MIN 0xffffffff80000000ul
#define KERNEL_BASE_MAX 0xfffffffff0000000ul

// For x86_64, possible max alignment is 0x1_000_000 (16MB) with default of
// 0x200_000 (2MB) in increments of 0x200_000 (2MB).
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/boot/compressed/kaslr.c#L850
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/Kconfig#L2182
// We use 1MB alignment (rather than 2MB)
#define KERNEL_ALIGN 0x100000ul
#define KERNEL_BASE_MASK 0x0ffffful

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/Kconfig#L2084
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/boot/compressed/kaslr.c#L869
#define PHYSICAL_START 0x1000000ul

#define TEXT_OFFSET 0

#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + PHYSICAL_START + TEXT_OFFSET)

/* -----------------------------------------------------------------------------
 * ARM 64-bit (aarch64 / arm64)
 * -----------------------------------------------------------------------------
 * https://lwn.net/Articles/673598/
 * https://www.kernel.org/doc/Documentation/arm64/memory.txt
 * https://github.com/torvalds/linux/blob/master/Documentation/arm64/booting.rst
 * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/arm64/memory.rst
 * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/arm64/kernel/head.S
 */
#elif defined(__aarch64__)

// 52 va bits (CONFIG_ARM64_VA_BITS_48_52) is largest.
// page_offset = (0xffffffffffffffffUL) << (va_bits - 1)
#define KERNEL_VAS_START 0xfff8000000000000ul

// 48 va bits (CONFIG_ARM64_VA_BITS_48) is a common configuration;
// but an unsafe assumption since introduction of CONFIG_ARM64_VA_BITS_48_52.
#define KERNEL_BASE_MIN 0xffff800008000000ul
#define KERNEL_BASE_MAX 0xffffffffff000000ul

// 2MB aligned
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm64/include/asm/boot.h#L18
// We use 1MB alignment (rather than 2MB)
#define KERNEL_ALIGN 0x100000ul
#define KERNEL_BASE_MASK 0x0ffffful

// TEXT_OFFSET was changed from 0x80000 to zero in 2020 from kernel v5.8 onwards
// https://elixir.bootlin.com/linux/v5.8/source/arch/arm64/Makefile
// https://lore.kernel.org/all/20200428134119.GI6791@willie-the-truck/T/
#define TEXT_OFFSET 0

#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + TEXT_OFFSET)

/* -----------------------------------------------------------------------------
 * MIPS 64-bit (mips64el)
 * -----------------------------------------------------------------------------
 * https://training.mips.com/basic_mips/PDF/Memory_Map.pdf
 */
#elif defined(__mips64) || defined(__mips64__)

#define KERNEL_VAS_START 0xffff000000000000ul

#define KERNEL_BASE_MIN 0xffffffff80000000ul
#define KERNEL_BASE_MAX 0xfffffffff0000000ul

// 2MB aligned
// We use 1MB alignment (rather than 2MB)
#define KERNEL_ALIGN 0x100000ul
#define KERNEL_BASE_MASK 0x0ffffful

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/kernel/head.S#L67
#define TEXT_OFFSET 0x400

#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + 0x100000ul + TEXT_OFFSET)

/* -----------------------------------------------------------------------------
 * x86_32 (i386 / i686)
 * -----------------------------------------------------------------------------
 * https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/Kconfig
 * https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/kernel/head_32.S
 */
#elif defined(__i386__)

// 3GB vmsplit (0xc0000000) is a common configuration
// for distro kernels for non-embedded systems
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/Kconfig#L1474
#define KERNEL_VAS_START 0xc0000000ul

// Old <= 4.4 era kernels used the RANDOMIZE_BASE_MAX_OFFSET config option
// which limited the maximum offset to 512 MiB (0x20_000_000), yielding 256
// possible base addresses (between 0xc0000000 and 0xe0000000).
// The RANDOMIZE_BASE_MAX_OFFSET option was later removed.
// We use a larger range with a max of 0xf0000000.
#define KERNEL_BASE_MIN 0xc0000000ul
#define KERNEL_BASE_MAX 0xf0000000ul

// For x86_32, possible max alignment is 0x1_000_000 (16MB) with default of
// 0x200_000 (2MB) in increments of 0x2_000 (8KB).
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/boot/compressed/kaslr.c#L850
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/Kconfig#L2182
// We use 1MB alignment (rather than 2MB)
#define KERNEL_ALIGN 0x100000ul
#define KERNEL_BASE_MASK 0x0ffffful

#define TEXT_OFFSET 0

#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + TEXT_OFFSET)

/* -----------------------------------------------------------------------------
 * ARM 32-bit (arm6l / arm7l / armhf)
 * -----------------------------------------------------------------------------
 * https://people.kernel.org/linusw/how-the-arm32-linux-kernel-decompresses
 * https://people.kernel.org/linusw/how-the-arm32-kernel-starts
 * https://www.kernel.org/doc/Documentation/arm/Porting
 * https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/kernel/head.S
 * https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/include/asm/memory.h#L30
 */
#elif defined(__arm__) || defined(__ARM_ARCH_6__) ||                           \
    defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) ||                    \
    defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__) ||                   \
    defined(__ARM_ARCH_6T2__) || defined(__ARM_ARCH_7__) ||                    \
    defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) ||                    \
    defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)

// 3GB vmsplit (0xc0000000) is common; but an unsafe assumption,
// especially for embedded systems
#define KERNEL_VAS_START 0xc0000000ul

#define KERNEL_BASE_MIN 0xc0000000ul
#define KERNEL_BASE_MAX 0xf0000000ul

// 2MB aligned
// We use 1MB alignment (rather than 2MB)
#define KERNEL_ALIGN 0x100000ul
#define KERNEL_BASE_MASK 0x0ffffful

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/Makefile#L145
#define TEXT_OFFSET 0x8000

#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + TEXT_OFFSET)

/* -----------------------------------------------------------------------------
 * MIPS 32-bit (mips / mipsbe / mipsel)
 * -----------------------------------------------------------------------------
 * https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/include/asm/mach-malta/spaces.h#L37
 * https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/include/asm/processor.h#L39
 * https://www.kernel.org/doc/Documentation/mips/booting.rst
 * https://training.mips.com/basic_mips/PDF/Memory_Map.pdf
 */
#elif defined(__mips__)

// kseg0: 0x80000000 - 0x9fffffff
#define KERNEL_VAS_START 0x80000000ul

#define KERNEL_BASE_MIN 0x80000000ul
#define KERNEL_BASE_MAX 0xf0000000ul

// page aligned (default CONFIG_PAGE_SIZE_4KB=y)
#define KERNEL_ALIGN 0x1000ul
#define KERNEL_BASE_MASK 0x0ffful

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/kernel/head.S#L67
#define TEXT_OFFSET 0x400

#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + 0x100000ul + TEXT_OFFSET)

/* -----------------------------------------------------------------------------
 * PowerPC 64-bit (powerpc64 / ppc64 / ppc64le)
 * -----------------------------------------------------------------------------
 * https://www.kernel.org/doc/ols/2001/ppc64.pdf
 */
#elif defined(__powerpc64__) || defined(__POWERPC64__)                         \
    || defined(__ppc64__) || defined(__PPC64__)

// 0xc000000000000000ul is a common configuration; but an unsafe assumption.
// For Freescale E-Book readers (CONFIG_PPC_BOOK3E_64), the kernel VAS start
// and text start is 0x8000000000000000ul.
// vmalloc, I/O and Bolted sections are mapped above kernel.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/Kconfig#L1267
#define KERNEL_VAS_START 0xc000000000000000ul

#define KERNEL_BASE_MIN 0xc000000000000000ul
#define KERNEL_BASE_MAX 0xffffffffff000000ul

// 16KiB (0x4000) aligned
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/Kconfig#L595
#define KERNEL_ALIGN 0x4000ul
#define KERNEL_BASE_MASK 0x0ffful

#define TEXT_OFFSET 0

#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + TEXT_OFFSET)

/* -----------------------------------------------------------------------------
 PowerPC 32-bit (powerpc / ppc)
 * -----------------------------------------------------------------------------
 */
#elif defined(__powerpc__) || defined(__POWERPC__) ||                          \
    defined(__ppc__) || defined(__PPC__)

#define KERNEL_VAS_START 0xc0000000ul

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/Kconfig#L1220
#define KERNEL_BASE_MIN 0xc0000000ul
#define KERNEL_BASE_MAX 0xf0000000ul

// page aligned
#define KERNEL_ALIGN 0x1000ul
#define KERNEL_BASE_MASK 0x0ffful

#define TEXT_OFFSET 0

#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + TEXT_OFFSET)

/* -----------------------------------------------------------------------------
 * RISC-V 64-bit (riscv64)
 * -----------------------------------------------------------------------------
 */
#elif (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64

#define KERNEL_VAS_START 0xffffffff80000000ul

#define KERNEL_BASE_MIN 0xffffffff80000000ul
#define KERNEL_BASE_MAX 0xffffffffff000000ul

// 2MiB (0x200000) aligned
// https://elixir.bootlin.com/linux/v6.2-rc2/source/arch/riscv/include/asm/efi.h#L41
// We use 1MiB alignment (rather than 2MiB)
#define KERNEL_ALIGN 0x100000ul
#define KERNEL_BASE_MASK 0x0ffffful

#define TEXT_OFFSET 0x2000

#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + TEXT_OFFSET)

/* -----------------------------------------------------------------------------
 * RISC-V 32-bit (riscv32)
 * -----------------------------------------------------------------------------
 */
#elif (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 32

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/riscv/Kconfig#L169
#define KERNEL_VAS_START 0xc0000000ul

#define KERNEL_BASE_MIN 0xc0000000ul
#define KERNEL_BASE_MAX 0xf0000000ul

// 4MiB (0x400000) aligned
// https://elixir.bootlin.com/linux/v6.2-rc2/source/arch/riscv/include/asm/efi.h#L41
// We use 1MiB alignment (rather than 4MiB)
#define KERNEL_ALIGN 0x100000ul
#define KERNEL_BASE_MASK 0x0ffffful

#define TEXT_OFFSET 0x2000

#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + TEXT_OFFSET)

/* -----------------------------------------------------------------------------
 * S390 (24-bit s370 / 32-bit s390 / 64-bit s390x)
 * -----------------------------------------------------------------------------
 * kernel uses 1:1 phys:virt mapping.
 * kernel text starts at 0x00000000_00100000 (1MB) offset.
 * Uses 24-bit (amode24), 32-bit (amode31) and 64-bit (amode64) addressing modes.
 * Linux for s390x did not receive KASLR support until kernel 5.2.
 *
 * https://elixir.bootlin.com/linux/v6.1.1/source/arch/s390/mm/vmem.c#L665
 * https://www.ibm.com/docs/en/zos-basic-skills?topic=1960s-what-is-virtual-storage
 * https://share.confex.com/share/115/webprogram/Handout/Session6865/Understanding%20zOS%20CS%20storage%20use.pdf
 * https://www.linux-kvm.org/images/a/ae/KVM_Forum_2018_s390_KVM_memory_management.pdf
 */
#elif defined(__s390__) || defined(__s390x__) ||                               \
    defined(__370__) || defined(__zarch__)
#error "S390 architecture is not supported!"

/* -----------------------------------------------------------------------------
 * SPARC (sparc / sparc64)
 * -----------------------------------------------------------------------------
 * Linux for sparc/sparc64 is largely abandoned and does not support KASLR.
 *
 * sparc32 kernel text starts at 0xf0004000
 * https://elixir.bootlin.com/linux/v6.1.1/source/arch/sparc/kernel/vmlinux.lds.S#L11
 *
 * sparc64 kernel text starts at 0x00000000_00404000
 * https://elixir.bootlin.com/linux/v6.1.1/source/arch/sparc/kernel/head_64.S#L39
 * https://elixir.bootlin.com/linux/v6.1.1/source/arch/sparc/kernel/vmlinux.lds.S#L18
 */
#elif defined(__sparc__)
#error "SPARC architecture is not supported!"

/* -----------------------------------------------------------------------------
 * Unsupported architectures
 * -----------------------------------------------------------------------------
 */
#else
#error "Unrecognised architecture!"
#endif

/* -----------------------------------------------------------------------------
 * Sanity check configured values
 * -----------------------------------------------------------------------------
 */
#if KERNEL_VAS_START > KERNEL_BASE_MIN
#error "Defined KERNEL_VAS_START is larger than KERNEL_BASE_MIN"
#endif

#if KERNEL_BASE_MASK > KERNEL_ALIGN
#error "Defined KERNEL_BASE_MASK is larger than KERNEL_ALIGN"
#endif

#if KERNEL_TEXT_DEFAULT > KERNEL_BASE_MAX
#error "Generated KERNEL_TEXT_DEFAULT is larger than KERNEL_BASE_MAX"
#endif

#if KERNEL_TEXT_DEFAULT < KERNEL_BASE_MIN
#error "Generated KERNEL_TEXT_DEFAULT is smaller than KERNEL_BASE_MIN"
#endif
