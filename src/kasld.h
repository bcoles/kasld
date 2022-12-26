// This file is part of KASLD - https://github.com/bcoles/kasld
//
// This file defines kernel config options using common values.
// These values may need to be tweaked for the target system.
// ---
// <bcoles@gmail.com>

/*
 * x86_64 (amd64)
 * https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
 */
#if defined(__x86_64__) || defined(__amd64__)

#define KERNEL_VAS_START 0xff00000000000000ul

#define KERNEL_BASE_MIN 0xffffffff80000000ul
#define KERNEL_BASE_MAX 0xfffffffff0000000ul

// 2MB aligned
#define KERNEL_BASE_MASK 0x0ffffful

// https://elixir.bootlin.com/linux/v5.15.10/source/arch/x86/Kconfig#L2046
#define PHYSICAL_START 0x1000000ul

#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + PHYSICAL_START)

/*
 * ARM 64-bit (aarch64)
 * https://www.kernel.org/doc/Documentation/arm64/memory.txt
 * https://github.com/torvalds/linux/blob/master/Documentation/arm64/booting.rst
 * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/arm64/memory.rst
 * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/arm64/kernel/head.S
 */
#elif defined(__aarch64__)

#define KERNEL_VAS_START 0xff00000000000000ul

// 48 va bits (CONFIG_ARM64_VA_BITS_48=y) is a common configuration
// page_offset = (0xffffffffffffffffUL) << (va_bits - 1)
#define KERNEL_BASE_MIN 0xffff000008000000ul
#define KERNEL_BASE_MAX 0xfffffffff0000000ul

// 2MB aligned
// https://elixir.bootlin.com/linux/v5.15.12/source/arch/arm64/include/asm/boot.h
#define KERNEL_BASE_MASK 0x0ffffful

// TEXT_OFFSET was changed from 0x80000 to zero on 2020-04-15
// https://lore.kernel.org/all/20200428134119.GI6791@willie-the-truck/T/
#define TEXT_OFFSET 0

#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + TEXT_OFFSET)

/*
 * MIPS 64-bit (mips64el)
 * https://training.mips.com/basic_mips/PDF/Memory_Map.pdf
 */
#elif defined(__mips64) || defined (__mips64__)

#define KERNEL_VAS_START 0xffff000000000000ul

#define KERNEL_BASE_MIN 0xffffffff80000000ul
#define KERNEL_BASE_MAX 0xfffffffff0000000ul

#define KERNEL_BASE_MASK 0x0ffffful

// https://elixir.bootlin.com/linux/v5.15.12/source/arch/mips/kernel/head.S#L67
#define TEXT_OFFSET 0x400

#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + 0x100000ul + TEXT_OFFSET)

/*
 * x86 (i386)
 * https://elixir.bootlin.com/linux/latest/source/arch/x86/Kconfig
 * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/head_32.S
 */
#elif defined(__i386__)

// 3GB vmsplit (0xc0000000) is a common configuration
// for distro kernels non-embedded systems
#define KERNEL_VAS_START 0xc0000000ul

#define KERNEL_BASE_MIN 0xc0000000ul
#define KERNEL_BASE_MAX 0xf0000000ul

// 2MB aligned
#define KERNEL_BASE_MASK 0x0ffffful

#define TEXT_OFFSET 0
#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + TEXT_OFFSET)

/*
 * ARM 32-bit (arm6l / arm7l)
 * https://people.kernel.org/linusw/how-the-arm32-linux-kernel-decompresses
 * https://people.kernel.org/linusw/how-the-arm32-kernel-starts
 * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/arm/kernel/head.S
 */
#elif defined(__arm__) ||                                                      \
    defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__) ||                     \
    defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) ||                    \
    defined(__ARM_ARCH_6ZK__) || defined(__ARM_ARCH_6T2__) ||                  \
    defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) ||                     \
    defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) ||                    \
    defined(__ARM_ARCH_7S__)

// 3GB vmsplit (0xc0000000) is common; but an unsafe assumption,
// especially for embedded systems
#define KERNEL_VAS_START 0xc0000000ul

#define KERNEL_BASE_MIN 0xc0000000ul
#define KERNEL_BASE_MAX 0xf0000000ul

// 2MB aligned
#define KERNEL_BASE_MASK 0x0ffffful

#define TEXT_OFFSET 0x8000
#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + TEXT_OFFSET)

/*
 * MIPS 32-bit (mipsel)
 * https://elixir.bootlin.com/linux/v5.15.12/source/arch/mips/include/asm/mach-malta/spaces.h#L37
 * https://elixir.bootlin.com/linux/v5.15.12/source/arch/mips/include/asm/processor.h#L39
 * https://www.kernel.org/doc/Documentation/mips/booting.rst
 * https://training.mips.com/basic_mips/PDF/Memory_Map.pdf
 */
#elif defined(__mips__)

// kseg0: 0x80000000 - 0x9fffffff
#define KERNEL_VAS_START 0x80000000ul

#define KERNEL_BASE_MIN 0x80000000ul
#define KERNEL_BASE_MAX 0xf0000000ul

// page aligned (default CONFIG_PAGE_SIZE_4KB=y)
#define KERNEL_BASE_MASK 0x0ffful

// https://elixir.bootlin.com/linux/v5.15.12/source/arch/mips/kernel/head.S#L67
#define TEXT_OFFSET 0x400

#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + 0x100000ul + TEXT_OFFSET)

#else
#error "Unrecognised architecture!"
#endif
