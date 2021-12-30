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

#define KERNEL_BASE_MIN 0xffffffff80000000ul
#define KERNEL_BASE_MAX 0xffffffffff000000ul

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

// page_offset = (0xffffffffffffffffUL) << (va_bits - 1)
// 48 va bits (0xffff800000000000) is a common configuration
// (CONFIG_ARM64_PA_BITS_48=y)
#define KERNEL_BASE_MIN 0xffff800000000000ul
#define KERNEL_BASE_MAX 0xffffffff00000000ul

// 2MB aligned
// https://elixir.bootlin.com/linux/v5.15.12/source/arch/arm64/include/asm/boot.h
#define KERNEL_BASE_MASK 0x0ffffful

// TEXT_OFFSET was changed from 0x80000 to zero on 2020-04-15
// https://lore.kernel.org/all/20200428134119.GI6791@willie-the-truck/T/
#define TEXT_OFFSET 0

#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + TEXT_OFFSET)

/*
 * x86 (i386)
 * https://elixir.bootlin.com/linux/latest/source/arch/x86/Kconfig
 * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/head_32.S
 */
#elif defined(__i386__)

// 3GB vmsplit (0xc0000000) is a common configuration
// for distro kernels non-embedded systems
#define KERNEL_BASE_MIN 0xc0000000ul
#define KERNEL_BASE_MAX 0xff000000ul

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
#elif defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__) ||                   \
    defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) ||                    \
    defined(__ARM_ARCH_6ZK__) || defined(__ARM_ARCH_6T2__) ||                  \
    defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) ||                     \
    defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) ||                    \
    defined(__ARM_ARCH_7S__)

// 3GB vmsplit (0xc0000000) is common; but an unsafe assumption,
// especially for embedded systems
#define KERNEL_BASE_MIN 0xc0000000ul
#define KERNEL_BASE_MAX 0xff000000ul

// 2MB aligned
#define KERNEL_BASE_MASK 0x0ffffful

#define TEXT_OFFSET 0x8000
#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + TEXT_OFFSET)

#else
#error "Unrecognised architecture!"
#endif
