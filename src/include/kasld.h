// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Expected kernel address space values for supported architectures.
//
// - KERNEL_VAS_START:    Expected virtual address for start of the kernel
//                        virtual address space (VAS).
//                        (eg. 0xc0000000 for 32-bit systems with 3GB vmsplit)
//
// - KERNEL_VAS_END:      Expected end of kernel virtual address space.
//                        (including modules, I/O, guard regions, ...)
//
// - KERNEL_BASE_MIN:     Expected minimum possible kernel base virtual address.
//
// - KERNEL_BASE_MAX:     Expected maximum possible kernel base virtual address.
//
// - MODULES_START:       Expected start virtual address for kernel modules.
//
// - MODULES_END:         Expected end virtual address for kernel modules.
//
// - KERNEL_ALIGN:        Expected kernel address alignment.
//                        (usually 2MiB on modern systems)
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

#define MB 0x100000ul
#define GB 0x40000000ul

#if defined(__x86_64__) || defined(__amd64__)
#include "kasld/x86_64.h"
#elif defined(__i386__)
#include "kasld/x86_32.h"
#elif defined(__aarch64__)
#include "kasld/arm64.h"
#elif defined(__arm__) || defined(__ARM_ARCH_6__) ||                           \
    defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) ||                    \
    defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__) ||                   \
    defined(__ARM_ARCH_6T2__) || defined(__ARM_ARCH_7__) ||                    \
    defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) ||                    \
    defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
#include "kasld/arm32.h"
#elif defined(__mips64) || defined(__mips64__)
#include "kasld/mips64.h"
#elif defined(__mips__)
#include "kasld/mips32.h"
#elif defined(__powerpc64__) || defined(__POWERPC64__) ||                      \
    defined(__ppc64__) || defined(__PPC64__)
#include "kasld/ppc64.h"
#elif defined(__powerpc__) || defined(__POWERPC__) || defined(__ppc__) ||      \
    defined(__PPC__)
#include "kasld/ppc32.h"
#elif (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64
#include "kasld/riscv64.h"
#elif (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 32
#include "kasld/riscv32.h"
#elif defined(__loongarch__) && __loongarch_grlen == 64
#include "kasld/loongarch64.h"
#elif defined(__s390__) || defined(__s390x__) || defined(__370__) ||           \
    defined(__zarch__)
#include "kasld/s390.h"
#elif defined(__sparc__)
#include "kasld/sparc.h"
#else
#error "Unrecognised architecture!"
#endif

/* -----------------------------------------------------------------------------
 * Sanity check configured values
 * -----------------------------------------------------------------------------
 */
#if KERNEL_VAS_START > KERNEL_VAS_END
#error "Defined KERNEL_VAS_START is larger than KERNEL_VAS_END"
#endif

#if KERNEL_VAS_START > KERNEL_BASE_MIN
#error "Defined KERNEL_VAS_START is larger than KERNEL_BASE_MIN"
#endif

#if KERNEL_BASE_MAX > KERNEL_VAS_END
#error "Defined KERNEL_BASE_MAX is larger than KERNEL_VAS_END"
#endif

#if KERNEL_TEXT_DEFAULT > KERNEL_BASE_MAX
#error "Generated KERNEL_TEXT_DEFAULT is larger than KERNEL_BASE_MAX"
#endif

#if KERNEL_TEXT_DEFAULT < KERNEL_BASE_MIN
#error "Generated KERNEL_TEXT_DEFAULT is smaller than KERNEL_BASE_MIN"
#endif
