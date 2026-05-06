// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: DRAM ceiling → text_base_max (POST_COLLECTION)
//
// Complements dram_bound.c (which raises text_base_min from the minimum
// observed PHYS/DRAM address) by lowering text_base_max from the maximum
// observed physical RAM top.
//
// Constraint: the kernel image must fit entirely within physical RAM:
//
//   phys_base + kernel_size ≤ dram_top
//   phys_base              ≤ dram_top − kernel_size
//
// On coupled architectures (PHYS_VIRT_DECOUPLED == 0), virtual and physical
// are linked via phys_to_virt(), so the physical ceiling translates directly
// to a virtual text ceiling:
//
//   text_base_max = min(text_base_max,
//                       align_down(phys_to_virt(dram_top − kernel_size)
//                                  + TEXT_OFFSET, kaslr_align))
//
// dram_top is the maximum PHYS/DRAM address tagged KASLD_REGION_RAM_TOP
// across all collected results. Components that emit RAM_TOP include
// dmesg_last_pfn, sysfs_firmware_memmap, proc-zoneinfo, dmesg_node_data, and
// sysfs_devicetree_memory. On systems with a single contiguous RAM region the
// maximum RAM_TOP equals the true physical RAM ceiling.
//
// kernel_size uses the same conservative estimate as kaslr_ceiling.c:
//   vmlinuz: stat("/boot/vmlinuz-$(uname -r)") × 3.5 (low compression ratio)
//   System.map: symbol-density heuristic (low-end multiplier)
//   Final value: min(vmlinuz, sysmap) — whichever is smaller; no estimate
//   is used if neither file is accessible.
//
// On decoupled arches (x86-64, arm64, riscv64, s390), meminfo_phys_ceiling.c
// already derives a physical ceiling from MemTotal. This plugin is a no-op on
// those arches (#else branch).
//
// Applicable: x86-32, MIPS32, MIPS64, PPC32 BookE, LoongArch.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#if !PHYS_VIRT_DECOUPLED

/* Low-end compression ratio — same as kaslr_ceiling.c. Underestimates
 * kernel_size so that only slots certainly above the ceiling are excluded. */
#define KASLR_CEILING_RATIO 3.5

#define SMAP_BYTES_PER_LINE 43UL
#define SMAP_TEXT_FRACTION 0.87
#define SMAP_SYMS_PER_KIB 7.0
#define SMAP_INIT_MULTIPLIER 2.0

static unsigned long estimate_from_vmlinuz(const char *release) {
  char path[256];
  struct stat st;
  snprintf(path, sizeof(path), "/boot/vmlinuz-%s", release);
  if (stat(path, &st) != 0)
    return 0;
  return (unsigned long)((double)st.st_size * KASLR_CEILING_RATIO);
}

static unsigned long estimate_from_sysmap(const char *release) {
  char path[256];
  struct stat st;
  snprintf(path, sizeof(path), "/boot/System.map-%s", release);
  if (stat(path, &st) != 0)
    return 0;
  unsigned long lines = (unsigned long)st.st_size / SMAP_BYTES_PER_LINE;
  double text_syms = (double)lines * SMAP_TEXT_FRACTION;
  double text_kib = text_syms / SMAP_SYMS_PER_KIB;
  return (unsigned long)(text_kib * 1024.0 * SMAP_INIT_MULTIPLIER);
}

static unsigned long estimate_kernel_size(void) {
  struct utsname uts;
  if (uname(&uts) != 0)
    return 0;
  unsigned long vmlinuz = estimate_from_vmlinuz(uts.release);
  unsigned long sysmap = estimate_from_sysmap(uts.release);
  if (vmlinuz == 0 && sysmap == 0)
    return 0;
  if (vmlinuz == 0)
    return sysmap;
  if (sysmap == 0)
    return vmlinuz;
  return vmlinuz < sysmap ? vmlinuz : sysmap;
}

#endif /* !PHYS_VIRT_DECOUPLED */

static void dram_ceiling_run(struct kasld_analysis_ctx *ctx) {
#if !PHYS_VIRT_DECOUPLED

  /* Find the maximum PHYS/DRAM address explicitly tagged as a RAM region top.
   * Arbitrary DRAM addresses (initrd, CMA base, etc.) do not bound the RAM
   * ceiling and are therefore excluded. */
  unsigned long dram_top = 0;
  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (r->type != KASLD_ADDR_PHYS ||
        strcmp(r->section, KASLD_SECTION_DRAM) != 0 ||
        strcmp(r->region, KASLD_REGION_RAM_TOP) != 0)
      continue;
    if (r->raw > dram_top)
      dram_top = r->raw;
  }

  if (!dram_top)
    return;

  unsigned long kernel_size = estimate_kernel_size();
  if (!kernel_size)
    return;

  unsigned long phys_offset = ctx->arch->phys_offset;
  unsigned long page_offset = ctx->layout->page_offset;
  unsigned long text_offset = ctx->arch->text_offset;
  unsigned long kaslr_align = ctx->arch->kaslr_align;
  unsigned long kaslr_min = ctx->arch->kaslr_base_min;

  /* Guard against underflow in the subtraction. */
  if (dram_top <= phys_offset || dram_top - phys_offset <= kernel_size)
    return;

  /* phys_ceiling = dram_top - kernel_size.
   * virt_ceiling = phys_to_virt(phys_ceiling) + TEXT_OFFSET
   *              = (phys_ceiling - phys_offset) + page_offset + text_offset.
   * Align DOWN: the slot boundary at or below virt_ceiling is the last slot
   * that fits entirely within RAM; rounding down keeps the bound sound. */
  unsigned long phys_ceiling = dram_top - kernel_size;
  unsigned long virt_ceiling =
      (phys_ceiling - phys_offset + page_offset + text_offset) &
      ~(kaslr_align - 1);

  if (virt_ceiling > kaslr_min && virt_ceiling < ctx->text_base_max) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] text_base_max tightened by dram_ceiling:"
              " %#lx -> %#lx (dram_top=%#lx kernel_size=%#lx)\n",
              ctx->text_base_max, virt_ceiling, dram_top, kernel_size);
    ctx->text_base_max = virt_ceiling;
  }

#else
  (void)ctx;
#endif /* !PHYS_VIRT_DECOUPLED */
}

static const struct kasld_inference dram_ceiling = {
    .name = "dram_ceiling",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = dram_ceiling_run,
};

KASLD_REGISTER_INFERENCE(dram_ceiling);
