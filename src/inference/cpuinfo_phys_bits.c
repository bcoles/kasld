// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: CPU physical address bits → physical ceiling
// (PRE_COLLECTION)
//
// On x86-64 and LoongArch, /proc/cpuinfo exposes the CPU's maximum physical
// address width ("address sizes" / "Address Sizes"), giving an architectural
// upper bound on the physical address space independent of installed RAM. The
// kernel cannot be placed at a physical address where the image extends beyond
// that space:
//
//   phys_base + kernel_size ≤ (1UL << phys_bits)
//   phys_base ≤ (1UL << phys_bits) - MIN_IMAGE_SIZE
//
// On decoupled architectures (x86-64): tighten phys_base_max directly:
//
//   phys_base_max = min(phys_base_max, (1UL << phys_bits) - MIN_IMAGE_SIZE)
//
// On coupled architectures (LoongArch): convert to a virtual ceiling using
// the arch's phys_to_virt() formula (text_base = phys_to_virt(phys_base) +
// TEXT_OFFSET) and tighten text_base_max:
//
//   text_base_max = min(text_base_max,
//       PAGE_OFFSET + TEXT_OFFSET + (1UL << phys_bits) - MIN_IMAGE_SIZE
//       - PHYS_OFFSET)
//
// On architectures that do not expose "address sizes" in /proc/cpuinfo
// (arm64, riscv64, MIPS, ...) the file scan finds no match and the plugin
// is a no-op.
//
// This complements meminfo_phys_ceiling (MemTotal-based, runtime) and
// kaslr_ceiling (KASLR window / image-size based). The phys_bits value may
// be artificially restricted by a hypervisor below installed RAM, providing
// a tighter constraint than MemTotal on VMs with a restricted guest PA space.
//
// Phase: PRE_COLLECTION — phys_bits is a static CPU property readable before
// any component runs. Uses compile-time PAGE_OFFSET (ctx->arch->page_offset)
// for the coupled branch: layout_adjust has not run yet, and on LoongArch
// PAGE_OFFSET is a fixed hardware constant anyway.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <stdio.h>
#include <string.h>

/* See meminfo_phys_ceiling.c for rationale. */
#define MIN_IMAGE_SIZE (4UL * 1024 * 1024)

/* Read physical address bits from /proc/cpuinfo "address sizes" field.
 * Handles x86-64 ("address sizes\t: N bits physical, M bits virtual") and
 * LoongArch ("Address Sizes\t\t: N bits physical, M bits virtual").
 * Returns 0 on failure or if the field is absent. */
static int read_phys_bits(void) {
  FILE *f = fopen("/proc/cpuinfo", "r");
  if (!f)
    return 0;

  char line[256];
  int phys_bits = 0;

  while (fgets(line, sizeof(line), f)) {
    /* Match both x86-64 ("address sizes") and LoongArch ("Address Sizes").
     * Only the first matching line is used; all CPUs on a shared die report
     * the same phys_bits. */
    if (strncmp(line, "address sizes", 13) != 0 &&
        strncmp(line, "Address Sizes", 13) != 0)
      continue;

    /* Skip the key and the ": " separator. */
    char *colon = strchr(line, ':');
    if (!colon)
      continue;

    if (sscanf(colon + 1, " %d bits physical", &phys_bits) == 1)
      break;

    phys_bits = 0; /* malformed line; keep scanning */
  }

  fclose(f);
  return phys_bits;
}

static void cpuinfo_phys_bits_run(struct kasld_analysis_ctx *ctx) {
  int phys_bits = read_phys_bits();

  /* phys_bits=0: field absent (arch not supported).
   * phys_bits >= width(unsigned long): 1UL << phys_bits is undefined behaviour.
   * Use sizeof to derive the actual shift limit so 32-bit builds are safe
   * (e.g. x86-32 with PAE reports phys_bits=36, which would overflow a
   * 32-bit unsigned long if the magic constant 64 were used). */
  if (phys_bits <= 0 || phys_bits >= (int)(sizeof(unsigned long) * 8))
    return;

  /* Architectural physical address ceiling: all physical addresses are in
   * [0, (1UL << phys_bits) - 1]. The kernel image must fit within this
   * space, so the highest valid phys_base is phys_ceiling - MIN_IMAGE_SIZE. */
  unsigned long phys_ceiling = 1UL << phys_bits;
  if (phys_ceiling <= MIN_IMAGE_SIZE)
    return;

  if (ctx->arch->phys_virt_decoupled) {
    /* Decoupled: tighten the physical KASLR ceiling directly. */
    unsigned long ceiling = phys_ceiling - MIN_IMAGE_SIZE;

    unsigned long phys_min = ctx->arch->phys_kaslr_base_min;
    unsigned long phys_align = ctx->arch->phys_kaslr_align;

    if (ceiling > phys_min && phys_align > 0)
      ceiling &= ~(phys_align - 1);

    if (ceiling > phys_min && ceiling < ctx->phys_base_max) {
      if (verbose && !quiet)
        fprintf(stdout,
                "[infer] phys_base_max tightened by cpuinfo_phys_bits:"
                " %#lx -> %#lx (phys_bits=%d)\n",
                ctx->phys_base_max, ceiling, phys_bits);
      ctx->phys_base_max = ceiling;
    }
  } else {
    /* Coupled: text_base = phys_to_virt(phys_base) + TEXT_OFFSET
     *        = page_offset + (phys_base - PHYS_OFFSET) + text_offset.
     * Substituting phys_base ≤ phys_ceiling - MIN_IMAGE_SIZE:
     *   text_base ≤ page_offset + text_offset
     *               + (phys_ceiling - MIN_IMAGE_SIZE) - PHYS_OFFSET.
     * Use compile-time page_offset: layout_adjust has not run yet, and
     * PAGE_OFFSET is hardware-fixed on all coupled arches that expose
     * phys_bits (LoongArch DMW). */
    unsigned long page_offset = ctx->arch->page_offset;
    unsigned long text_offset = ctx->arch->text_offset;
    unsigned long phys_offset = ctx->arch->phys_offset;
    unsigned long virt_ceiling = page_offset + text_offset +
                                 (phys_ceiling - MIN_IMAGE_SIZE) - phys_offset;

    unsigned long kaslr_min = ctx->arch->kaslr_base_min;
    unsigned long kaslr_align = ctx->arch->kaslr_align;

    if (virt_ceiling > kaslr_min && kaslr_align > 0)
      virt_ceiling &= ~(kaslr_align - 1);

    if (virt_ceiling > kaslr_min && virt_ceiling < ctx->text_base_max) {
      if (verbose && !quiet)
        fprintf(stdout,
                "[infer] text_base_max tightened by cpuinfo_phys_bits:"
                " %#lx -> %#lx (phys_bits=%d)\n",
                ctx->text_base_max, virt_ceiling, phys_bits);
      ctx->text_base_max = virt_ceiling;
    }
  }
}

static const struct kasld_inference cpuinfo_phys_bits = {
    .name = "cpuinfo_phys_bits",
    .phase = KASLD_INFER_PHASE_PRE_COLLECTION,
    .run = cpuinfo_phys_bits_run,
};

KASLD_REGISTER_INFERENCE(cpuinfo_phys_bits);
