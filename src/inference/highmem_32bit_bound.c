// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: highmem LowTotal physical ceiling (POST_COLLECTION)
//
// On 32-bit kernels compiled with CONFIG_HIGHMEM, physical RAM is split into:
//   ZONE_NORMAL (lowmem): physical addresses linearly mapped below PAGE_OFFSET.
//   ZONE_HIGHMEM (highmem): physical addresses above the direct-map ceiling,
//     temporarily mapped via kmap()/pkmap().
//
// The kernel image itself must reside in lowmem — the decompressor, KASLR
// slot selection, and boot-time identity mapping all require a linearly mapped
// placement. So on highmem systems the kernel's physical base is bounded by
// LowTotal, not MemTotal.
//
// /proc/meminfo reports:
//   LowTotal: <N> kB    (lowmem = direct-mapped RAM; kernel can load here)
//   HighTotal: <N> kB   (highmem; kernel cannot load here)
//
// When HighTotal > 0: MemTotal > LowTotal, so the meminfo_phys_ceiling.c
// bound is too loose by exactly HighTotal. This plugin tightens it:
//
//   text_base_max = min(text_base_max,
//                       page_offset + LowTotal - MIN_IMAGE_SIZE + TEXT_OFFSET)
//
// When HighTotal == 0 (no highmem or field absent): LowTotal == MemTotal,
// meminfo_phys_ceiling already gives the tightest possible bound. This plugin
// is a no-op in that case.
//
// Applicable architectures: 32-bit coupled only (PHYS_VIRT_DECOUPLED == 0,
// sizeof(unsigned long) == 4). HighTotal/LowTotal are absent on 64-bit
// and on decoupled arches; the plugin is a no-op there (field not found).
// Concrete 32-bit arches with CONFIG_HIGHMEM:
//   - x86-32 (i386 / i686): highmem above ~896 MB (classic configuration)
//   - arm32: highmem above lowmem ceiling (~768 MB – 1 GiB depending on split)
//   - MIPS32: highmem above KSEG0 (32-bit MIPS with > ~512 MB RAM)
//   - PPC32: highmem above ~768 MB
//
// Phase: POST_COLLECTION — uses ctx->layout->page_offset (set by layout_adjust)
// so that the bound is computed against the runtime-detected PAGE_OFFSET, which
// matters for arches with a configurable vmsplit (x86-32, arm32) where the
// compile-time constant may differ from the actual boot configuration.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

/* Same conservative floor as meminfo_phys_ceiling.c — must never exclude the
 * true kernel base. The true image is always larger. */
#define MIN_IMAGE_SIZE (4UL * 1024 * 1024)

/* Read LowTotal and HighTotal from /proc/meminfo (in bytes).
 * Returns 0 in *lowtotal_out on any error or if the field is absent.
 * Returns 0 in *hightotal_out if the field is absent (treated as 0). */
static void read_lowmem_info(unsigned long *lowtotal_out,
                             unsigned long *hightotal_out) {
  *lowtotal_out = 0;
  *hightotal_out = 0;

  FILE *f = fopen("/proc/meminfo", "r");
  if (!f)
    return;

  char line[128];
  unsigned long long lo_kb = 0, hi_kb = 0;
  int found_lo = 0, found_hi = 0;

  while (fgets(line, sizeof(line), f)) {
    if (!found_lo && sscanf(line, "LowTotal: %llu kB", &lo_kb) == 1)
      found_lo = 1;
    if (!found_hi && sscanf(line, "HighTotal: %llu kB", &hi_kb) == 1)
      found_hi = 1;
    if (found_lo && found_hi)
      break;
  }

  fclose(f);

  unsigned long long lo_bytes = lo_kb * 1024ULL;
  unsigned long long hi_bytes = hi_kb * 1024ULL;

  *lowtotal_out = found_lo ? (lo_bytes > ULONG_MAX ? ULONG_MAX : (unsigned long)lo_bytes) : 0;
  *hightotal_out = found_hi ? (hi_bytes > ULONG_MAX ? ULONG_MAX : (unsigned long)hi_bytes) : 0;
}

static void highmem_32bit_bound_run(struct kasld_analysis_ctx *ctx) {
  /* Only meaningful on 32-bit coupled arches. On 64-bit hosts, LowTotal and
   * HighTotal are either absent or zero, so the plugin is harmlessly a no-op.
   * The sizeof guard makes the intent explicit. */
  if (sizeof(unsigned long) != 4)
    return;
  if (ctx->arch->phys_virt_decoupled)
    return;

  unsigned long lowtotal = 0, hightotal = 0;
  read_lowmem_info(&lowtotal, &hightotal);

  /* If HighTotal is absent or zero, no highmem — no tighter bound to apply.
   * meminfo_phys_ceiling already handles the MemTotal == LowTotal case. */
  if (hightotal == 0 || lowtotal == 0)
    return;

  if (lowtotal <= MIN_IMAGE_SIZE)
    return;

  /* Use the runtime page_offset (set by layout_adjust from collected results,
   * e.g. mmap-brute-vmsplit component). Falls back to compile-time default
   * when no runtime detection has occurred. */
  unsigned long page_offset = ctx->layout->page_offset;
  unsigned long text_offset = ctx->arch->text_offset;

  /* Guard against unsigned wraparound: page_offset + lowtotal must not exceed
   * ULONG_MAX. On a well-configured 32-bit system this cannot happen (the
   * kernel VAS ends at 0xffffffff and lowtotal < VAS size), but check anyway. */
  if (lowtotal > ULONG_MAX - page_offset)
    return;

  /* Ceiling: highest virtual text base compatible with a lowmem placement.
   *   phys_base ≤ LowTotal - MIN_IMAGE_SIZE
   *   text_base = page_offset + phys_base + text_offset
   *             ≤ page_offset + LowTotal - MIN_IMAGE_SIZE + text_offset */
  unsigned long virt_ceiling = page_offset + lowtotal - MIN_IMAGE_SIZE + text_offset;

  unsigned long kaslr_min = ctx->arch->kaslr_base_min;
  unsigned long kaslr_align = ctx->arch->kaslr_align;

  if (kaslr_align > 0 && virt_ceiling > kaslr_min)
    virt_ceiling &= ~(kaslr_align - 1);

  if (virt_ceiling > kaslr_min && virt_ceiling < ctx->text_base_max) {
    if (verbose && !quiet)
      fprintf(stderr,
              "[layout] text_base_max tightened by highmem_32bit_bound:"
              " %#lx -> %#lx (LowTotal=%lu kB, HighTotal=%lu kB)\n",
              ctx->text_base_max, virt_ceiling,
              lowtotal / 1024, hightotal / 1024);
    ctx->text_base_max = virt_ceiling;
  }
}

static const struct kasld_inference highmem_32bit_bound = {
    .name = "highmem_32bit_bound",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = highmem_32bit_bound_run,
};

KASLD_REGISTER_INFERENCE(highmem_32bit_bound);
