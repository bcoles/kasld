// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: KASLR image ceiling (PRE_COLLECTION)
//
// Tightens ctx->text_base_max by eliminating positions where the kernel image
// would overflow past the top of the KASLR randomization region. The kernel's
// own placement code enforces this constraint at boot: positions where
// base + image_size > region_ceiling are never selected. The resulting
// forbidden band is always contiguous and always at the top of the range:
//
//   [KASLR_BASE_MAX - kernel_size, KASLR_BASE_MAX)
//
// After this plugin runs, the orchestrator syncs text_base_max back to
// layout.kernel_base_max and layout.kaslr_base_max (see
// run_pre_collection_inference() in orchestrator.c).
//
// kernel_size is estimated without privileges:
//   vmlinuz: stat("/boot/vmlinuz-$(uname -r)") — requires only execute
//            permission on /boot, not read on the file.
//   System.map: stat("/boot/System.map-$(uname -r)") — same access model.
//
// The estimate uses a ratio at the low end of the observed compression range
// to underestimate kernel_size: we only eliminate slots that are certainly
// in the forbidden band. Overestimating risks excluding the true kernel base
// from the candidate set.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <stdio.h>
#include <sys/stat.h>
#include <sys/utsname.h>

/* Low-end compression ratio: underestimates kernel_size so that only slots
 * certainly in the forbidden band are eliminated. Typical xz/gzip/lzma
 * ratio for init_size on x86 is 4–5×; using 3.5 stays below that floor. */
#define KASLR_CEILING_RATIO 3.5

/* Parameters for estimating kernel text size from System.map file size.
 * Format: ~43 bytes per line; ~87% of symbols are in the text section;
 * symbol density ~7 symbols/KiB. The multiplier converts text size to
 * init_size (data + bss + decompressor slack). */
#define SMAP_BYTES_PER_LINE 43UL
#define SMAP_TEXT_FRACTION 0.87
#define SMAP_SYMS_PER_KIB 7.0
#define SMAP_INIT_MULTIPLIER 2.0 /* low end of 2.0–2.5 range; underestimate */

/* stat() requires only execute permission on the parent directory, not read
 * permission on the file itself. */

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

/* Use the smaller of the two estimates: eliminates fewer slots but avoids
 * excluding valid positions. */
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

static void kaslr_ceiling_run(struct kasld_analysis_ctx *ctx) {
  unsigned long kernel_size = estimate_kernel_size();
  if (kernel_size == 0)
    return;

  /* Use compile-time arch constants, not the live ctx->arch values.
   * ctx->arch->kaslr_base_max is refreshed from layout each convergence
   * pass, so using it would re-apply the ceiling subtraction on an already-
   * tightened bound and fire multiple times. The ceiling is a one-shot
   * computation against the original KASLR window. */
  const unsigned long kaslr_max = KASLR_BASE_MAX;
  const unsigned long kaslr_min = KASLR_BASE_MIN;
  const unsigned long kaslr_align = KASLR_ALIGN;

  if (kernel_size < kaslr_max - kaslr_min) {
    /* Valid base range: [KASLR_BASE_MIN, KASLR_BASE_MAX - kernel_size].
     * Align down to the nearest slot boundary. */
    unsigned long new_max = (kaslr_max - kernel_size) & ~(kaslr_align - 1);
    if (new_max > kaslr_min && new_max < ctx->text_base_max) {
      fprintf(stderr,
              "[layout] text_base_max tightened by kaslr_ceiling:"
              " %#lx -> %#lx (kernel_size=%#lx)\n",
              ctx->text_base_max, new_max, kernel_size);
      ctx->text_base_max = new_max;
    }
  }

#if PHYS_VIRT_DECOUPLED
  const unsigned long phys_max = KASLR_PHYS_MAX;
  const unsigned long phys_min = KASLR_PHYS_MIN;
  const unsigned long phys_align = KASLR_PHYS_ALIGN;

  if (phys_max > phys_min && kernel_size < phys_max - phys_min) {
    unsigned long new_phys_max = (phys_max - kernel_size) & ~(phys_align - 1);
    if (new_phys_max > phys_min && new_phys_max < ctx->phys_base_max) {
      fprintf(stderr,
              "[layout] phys_base_max tightened by kaslr_ceiling:"
              " %#lx -> %#lx (kernel_size=%#lx)\n",
              ctx->phys_base_max, new_phys_max, kernel_size);
      ctx->phys_base_max = new_phys_max;
    }
  }
#endif
}

static const struct kasld_inference kaslr_ceiling = {
    .name = "kaslr_ceiling",
    .phase = KASLD_INFER_PHASE_PRE_COLLECTION,
    .run = kaslr_ceiling_run,
};

KASLD_REGISTER_INFERENCE(kaslr_ceiling);
