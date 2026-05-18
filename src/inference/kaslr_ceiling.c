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

#include "../include/kasld/inference.h"

#include <stdint.h>
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

/* Minimum plausible file sizes. A real compressed vmlinuz is always several
 * MiB; a real System.map always contains thousands of symbol lines. Reject
 * tiny stub files, placeholder symlinks, and partial downloads that would
 * produce wildly wrong kernel-size estimates. */
#define MIN_VMLINUZ_BYTES (512UL * 1024)
#define MIN_SYSMAP_BYTES (256UL * 1024)

/* stat() requires only execute permission on the parent directory, not read
 * permission on the file itself. */

/* Read exact image_size from an EFI/PE-style Image header (riscv64, arm64).
 * The header layout (arch/riscv/include/asm/image.h,
 * arch/arm64/include/asm/image.h) places image_size as a u64 LE field at
 * byte offset 16, preceded by MZ magic at offset 0. Returns 0 on failure. */
static unsigned long estimate_from_image_header(const char *release) {
  const char *const paths[] = {
      "/boot/Image-%s",
      "/boot/vmlinuz-%s",
      NULL,
  };
  char path[256];
  uint8_t hdr[24];

  for (int i = 0; paths[i] != NULL; i++) {
    snprintf(path, sizeof(path), paths[i], release);
    FILE *fp = fopen(path, "rb");
    if (!fp)
      continue;
    size_t n = fread(hdr, 1, sizeof(hdr), fp);
    fclose(fp);

    if (n < sizeof(hdr))
      continue;
    if (hdr[0] != 0x4d || hdr[1] != 0x5a)
      continue;

    uint64_t image_size =
        ((uint64_t)hdr[16]) | ((uint64_t)hdr[17] << 8) |
        ((uint64_t)hdr[18] << 16) | ((uint64_t)hdr[19] << 24) |
        ((uint64_t)hdr[20] << 32) | ((uint64_t)hdr[21] << 40) |
        ((uint64_t)hdr[22] << 48) | ((uint64_t)hdr[23] << 56);

    if (image_size < MIN_VMLINUZ_BYTES)
      continue;

    return (unsigned long)image_size;
  }
  return 0;
}

static unsigned long estimate_from_vmlinuz(const char *release) {
  char path[256];
  struct stat st;
  snprintf(path, sizeof(path), "/boot/vmlinuz-%s", release);
  if (stat(path, &st) != 0)
    return 0;
  if ((unsigned long)st.st_size < MIN_VMLINUZ_BYTES)
    return 0;
  return (unsigned long)((double)st.st_size * KASLR_CEILING_RATIO);
}

static unsigned long estimate_from_sysmap(const char *release) {
  char path[256];
  struct stat st;
  snprintf(path, sizeof(path), "/boot/System.map-%s", release);
  if (stat(path, &st) != 0)
    return 0;
  if ((unsigned long)st.st_size < MIN_SYSMAP_BYTES)
    return 0;
  unsigned long lines = (unsigned long)st.st_size / SMAP_BYTES_PER_LINE;
  double text_syms = (double)lines * SMAP_TEXT_FRACTION;
  double text_kib = text_syms / SMAP_SYMS_PER_KIB;
  return (unsigned long)(text_kib * 1024.0 * SMAP_INIT_MULTIPLIER);
}

/* Use the most accurate available estimate. Image header gives the exact
 * decompressed size (no ratio needed); vmlinuz and System.map are fallbacks
 * with underestimating ratios to avoid excluding valid positions.
 *
 * Cross-check: vmlinuz and sysmap estimates are intentional lower bounds.
 * If the header-derived value falls below either lower bound it is
 * inconsistent — a sign of a misidentified file or a non-standard PE layout —
 * and is discarded. */
static unsigned long estimate_kernel_size(void) {
  struct utsname uts;
  if (uname(&uts) != 0)
    return 0;

  unsigned long from_hdr = estimate_from_image_header(uts.release);
  unsigned long vmlinuz = estimate_from_vmlinuz(uts.release);
  unsigned long sysmap = estimate_from_sysmap(uts.release);

  /* Discard the header value if it falls below a known lower bound. */
  if (from_hdr > 0 && ((vmlinuz > 0 && from_hdr < vmlinuz) ||
                       (sysmap > 0 && from_hdr < sysmap)))
    from_hdr = 0;

  if (from_hdr)
    return from_hdr;

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
      if (verbose && !quiet)
        fprintf(stdout,
                "[infer] virt_text_base_max tightened by kaslr_ceiling:"
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
      if (verbose && !quiet)
        fprintf(stdout,
                "[infer] phys_base_max tightened by kaslr_ceiling:"
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
