// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: riscv64 FDT kaslr-seed -> exact text_base (POST_COLLECTION)
//
// On riscv64 (v6.6+), the KASLR virtual offset is computed in
// arch/riscv/mm/init.c as:
//
//   kaslr_seed = get_kaslr_seed_dt(dtb_va);
//   if (IS_ENABLED(CONFIG_EFI))
//       kaslr_seed ^= efi_kaslr_seed;
//   if (!kaslr_seed) return;   // no KASLR
//   nr_pos = (PUD_SIZE - kernel_size) / PMD_SIZE;
//   virt_offset = (kaslr_seed % nr_pos) * PMD_SIZE;
//   text_base = KERNEL_LINK_ADDR + virt_offset
//
// The FDT /chosen/kaslr-seed property, readable from userspace at
// /proc/device-tree/chosen/kaslr-seed, is an 8-byte big-endian value.
//
// NOTE: seed-wiping on riscv64 is unverified. The comment in
// sysfs_devicetree_initrd.c suggests the kernel may zero this property after
// consuming it. A non-zero read indicates the seed was not wiped (or that
// wiping is not implemented); a zero value is treated as absent (no inference
// possible). Until verified on a real host, this plugin triggers only on
// non-zero content.
//
// Non-EFI systems only: on EFI-booted systems the combined seed is
// fdt_seed ^ efi_kaslr_seed; the FDT value alone does not reconstruct it.
//
// nr_pos derivation uses two paths in priority order:
//
//   1. Image header (preferred): open /boot/Image-$(uname -r) or
//      /boot/vmlinuz-$(uname -r). Check MZ magic (0x4d, 0x5a) at byte
//      offset 0; read image_size (u64 LE) at byte offset 16. This field
//      equals _end - _start (the exact kernel_size used in the formula).
//      If readable: exact nr_pos -> single candidate -> bilateral pin.
//
//   2. Gap fallback: gap = max(DATA results) - min(TEXT results) is a sound
//      lower bound on kernel_size. nr_pos_max = (PUD_SIZE - gap) / PMD_SIZE
//      >= true_nr_pos. Enumerate candidates for i in [1, nr_pos_max]; the
//      true text_base lies within the range of this set. Since i = 1 always
//      yields offset 0 (= KERNEL_LINK_ADDR = current text_base_min), only
//      text_base_max can be tightened by this path.
//
// Phase: POST_COLLECTION -- requires DATA/TEXT results for the gap fallback.
// Applicable: riscv64 only.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64

/* Read the 8-byte big-endian kaslr-seed FDT property.
 * Returns 0 on failure or if the content is all-zero bytes. */
static uint64_t read_fdt_kaslr_seed(void) {
  FILE *fp = fopen("/proc/device-tree/chosen/kaslr-seed", "rb");
  if (!fp)
    return 0;

  uint8_t buf[8] = {0};
  size_t n = fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  if (n != sizeof(buf))
    return 0;

  /* FDT property values are stored big-endian. */
  return ((uint64_t)buf[0] << 56) | ((uint64_t)buf[1] << 48) |
         ((uint64_t)buf[2] << 40) | ((uint64_t)buf[3] << 32) |
         ((uint64_t)buf[4] << 24) | ((uint64_t)buf[5] << 16) |
         ((uint64_t)buf[6] << 8) | ((uint64_t)buf[7]);
}

/* Open the kernel image and read image_size from its EFI/PE-style header.
 * Returns 0 if the image is absent, unreadable, or lacks the MZ header. */
static unsigned long read_image_size(const char *release) {
  const char *const paths[] = {
      "/boot/Image-%s",
      "/boot/vmlinuz-%s",
      NULL,
  };
  char path[PATH_MAX];
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

    /* MZ magic (0x4d 0x5a) at offset 0 confirms the EFI/PE-style header. */
    if (hdr[0] != 0x4d || hdr[1] != 0x5a)
      continue;

    /* image_size (u64 LE) at byte offset 16 == _end - _start. */
    uint64_t image_size =
        ((uint64_t)hdr[16]) | ((uint64_t)hdr[17] << 8) |
        ((uint64_t)hdr[18] << 16) | ((uint64_t)hdr[19] << 24) |
        ((uint64_t)hdr[20] << 32) | ((uint64_t)hdr[21] << 40) |
        ((uint64_t)hdr[22] << 48) | ((uint64_t)hdr[23] << 56);

    if (image_size == 0)
      continue;

    return (unsigned long)image_size;
  }

  return 0;
}

/* Returns gap = max(DATA results) - min(TEXT results), a lower bound on
 * kernel_size.  Returns 0 if insufficient results or inconsistent pair. */
static unsigned long get_text_data_gap(const struct kasld_analysis_ctx *ctx) {
  unsigned long min_text = ULONG_MAX;
  unsigned long max_data = 0;

  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (r->type != KASLD_ADDR_VIRT || !r->valid)
      continue;
    if (strcmp(r->section, KASLD_SECTION_TEXT) == 0) {
      if (r->raw < min_text)
        min_text = r->raw;
    } else if (strcmp(r->section, KASLD_SECTION_DATA) == 0) {
      if (r->raw > max_data)
        max_data = r->raw;
    }
  }

  if (min_text == ULONG_MAX || max_data == 0 || max_data <= min_text)
    return 0;

  return max_data - min_text;
}

#endif /* riscv64 */

static void riscv64_fdt_kaslr_seed_run(struct kasld_analysis_ctx *ctx) {
#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64
  const unsigned long pud_size = 1ul << 30; /* 1 GiB */
  const unsigned long pmd_size = 2ul * MB;  /* 2 MiB */

  /* Non-EFI only: on EFI boots the combined seed is fdt_seed ^ efi_seed;
   * the FDT value alone does not reconstruct it. */
  if (access("/sys/firmware/efi", F_OK) == 0)
    return;

  /* FDT not mounted: seed property inaccessible. */
  if (access("/proc/device-tree", F_OK) != 0)
    return;

  /* Seed property absent: handled by riscv64_no_seed_default. */
  if (access("/proc/device-tree/chosen/kaslr-seed", F_OK) != 0)
    return;

  uint64_t seed = read_fdt_kaslr_seed();

  /* seed == 0: KASLR was disabled, or the property was zeroed after boot
   * (seed-wiping ambiguity -- see header comment).  Skip in both cases. */
  if (seed == 0)
    return;

  /* --- Path 1: image header -- exact nr_pos -> bilateral pin --- */
  struct utsname uts;
  if (uname(&uts) == 0) {
    unsigned long image_size = read_image_size(uts.release);
    if (image_size > 0 && image_size < pud_size) {
      unsigned long nr_pos = (pud_size - image_size) / pmd_size;
      if (nr_pos > 0) {
        unsigned long virt_offset =
            (unsigned long)((seed % (uint64_t)nr_pos) * (uint64_t)pmd_size);
        unsigned long candidate = (unsigned long)KERNEL_LINK_ADDR + virt_offset;

        if (candidate >= ctx->text_base_min &&
            candidate <= ctx->text_base_max) {
          if (verbose && !quiet)
            fprintf(stdout,
                    "[infer] virt_text_base pinned by riscv64_fdt_kaslr_seed:"
                    " [%#lx, %#lx] -> %#lx"
                    " (seed=%#llx, nr_pos=%lu, image_size=%#lx)\n",
                    ctx->text_base_min, ctx->text_base_max, candidate,
                    (unsigned long long)seed, nr_pos, image_size);
          ctx->text_base_min = candidate;
          ctx->text_base_max = candidate;
          return;
        }
      }
    }
  }

  /* --- Path 2: gap fallback -- nr_pos upper bound -> tighten text_base_max ---
   */
  unsigned long gap = get_text_data_gap(ctx);
  if (gap == 0 || gap >= pud_size)
    return;

  unsigned long nr_pos_max = (pud_size - gap) / pmd_size;
  if (nr_pos_max == 0)
    return;

  /* Enumerate candidate text_base values for i in [1, nr_pos_max].
   * The true text_base appears at i = true_nr_pos; max_cand >= true text_base.
   * Only text_base_max can be tightened here (seed % 1 == 0 gives the minimum).
   */
  unsigned long max_cand = 0;
  for (unsigned long i = 1; i <= nr_pos_max; i++) {
    unsigned long cand =
        (unsigned long)KERNEL_LINK_ADDR +
        (unsigned long)((seed % (uint64_t)i) * (uint64_t)pmd_size);
    if (cand > max_cand)
      max_cand = cand;
  }

  if (max_cand > ctx->text_base_min && max_cand < ctx->text_base_max) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] virt_text_base_max tightened by riscv64_fdt_kaslr_seed"
              " (gap fallback): [%#lx, %#lx] -> [%#lx, %#lx]"
              " (seed=%#llx, nr_pos_max=%lu, gap=%#lx)\n",
              ctx->text_base_min, ctx->text_base_max, ctx->text_base_min,
              max_cand, (unsigned long long)seed, nr_pos_max, gap);
    ctx->text_base_max = max_cand;
  }

#else
  (void)ctx;
#endif /* riscv64 */
}

static const struct kasld_inference riscv64_fdt_kaslr_seed = {
    .name = "riscv64_fdt_kaslr_seed",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = riscv64_fdt_kaslr_seed_run,
};

KASLD_REGISTER_INFERENCE(riscv64_fdt_kaslr_seed);
