// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: forbidden lower slots from kernel image size
// (POST_COLLECTION)
//
// Both MIPS and LoongArch enforce a minimum KASLR offset:
//
//   offset &= (CONFIG_RANDOMIZE_BASE_MAX_OFFSET - 1);
//   if (offset < kernel_length)
//       offset += ALIGN(kernel_length, KERNEL_ALIGN);   // MIPS
//       // or, on LoongArch: offset = ALIGN(kernel_length, KERNEL_ALIGN)
//
// Any randomly-drawn offset in [0, kernel_length) is bumped upward. The
// range [0, kernel_length) is a forbidden zone: no valid text base falls
// in [KASLR_BASE_MIN, KASLR_BASE_MIN + kernel_length).
//
// Inference:
//   text_base_min = max(text_base_min, KASLR_BASE_MIN + kernel_length_estimate)
//
// kernel_length_estimate = max(DATA results) - min(TEXT results) — the same
// gap lower bound used by image_size_from_text_data_gap.c. Because it is a
// lower bound (true kernel size ≥ gap), raising text_base_min by gap is
// sound: the kernel cannot load within the forbidden zone, and the zone
// extends at least gap bytes from KASLR_BASE_MIN.
//
// LoongArch extension (see LoongArch H4):
//   When kernel_length ≥ CONFIG_RANDOMIZE_BASE_MAX_OFFSET, every offset
//   drawn from [0, max_offset) satisfies offset < kernel_length, so the
//   bump always fires. On LoongArch the bump is an assignment (not an
//   addition), making the result a single fixed value:
//
//     text_base = KASLR_BASE_MIN + ALIGN(kernel_length, KERNEL_ALIGN)
//
//   When kernel_length_estimate ≥ max_offset this plugin emits a verbose
//   diagnostic. A bilateral pin is not applied: the gap is a lower bound
//   (gap ≤ true kernel_length), so ALIGN(gap) ≤ ALIGN(true_kernel_length),
//   and setting text_base_max = KASLR_BASE_MIN + ALIGN(gap) could exclude
//   the true text base if gap underestimates by more than one KERNEL_ALIGN
//   step. Implementing the bilateral pin soundly requires exact kernel_length
//   (e.g. from /boot/Image header — see riscv64_fdt_kaslr_seed §6 for the
//   Image-header approach; a LoongArch variant is a future enhancement).
//
// Note: config_max_offset_bound (PRE_COLLECTION) sets
//   text_base_max = KASLR_BASE_MIN + max_offset.
// On LoongArch systems where kernel_length > max_offset the bump code places
// the kernel above this ceiling; config_max_offset_bound's bound is too
// tight in that case and may block the text_base_min raise below.
//
// Phase: POST_COLLECTION — requires TEXT and DATA results from components.
// Applicable: MIPS (32-bit and 64-bit), LoongArch.
// See MIPS H7, LoongArch H4.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

#if defined(__mips__) || defined(__loongarch__)

/* Compute kernel_length_estimate = max(DATA results) - min(TEXT results).
 * Returns 0 if insufficient results are present or the pair is inconsistent. */
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

#endif /* defined(__mips__) || defined(__loongarch__) */

#if defined(__loongarch__)

/* Open the kernel config file at well-known paths.
 * Mirrors the search order used by config_max_offset_bound.c. */
static FILE *open_boot_config(const char *release) {
  const char *fixed_paths[] = {"/boot/config", NULL};

  for (int i = 0; fixed_paths[i]; i++) {
    FILE *fp = fopen(fixed_paths[i], "r");
    if (fp)
      return fp;
  }

  const char *release_fmts[] = {
      "/boot/config-%s",
      "/lib/modules/%s/build/.config",
      "/lib/modules/%s/config",
      NULL,
  };

  char path[256];
  for (int i = 0; release_fmts[i]; i++) {
    snprintf(path, sizeof(path), release_fmts[i], release);
    FILE *fp = fopen(path, "r");
    if (fp)
      return fp;
  }

  return NULL;
}

/* Parse CONFIG_RANDOMIZE_BASE_MAX_OFFSET from an open config FILE*.
 * Returns the value, or 0 if absent or malformed. */
static unsigned long get_max_offset(FILE *fp) {
  const char *key = "CONFIG_RANDOMIZE_BASE_MAX_OFFSET=";
  const size_t keylen = strlen(key);
  char buf[256];

  while (fgets(buf, sizeof(buf), fp) != NULL) {
    if (strncmp(buf, key, keylen) == 0) {
      char *end;
      unsigned long val = strtoul(buf + keylen, &end, 0);
      if (end != buf + keylen && val > 0)
        return val;
    }
  }
  return 0;
}

#endif /* defined(__loongarch__) */

static void min_offset_from_image_size_run(struct kasld_analysis_ctx *ctx) {
#if defined(__mips__) || defined(__loongarch__)

  unsigned long gap = get_text_data_gap(ctx);
  if (!gap)
    return;

  unsigned long kaslr_min = ctx->arch->kaslr_base_min;
  unsigned long new_min = kaslr_min + gap;

  if (new_min > kaslr_min && new_min > ctx->text_base_min &&
      new_min < ctx->text_base_max) {
    if (verbose && !quiet)
      fprintf(stderr,
              "[layout] text_base_min raised by min_offset_from_image_size:"
              " %#lx -> %#lx (kernel_length_estimate=%#lx)\n",
              ctx->text_base_min, new_min, gap);
    ctx->text_base_min = new_min;
  }

#if defined(__loongarch__)
  /* LoongArch extension: when kernel_length >= max_offset the bump always
   * fires (assignment semantics), making KASLR deterministic. Log this
   * condition for awareness; a bilateral pin is not applied because gap is
   * a lower bound on the true kernel_length (see file header). */
  struct utsname uts;
  if (uname(&uts) == 0) {
    FILE *fp = open_boot_config(uts.release);
    if (fp) {
      unsigned long max_offset = get_max_offset(fp);
      fclose(fp);
      if (max_offset > 0 && gap >= max_offset) {
        unsigned long kaslr_align = ctx->arch->kaslr_align;
        unsigned long aligned_gap =
            kaslr_align > 0 ? (gap + kaslr_align - 1) & ~(kaslr_align - 1)
                            : gap;

        if (verbose && !quiet)
          fprintf(
              stderr,
              "[layout] min_offset_from_image_size: LoongArch KASLR"
              " deterministic (kernel_length_estimate=%#lx >= max_offset=%#lx);"
              " deterministic text_base >= %#lx;"
              " bilateral pin requires exact kernel_length\n",
              gap, max_offset, kaslr_min + aligned_gap);
      }
    }
  }
#endif /* defined(__loongarch__) */

#else
  (void)ctx;
#endif /* defined(__mips__) || defined(__loongarch__) */
}

static const struct kasld_inference min_offset_from_image_size = {
    .name = "min_offset_from_image_size",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = min_offset_from_image_size_run,
};

KASLD_REGISTER_INFERENCE(min_offset_from_image_size);
