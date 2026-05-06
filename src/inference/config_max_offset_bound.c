// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: CONFIG_RANDOMIZE_BASE_MAX_OFFSET ceiling (PRE_COLLECTION)
//
// On LoongArch and MIPS, the KASLR code masks the random offset:
//
//   offset &= CONFIG_RANDOMIZE_BASE_MAX_OFFSET - 1;
//
// so the kernel text base falls in [KASLR_BASE_MIN, KASLR_BASE_MIN +
// max_offset). Reading this option from the boot config tightens text_base_max:
//
//   text_base_max = min(text_base_max, ctx->text_base_min + max_offset)
//
// LoongArch default: CONFIG_RANDOMIZE_BASE_MAX_OFFSET = 0x01000000 (16 MiB).
// Default KASLR window without this plugin: 4 GiB (0x100000000 / KERNEL_ALIGN).
// With 16 MiB max_offset: 256 slots (256 × 64 KiB). A 256× reduction.
//
// MIPS: same masking pattern; CONFIG_RANDOMIZE_BASE_MAX_OFFSET default is
// arch/mips/Kconfig-defined. MIPS64 KASLR is not deployed in production
// (MIPS H6 confirmed), so LoongArch is the primary target in practice.
//
// If the config file is unreadable or the option is absent, this plugin is a
// no-op. The plugin is naturally a no-op on architectures that do not set
// CONFIG_RANDOMIZE_BASE_MAX_OFFSET (x86, arm64, riscv64, s390).
//
// Phase: PRE_COLLECTION — runs before any component.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

/* Open the kernel config file at well-known paths, trying the release-specific
 * path before generic fallbacks. Returns an open FILE* or NULL.
 * Mirrors the search order used by boot-config.c. */
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

/* Parse CONFIG_RANDOMIZE_BASE_MAX_OFFSET=<hex> from an open config FILE*.
 * Returns the value, or 0 if absent or malformed. */
static unsigned long get_max_offset(FILE *fp) {
  const char *key = "CONFIG_RANDOMIZE_BASE_MAX_OFFSET=";
  const size_t keylen = strlen(key);
  char buf[256];

  rewind(fp);
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

static void config_max_offset_bound_run(struct kasld_analysis_ctx *ctx) {
  struct utsname uts;
  if (uname(&uts) != 0)
    return;

  FILE *fp = open_boot_config(uts.release);
  if (!fp)
    return;

  unsigned long max_offset = get_max_offset(fp);
  fclose(fp);

  if (max_offset == 0)
    return;

  /* At PRE_COLLECTION, ctx->text_base_min == KASLR_BASE_MIN (the first valid
   * slot). The KASLR offset is drawn from [0, max_offset), so the last valid
   * text base is KASLR_BASE_MIN + max_offset - kaslr_align, and the exclusive
   * upper bound is KASLR_BASE_MIN + max_offset. */
  unsigned long new_max = ctx->text_base_min + max_offset;

  if (new_max > ctx->text_base_min && new_max < ctx->text_base_max) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] text_base_max tightened by config_max_offset_bound:"
              " %#lx -> %#lx (CONFIG_RANDOMIZE_BASE_MAX_OFFSET=%#lx)\n",
              ctx->text_base_max, new_max, max_offset);
    ctx->text_base_max = new_max;
  }
}

static const struct kasld_inference config_max_offset_bound = {
    .name = "config_max_offset_bound",
    .phase = KASLD_INFER_PHASE_PRE_COLLECTION,
    .run = config_max_offset_bound_run,
};

KASLD_REGISTER_INFERENCE(config_max_offset_bound);
