// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: initrd physical interval → forbidden zone for kernel
// placement (POST_COLLECTION)
//
// The bootloader-supplied initrd occupies a contiguous physical range
// [initrd_start, initrd_end). The early kernel-placement code registers this
// region as a forbidden interval and will not select a slot whose
// [base, base + image_size) overlaps it. Any collected PHYS result tagged as
// a kernel text/data address (i.e. KASLD_SECTION_TEXT or KASLD_SECTION_DATA)
// that lands inside this interval is therefore misclassified.
//
// Source of the initrd interval:
//
//   x86-64: /sys/kernel/boot_params/data
//     hdr.ramdisk_image      u32 LE @ boot_params+0x218 (low 32 bits of phys)
//     ext_ramdisk_image      u32 LE @ boot_params+0x0c0 (high 32 bits)
//     hdr.ramdisk_size       u32 LE @ boot_params+0x21c (low 32 bits of size)
//     ext_ramdisk_size       u32 LE @ boot_params+0x0c4 (high 32 bits)
//     Registered in arch/x86/boot/compressed/kaslr.c as MEM_AVOID_INITRD.
//
//   Device-tree arches (arm64, riscv64, ppc-DT, ...):
//     /sys/firmware/devicetree/base/chosen/linux,initrd-start (BE 4 or 8 B)
//     /sys/firmware/devicetree/base/chosen/linux,initrd-end   (BE 4 or 8 B)
//     The DT chosen node persists post-boot; properties are 0444.
//
// Inference: walk results[] and invalidate any VALID result with
//   type == PHYS && section ∈ {text, data} && initrd_start ≤ raw < initrd_end.
//
// Distinct from the existing sysfs_devicetree_initrd.c component, which emits
// the initrd start/end as PHYS/DRAM `KASLD_REGION_INITRD` *witnesses* (DRAM
// floor signal). This plugin uses the same data orthogonally — as an
// interval-exclusion for kernel-base candidates.
//
// Phase: POST_COLLECTION — needs collected PHYS/TEXT or PHYS/DATA results.
// Cross-arch: x86-64 path + DT-arch path; gracefully no-op when neither
// source is available.
//
// Note: only PHYS results are checked. On coupled arches a future extension
// could project the interval into virtual space (V = phys_to_virt(P)) and
// invalidate VIRT/TEXT results similarly; deferred to keep the first cut
// simple and the soundness obvious.
//
// References:
//   arch/x86/boot/compressed/kaslr.c (MEM_AVOID_INITRD registration)
//   arch/x86/include/uapi/asm/bootparam.h (boot_params layout)
//   drivers/of/fdt.c (initrd FDT chosen node parsing)
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define BOOT_PARAMS_PATH "/sys/kernel/boot_params/data"

/* boot_params field offsets (x86 boot protocol). hdr is at offset 0x1f1. */
#define OFF_EXT_RAMDISK_IMAGE 0x0c0ul
#define OFF_EXT_RAMDISK_SIZE 0x0c4ul
#define OFF_RAMDISK_IMAGE 0x218ul
#define OFF_RAMDISK_SIZE 0x21cul

/* Read a u32 LE at offset off from path. Returns -1 on failure. */
static int read_u32_at(const char *path, off_t off, uint32_t *out) {
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return -1;
  ssize_t n = pread(fd, out, sizeof(*out), off);
  close(fd);
  return (n == (ssize_t)sizeof(*out)) ? 0 : -1;
}

/* Read a 4- or 8-byte big-endian property from a sysfs file. */
static int read_be_addr(const char *path, unsigned long *out) {
  uint8_t buf[8];
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return -1;
  ssize_t n = read(fd, buf, sizeof(buf));
  close(fd);

  if (n == 8) {
    *out = ((unsigned long)buf[0] << 56) | ((unsigned long)buf[1] << 48) |
           ((unsigned long)buf[2] << 40) | ((unsigned long)buf[3] << 32) |
           ((unsigned long)buf[4] << 24) | ((unsigned long)buf[5] << 16) |
           ((unsigned long)buf[6] << 8) | ((unsigned long)buf[7]);
    return 0;
  }
  if (n == 4) {
    *out = ((unsigned long)buf[0] << 24) | ((unsigned long)buf[1] << 16) |
           ((unsigned long)buf[2] << 8) | ((unsigned long)buf[3]);
    return 0;
  }
  return -1;
}

/* Populate [start, end) of the initrd from x86 boot_params. Returns 0 on
 * success, -1 when the boot_params file is unavailable or no initrd was
 * loaded (size == 0). */
static int read_initrd_x86(unsigned long *start, unsigned long *end) {
#if defined(__x86_64__) || defined(__i386__)
  uint32_t lo_img = 0, hi_img = 0, lo_sz = 0, hi_sz = 0;
  if (read_u32_at(BOOT_PARAMS_PATH, OFF_RAMDISK_IMAGE, &lo_img) != 0)
    return -1;
  /* The ext_* fields exist in modern boot_params; absence is non-fatal. */
  (void)read_u32_at(BOOT_PARAMS_PATH, OFF_EXT_RAMDISK_IMAGE, &hi_img);
  if (read_u32_at(BOOT_PARAMS_PATH, OFF_RAMDISK_SIZE, &lo_sz) != 0)
    return -1;
  (void)read_u32_at(BOOT_PARAMS_PATH, OFF_EXT_RAMDISK_SIZE, &hi_sz);

  /* Use uint64_t to avoid UB from shifting into/beyond the width of
   * unsigned long on 32-bit hosts (where hi_img/hi_sz are always 0). */
  uint64_t phys = ((uint64_t)hi_img << 32) | (uint64_t)lo_img;
  uint64_t size = ((uint64_t)hi_sz << 32) | (uint64_t)lo_sz;

  if (phys == 0 || size == 0 || phys > (uint64_t)ULONG_MAX ||
      phys + size > (uint64_t)ULONG_MAX)
    return -1;

  *start = (unsigned long)phys;
  *end = (unsigned long)(phys + size);
  return 0;
#else
  (void)start;
  (void)end;
  return -1;
#endif
}

/* Populate [start, end) of the initrd from the device tree chosen node.
 * Tries /sys/firmware/devicetree/base/chosen first, then /proc/device-tree. */
static int read_initrd_dt(unsigned long *start, unsigned long *end) {
  static const char *const bases[] = {
      "/sys/firmware/devicetree/base/chosen",
      "/proc/device-tree/chosen",
      NULL,
  };
  char path[256];
  unsigned long s = 0, e = 0;

  for (int i = 0; bases[i] != NULL; i++) {
    snprintf(path, sizeof(path), "%s/linux,initrd-start", bases[i]);
    if (read_be_addr(path, &s) != 0)
      continue;
    snprintf(path, sizeof(path), "%s/linux,initrd-end", bases[i]);
    if (read_be_addr(path, &e) != 0)
      continue;
    if (s == 0 || e <= s)
      continue;
    *start = s;
    *end = e;
    return 0;
  }
  return -1;
}

/* Predicate: result represents a kernel-base candidate in physical space.
 * Conservatively limited to PHYS results in TEXT or DATA sections — these
 * are the addresses subject to the initrd-avoid constraint. PHYS/DRAM
 * results carry RAM landmarks (ram_base/ram_top, initrd witnesses, etc.)
 * and must not be invalidated. */
static int is_phys_kernel_base_candidate(const struct result *r) {
  if (r->type != KASLD_ADDR_PHYS)
    return 0;
  if (strcmp(r->section, KASLD_SECTION_TEXT) == 0)
    return 1;
  if (strcmp(r->section, KASLD_SECTION_DATA) == 0)
    return 1;
  return 0;
}

static void initrd_phys_avoid_run(struct kasld_analysis_ctx *ctx) {
  (void)ctx;

  unsigned long initrd_start = 0, initrd_end = 0;
  const char *src = NULL;

  if (read_initrd_x86(&initrd_start, &initrd_end) == 0)
    src = "boot_params";
  else if (read_initrd_dt(&initrd_start, &initrd_end) == 0)
    src = "devicetree/chosen";
  else
    return; /* no initrd information available */

  /* Sanity: end must strictly exceed start, and the interval must fit in
   * a plausible physical address space (< 1 PiB). Use 1ull to avoid UB
   * from shifting beyond the width of unsigned long on 32-bit hosts. */
  if (initrd_end <= initrd_start ||
      (uint64_t)(initrd_end - initrd_start) > (1ull << 50))
    return;

  static bool printed = false;
  if (verbose && !quiet && !printed) {
    printed = true;
    fprintf(stdout,
            "[infer] initrd_phys_avoid: forbidden interval [%#lx, %#lx)"
            " from %s\n",
            initrd_start, initrd_end, src);
  }

  int invalidated = 0;
  for (int i = 0; i < num_results; i++) {
    struct result *r = &results[i];
    if (!r->valid)
      continue;
    if (!is_phys_kernel_base_candidate(r))
      continue;
    if (r->raw < initrd_start || r->raw >= initrd_end)
      continue;

    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] initrd_phys_avoid: invalidating PHYS/%s result"
              " %#lx (inside initrd interval [%#lx, %#lx))\n",
              r->section, r->raw, initrd_start, initrd_end);
    r->valid = 0;
    invalidated++;
  }

  if (invalidated)
    revalidate_results();
}

static const struct kasld_inference initrd_phys_avoid = {
    .name = "initrd_phys_avoid",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = initrd_phys_avoid_run,
};

KASLD_REGISTER_INFERENCE(initrd_phys_avoid);
