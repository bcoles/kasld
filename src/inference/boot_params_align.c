// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: boot_params kernel_alignment and init_size (PRE_COLLECTION)
//
// /sys/kernel/boot_params/data is a 2 KiB binary sysfs file exposing the full
// struct boot_params passed from the bootloader. Permission 0444
// (world-readable). Present on x86-64 kernels with CONFIG_BOOT_PARAMS_SYSFS=y
// (selected by default in all mainline x86-64 configurations).
//
// Two fields from struct setup_header are useful for inference:
//
//   hdr.kernel_alignment (u32 LE at boot_params offset 0x230 = hdr+0x3f):
//     CONFIG_PHYSICAL_ALIGN — the physical KASLR slot granularity for this
//     kernel. Default 2 MiB (0x200000); range 4 KiB–16 MiB. When the value
//     exceeds the arch-header default, the slot count is proportionally
//     smaller. Re-snapping text_base_max and phys_base_max to this alignment
//     eliminates partial slots from the top of each range.
//
//   hdr.init_size (u32 LE at boot_params offset 0x260 = hdr+0x6f):
//     Amount of linear memory required during kernel initialisation — the
//     decompressed image size including decompressor slack — used by the
//     KASLR placement code itself to bound slot selection. This is the
//     definitive kernel_size value, more precise than the stat(vmlinuz)×3.5
//     estimate used by kaslr_ceiling.c:
//
//       text_base_max = min(text_base_max,
//                           floor(KASLR_BASE_MAX − init_size,
//                           kernel_alignment))
//       phys_base_max = min(phys_base_max,
//                           floor(KASLR_PHYS_MAX − init_size,
//                           kernel_alignment))
//
//     The ceiling from init_size is applied after the alignment snap so a
//     single pass handles both constraints.
//
// Phase: PRE_COLLECTION — boot_params is a static file (set at boot); no
// component results are needed. Reading before components also means the
// corrected alignment can contribute to kaslr_ceiling's bound via convergence.
//
// Applicable: x86-64 only.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

/* /sys/kernel/boot_params/data field offsets (x86 boot protocol).
 * setup_header starts at boot_params+0x1f1; the struct is __packed.
 * kernel_alignment: hdr+0x3f  → boot_params+0x230
 * init_size:        hdr+0x6f  → boot_params+0x260  */
#define BOOT_PARAMS_PATH "/sys/kernel/boot_params/data"
#define BOOT_PARAMS_KERNEL_ALIGN 0x230ul
#define BOOT_PARAMS_INIT_SIZE 0x260ul

#if defined(__x86_64__)

static int is_power_of_two(unsigned long n) {
  return n != 0 && (n & (n - 1)) == 0;
}

static int read_boot_params(uint32_t *kernel_alignment_out,
                            uint32_t *init_size_out) {
  int fd = open(BOOT_PARAMS_PATH, O_RDONLY);
  if (fd < 0)
    return -1;

  ssize_t n = pread(fd, kernel_alignment_out, 4, BOOT_PARAMS_KERNEL_ALIGN);
  if (n != 4) {
    close(fd);
    return -1;
  }

  n = pread(fd, init_size_out, 4, BOOT_PARAMS_INIT_SIZE);
  if (n != 4) {
    close(fd);
    return -1;
  }

  close(fd);
  return 0;
}

#endif /* defined(__x86_64__) */

static void boot_params_align_run(struct kasld_analysis_ctx *ctx) {
#if defined(__x86_64__)

  uint32_t raw_align = 0, raw_init_size = 0;
  if (read_boot_params(&raw_align, &raw_init_size) != 0)
    return;

  /* Sanity check: kernel_alignment must be a non-zero power of two in the
   * range [4 KiB, 1 GiB]. Values outside this range indicate a corrupt or
   * absent boot_params file; fall back silently to arch-header defaults. */
  unsigned long kernel_alignment = (unsigned long)raw_align;
  if (!is_power_of_two(kernel_alignment) || kernel_alignment < 4096ul ||
      kernel_alignment > (1024ul * 1024 * 1024)) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] boot_params_align: kernel_alignment=%#lx"
              " failed sanity check; skipping\n",
              kernel_alignment);
    return;
  }

  if (verbose && !quiet)
    fprintf(stdout,
            "[infer] boot_params_align: kernel_alignment=%#lx"
            " init_size=%#x\n",
            kernel_alignment, raw_init_size);

  /* Propagate the actual slot granularity to the layout so the analysis
   * summary reports the correct slot count. Only increase (coarser alignment
   * = fewer valid slots — monotone tightening). phys_kaslr_align shares the
   * same granularity on x86-64 (physical and virtual offsets are locked).
   * Guard phys_kaslr_align update: skip when zero (physical KASLR absent). */
  if (kernel_alignment > ctx->layout->kaslr_align) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] boot_params_align: kaslr_align updated"
              " %#lx -> %#lx\n",
              ctx->layout->kaslr_align, kernel_alignment);
    ctx->layout->kaslr_align = kernel_alignment;
  }
  if (ctx->layout->phys_kaslr_align > 0 &&
      kernel_alignment > ctx->layout->phys_kaslr_align) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] boot_params_align: phys_kaslr_align updated"
              " %#lx -> %#lx\n",
              ctx->layout->phys_kaslr_align, kernel_alignment);
    ctx->layout->phys_kaslr_align = kernel_alignment;
  }

  /* Alignment snap: re-snap text_base_max to the actual slot boundary.
   * When kernel_alignment equals the compile-time default (2 MiB),
   * kaslr_ceiling already aligned correctly and this is a no-op. When larger
   * (e.g. 16 MiB), the snap removes partial slots from the top of the KASLR
   * window. */
  unsigned long virt_max = ctx->text_base_max & ~(kernel_alignment - 1);
  if (virt_max > KASLR_BASE_MIN && virt_max < ctx->text_base_max) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] text_base_max tightened by boot_params_align"
              " (align snap): %#lx -> %#lx\n",
              ctx->text_base_max, virt_max);
    ctx->text_base_max = virt_max;
  }

  /* Physical alignment snap. */
  unsigned long phys_max = ctx->phys_base_max & ~(kernel_alignment - 1);
  if (phys_max > KASLR_PHYS_MIN && phys_max < ctx->phys_base_max) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] phys_base_max tightened by boot_params_align"
              " (align snap): %#lx -> %#lx\n",
              ctx->phys_base_max, phys_max);
    ctx->phys_base_max = phys_max;
  }

  /* Ceiling from exact init_size.
   * Use compile-time KASLR_BASE_MAX / KASLR_PHYS_MAX (not ctx values) to
   * avoid re-compounding the subtraction across convergence passes. */
  if (raw_init_size == 0)
    return;

  unsigned long init_size = (unsigned long)raw_init_size;

  if (init_size < KASLR_BASE_MAX - KASLR_BASE_MIN) {
    unsigned long new_virt_max =
        (KASLR_BASE_MAX - init_size) & ~(kernel_alignment - 1);
    if (new_virt_max > KASLR_BASE_MIN && new_virt_max < ctx->text_base_max) {
      if (verbose && !quiet)
        fprintf(stdout,
                "[infer] text_base_max tightened by boot_params_align"
                " (init_size): %#lx -> %#lx (init_size=%#lx)\n",
                ctx->text_base_max, new_virt_max, init_size);
      ctx->text_base_max = new_virt_max;
    }
  }

  if (init_size < KASLR_PHYS_MAX - KASLR_PHYS_MIN) {
    unsigned long new_phys_max =
        (KASLR_PHYS_MAX - init_size) & ~(kernel_alignment - 1);
    if (new_phys_max > KASLR_PHYS_MIN && new_phys_max < ctx->phys_base_max) {
      if (verbose && !quiet)
        fprintf(stdout,
                "[infer] phys_base_max tightened by boot_params_align"
                " (init_size): %#lx -> %#lx (init_size=%#lx)\n",
                ctx->phys_base_max, new_phys_max, init_size);
      ctx->phys_base_max = new_phys_max;
    }
  }

#else
  (void)ctx;
#endif /* defined(__x86_64__) */
}

static const struct kasld_inference boot_params_align = {
    .name = "boot_params_align",
    .phase = KASLD_INFER_PHASE_PRE_COLLECTION,
    .run = boot_params_align_run,
};

KASLD_REGISTER_INFERENCE(boot_params_align);
