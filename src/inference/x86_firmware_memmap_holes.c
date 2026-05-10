// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: x86 /sys/firmware/memmap System RAM hole validation
// (POST_COLLECTION)
//
// /sys/firmware/memmap exposes the firmware-provided physical memory map
// (E820 entries on x86; populated by arch/x86/kernel/e820.c via
// firmware_map_add_early). Each entry has start, end, and a type label such
// as "System RAM", "Reserved", "ACPI NVS", "ACPI Tables",
// "Persistent Memory", "Unusable Memory", or "Bad RAM".
//
// arch/x86/boot/compressed/kaslr.c:process_e820_entries() walks each entry
// whole and only selects KASLR slots that fit inside one entry. A slot
// whose [start, start + image_size) would straddle a non-System-RAM gap is
// rejected even when start and end are individually inside System RAM
// regions. The kernel image therefore lies fully inside exactly one
// "System RAM" interval.
//
// Inference: any collected PHYS result tagged as a kernel-base candidate
// (section ∈ {text, data}) that is *not* covered by any System RAM
// interval, or whose [base, base + MIN_IMAGE_SIZE) extends past the end of
// its containing System RAM interval, is misclassified.
//
// Difference from existing logic: dram_ceiling.c uses the global RAM-top
// witness as a single ceiling. It does not detect mid-range holes, so a
// kernel-sized slot crossing a hole is not currently rejected. This plugin
// closes that gap.
//
// Phase: POST_COLLECTION — needs collected PHYS/TEXT or PHYS/DATA results.
// x86 only: Linux populates /sys/firmware/memmap exclusively from
// arch/x86/kernel/e820.c; no other arch calls firmware_map_add_early().
//
// Soundness: MIN_IMAGE_SIZE underestimates the real kernel image. We only
// invalidate a result when its [base, base + MIN_IMAGE_SIZE) certainly
// extends past a System RAM interval's end — i.e. when even the smallest
// plausible image would not fit. Real kernels are larger, so this rule
// does not exclude any valid placement.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MEMMAP_BASE "/sys/firmware/memmap"

/* Conservative minimum kernel image size. A real kernel image is always
 * many megabytes; 4 MiB stays well below the floor and ensures we only
 * invalidate results that certainly straddle a non-System-RAM gap. */
#define MIN_IMAGE_SIZE (4ul * 1024 * 1024)

/* Upper bound on entries we will collect from /sys/firmware/memmap.
 * E820 typically has < 32 entries; EFI memory maps can be larger but
 * /sys/firmware/memmap on x86 mirrors only the E820 view. 256 is generous. */
#define MAX_RAM_INTERVALS 256

struct ram_interval {
  unsigned long start;
  unsigned long end; /* exclusive: kernel uses end as last-byte inclusive,
                        but kaslr.c slot logic treats it as a half-open
                        range; we store half-open for arithmetic clarity. */
};

#if defined(__x86_64__) || defined(__i386__)

static int read_first_line(const char *path, char *buf, size_t len) {
  FILE *f = fopen(path, "r");
  if (!f)
    return -1;
  if (!fgets(buf, (int)len, f)) {
    fclose(f);
    return -1;
  }
  fclose(f);
  buf[strcspn(buf, "\n")] = '\0';
  return 0;
}

static int cmp_intervals(const void *a, const void *b) {
  const struct ram_interval *x = a;
  const struct ram_interval *y = b;
  if (x->start < y->start)
    return -1;
  if (x->start > y->start)
    return 1;
  return 0;
}

/* Populate `intervals` with all "System RAM" entries; returns the count.
 * The kernel exposes end as the last inclusive byte, so we add 1 to
 * convert into a half-open [start, end) interval. */
static int load_ram_intervals(struct ram_interval *intervals, int max) {
  DIR *d = opendir(MEMMAP_BASE);
  if (!d)
    return -1;

  int count = 0;
  struct dirent *ent;
  while ((ent = readdir(d)) != NULL) {
    if (ent->d_name[0] == '.')
      continue;
    if (count >= max)
      break;

    char path[512], buf[256];

    snprintf(path, sizeof(path), "%s/%s/type", MEMMAP_BASE, ent->d_name);
    if (read_first_line(path, buf, sizeof(buf)) != 0)
      continue;
    if (strcmp(buf, "System RAM") != 0)
      continue;

    snprintf(path, sizeof(path), "%s/%s/start", MEMMAP_BASE, ent->d_name);
    if (read_first_line(path, buf, sizeof(buf)) != 0)
      continue;
    char *endp;
    unsigned long start = strtoul(buf, &endp, 16);

    snprintf(path, sizeof(path), "%s/%s/end", MEMMAP_BASE, ent->d_name);
    if (read_first_line(path, buf, sizeof(buf)) != 0)
      continue;
    unsigned long inclusive_end = strtoul(buf, &endp, 16);

    if (inclusive_end < start)
      continue;

    intervals[count].start = start;
    intervals[count].end = inclusive_end + 1; /* half-open */
    count++;
  }
  closedir(d);

  if (count > 0)
    qsort(intervals, (size_t)count, sizeof(*intervals), cmp_intervals);
  return count;
}

/* Find the interval containing addr. Returns pointer or NULL. */
static const struct ram_interval *
find_interval(const struct ram_interval *intervals, int count,
              unsigned long addr) {
  for (int i = 0; i < count; i++) {
    if (addr >= intervals[i].start && addr < intervals[i].end)
      return &intervals[i];
  }
  return NULL;
}

static int is_phys_kernel_base_candidate(const struct result *r) {
  if (r->type != KASLD_ADDR_PHYS)
    return 0;
  if (strcmp(r->section, KASLD_SECTION_TEXT) == 0)
    return 1;
  if (strcmp(r->section, KASLD_SECTION_DATA) == 0)
    return 1;
  return 0;
}

#endif /* x86 */

static void x86_firmware_memmap_holes_run(struct kasld_analysis_ctx *ctx) {
#if defined(__x86_64__) || defined(__i386__)
  (void)ctx;

  struct ram_interval intervals[MAX_RAM_INTERVALS];
  int n = load_ram_intervals(intervals, MAX_RAM_INTERVALS);
  if (n <= 0)
    return; /* /sys/firmware/memmap absent or empty */

  if (verbose && !quiet)
    fprintf(stdout,
            "[infer] x86_firmware_memmap_holes: %d System RAM intervals\n", n);

  int invalidated = 0;
  for (int i = 0; i < num_results; i++) {
    struct result *r = &results[i];
    if (!r->valid)
      continue;
    if (!is_phys_kernel_base_candidate(r))
      continue;

    const struct ram_interval *iv = find_interval(intervals, n, r->raw);
    if (!iv) {
      if (verbose && !quiet)
        fprintf(stdout,
                "[infer] x86_firmware_memmap_holes: invalidating PHYS/%s"
                " result %#lx (not in any System RAM interval)\n",
                r->section, r->raw);
      r->valid = 0;
      invalidated++;
      continue;
    }

    /* Straddle check: even the smallest plausible image must fit inside
     * the containing interval. */
    if (r->raw + MIN_IMAGE_SIZE > iv->end) {
      if (verbose && !quiet)
        fprintf(stdout,
                "[infer] x86_firmware_memmap_holes: invalidating PHYS/%s"
                " result %#lx (slot would straddle hole at %#lx;"
                " interval end %#lx)\n",
                r->section, r->raw, iv->end, iv->end);
      r->valid = 0;
      invalidated++;
    }
  }

  if (invalidated)
    revalidate_results();
#else
  (void)ctx;
#endif /* x86 */
}

static const struct kasld_inference x86_firmware_memmap_holes = {
    .name = "x86_firmware_memmap_holes",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = x86_firmware_memmap_holes_run,
};

KASLD_REGISTER_INFERENCE(x86_firmware_memmap_holes);
