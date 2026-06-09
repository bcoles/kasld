// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read kernel-image extents from /proc/iomem ("Kernel code/data/bss").
//
// Detection component — emits memory extents the kernel itself published.
//   Purpose: x86 /proc/iomem nests three top-level "System RAM" sub-entries
//   labeled "Kernel code", "Kernel data", and "Kernel bss". Each is the
//   exact physical range the corresponding ELF section was loaded at.
//   Emitting them as PHYS REGION_KERNEL_TEXT / KERNEL_DATA / KERNEL_BSS
//   gives the engine the tightest possible bound on Q_PHYS_TEXT_BASE
//   (pinned exactly by text_pin_from_observation when the KERNEL_TEXT
//   range arrives as a POS_BASE record; the upper edge of the image is
//   absorbed by kernel_image_phys_bound's image-size constraints) — much
//   tighter than the wide arch ceiling.
//
// Access: /proc/iomem is world-readable but the addresses are masked to 0
//   under kptr_restrict >= 1 unless the caller has CAP_SYS_ADMIN. Detect
//   masking (first valid line reads as 00000000-00000000) and emit nothing
//   in that case — the alternative would be to emit a "phys text at 0"
//   bound, which is harmful nonsense.
//
// Format (one line per range, indentation indicates nesting):
//   80000000-bfffffff : System RAM
//     1bc00000-1d336cef : Kernel code
//     1e600000-1ead557f : Kernel data
//     1f047000-1f5fffff : Kernel bss
//
// Scope: arches that publish kernel-image extents via the generic
// iomem_resource path (x86 setup.c, s390 setup.c — confirmed). The
// detection is label-driven (`Kernel code` etc.), so the component is
// harmless on arches that don't emit these labels: the parser finds no
// matching line and emits nothing.
//
// References:
// arch/x86/kernel/setup.c reserve_real_mode() +
// insert_resource(&iomem_resource, &code_resource);
// ---
// <bcoles@gmail.com>

#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include "include/kasld/sysroot.h"
#include <stdio.h>
#include <string.h>

KASLD_EXPLAIN(
    "Parses /proc/iomem for the kernel-image sub-entries (\"Kernel code\", "
    "\"Kernel data\", \"Kernel bss\") and emits each as a PHYS extent on "
    "REGION_KERNEL_TEXT / KERNEL_DATA / KERNEL_BSS. These are the "
    "authoritative physical placement of the running kernel image. x86 and "
    "s390 emit these labels in their setup code; harmless on arches that "
    "don't (no matching line → no emission). /proc/iomem requires "
    "CAP_SYS_ADMIN for unmasked addresses; emits nothing under masking.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:phys-extent\n"
           "sysctl:kptr_restrict>=1 (mask)\n");

/* Map one of the kernel-image iomem labels to its KASLD region. */
static int region_from_label(const char *label, enum kasld_region *r,
                             const char **wire) {
  if (strcmp(label, "Kernel code") == 0) {
    *r = REGION_KERNEL_TEXT;
    *wire = "kernel_code";
    return 1;
  }
  if (strcmp(label, "Kernel data") == 0) {
    *r = REGION_KERNEL_DATA;
    *wire = "kernel_data";
    return 1;
  }
  if (strcmp(label, "Kernel bss") == 0) {
    *r = REGION_KERNEL_BSS;
    *wire = "kernel_bss";
    return 1;
  }
  return 0;
}

int main(void) {
  FILE *f = kasld_fopen("/proc/iomem", "r");
  if (!f) {
    kasld_err("/proc/iomem unavailable");
    return 1;
  }

  /* Detect kptr_restrict masking by scanning a few lines for a real address.
   * If every line up to a small cap reads as 00000000-00000000, the file is
   * masked and we cannot use it. */
  int saw_real_addr = 0;
  char line[256];
  long start_pos = ftell(f);
  for (int i = 0; i < 32 && fgets(line, sizeof(line), f); i++) {
    unsigned long lo = 0, hi = 0;
    const char *p = line;
    while (*p == ' ' || *p == '\t')
      p++;
    if (sscanf(p, "%lx-%lx", &lo, &hi) == 2 && (lo != 0 || hi != 0)) {
      saw_real_addr = 1;
      break;
    }
  }
  if (!saw_real_addr) {
    fprintf(stderr, "[-] /proc/iomem appears masked (kptr_restrict?); "
                    "addresses read as 0\n");
    fclose(f);
    return 1;
  }
  fseek(f, start_pos, SEEK_SET);

  int emitted = 0;
  while (fgets(line, sizeof(line), f)) {
    const char *p = line;
    while (*p == ' ' || *p == '\t')
      p++;
    unsigned long lo = 0, hi = 0;
    char label[128] = {0};
    if (sscanf(p, "%lx-%lx : %127[^\n]", &lo, &hi, label) != 3)
      continue;
    if (hi < lo)
      continue;
    enum kasld_region region;
    const char *name_wire;
    if (!region_from_label(label, &region, &name_wire))
      continue;
    kasld_info("iomem %s -> phys [%#lx, %#lx]", label, lo, hi);
    kasld_result_range(KASLD_TYPE_PHYS, region, lo, hi, name_wire, CONF_PARSED);
    emitted++;
  }
  fclose(f);
  if (emitted == 0)
    kasld_err("no Kernel code/data/bss entries found in /proc/iomem");
  return 0;
}
