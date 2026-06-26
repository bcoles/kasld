// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Parse `memmap=size$start` / `size!start` / `size#start` reservations from
// the cmdline (x86) and emit each as a PHYS REGION_CMDLINE_MEMMAP extent.
//
// Detection component — emits memory extents (cmdline-reported), not kernel
// pointers.
//   Purpose: arch/x86/boot/compressed/kaslr.c parse_memmap() +
//   mem_avoid_memmap() add each reservation interval to mem_avoid[] so
//   find_random_phys_addr() refuses to place the kernel image overlapping
//   it. The cmdline_memmap_phys_exclude rule consumes the emitted extents
//   (with SF_IMAGE_SIZE_MIN) to widen each into the inclusive forbidden hole
//   `[start - image_size + 1, start + size - 1]` and emits C_EXCLUDE on
//   Q_PHYS_IMAGE_BASE — mirroring initrd_phys_exclude / cmdline_phys_exclude.
//
// Syntax (mirrors lib/cmdline.c memparse + the kernel's @$!# delimiters):
//   memmap=<size>@<start>   usable RAM (NO avoidance — size=0 in mem_avoid)
//   memmap=<size>$<start>   reserved
//   memmap=<size>!<start>   persistent memory
//   memmap=<size>#<start>   ACPI NVS
//   memmap=<size>           equivalent to mem=<size> (no avoidance entry)
// Up to 4 with-offset entries are honoured by the kernel; a 5th sets
// memmap_too_large = true and KASLR bails — we still emit them all (the rule
// treats each as an exclusion regardless).
//
// /proc/cmdline is world-readable (0444). x86 only; the component returns 0
// elsewhere (memmap= on other arches is parsed later and does not constrain
// the KASLR placer).
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/arch/x86/boot/compressed/kaslr.c#L118
// https://elixir.bootlin.com/linux/v6.12/source/arch/x86/boot/compressed/kaslr.c#L168
// https://www.kernel.org/doc/html/v6.12/admin-guide/kernel-parameters.html
// ---
// <bcoles@gmail.com>

#include "include/cmdline.h"
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <stdio.h>

KASLD_EXPLAIN(
    "x86 only: parses `memmap=size$start` / `size!start` / `size#start` "
    "reservations from /proc/cmdline and emits each as a PHYS "
    "REGION_CMDLINE_MEMMAP extent. The kernel placer refuses to overlap "
    "these intervals; cmdline_memmap_phys_exclude turns each into a "
    "forbidden zone on Q_PHYS_IMAGE_BASE. /proc/cmdline is world-readable.");

KASLD_META("method:detection\n"
           "phase:inference\n"
           "addr:phys-extent\n");

#if defined(__x86_64__) || defined(__i386__)
/* Parse one memmap=<size><sep><start> token starting at p. On success,
 * stores the (lo, hi) interval, the separator character, and `is_avoid` =
 * 1 iff the token contributes a forbidden interval (`$`, `!`, `#`); 0 for
 * `@` (usable RAM — counted toward MAX_MEMMAP_REGIONS by the kernel but
 * produces no avoidance band). Returns 1 on parse, 0 on malformed input.
 * The bare `memmap=size` form (no separator) is handled by the bare-mem=
 * cmdline path and is rejected here. */
static int parse_one_memmap(const char *p, unsigned long *lo, unsigned long *hi,
                            char *sep_out, int *is_avoid) {
  unsigned long size = 0, start = 0;
  if (!kasld_memparse(&p, &size) || size == 0)
    return 0;
  char sep = *p;
  if (sep != '$' && sep != '!' && sep != '#' && sep != '@')
    return 0;
  p++;
  if (!kasld_memparse(&p, &start))
    return 0;
  if (size - 1 > ULONG_MAX - start)
    return 0; /* overflow */
  *lo = start;
  *hi = start + size - 1;
  *sep_out = sep;
  *is_avoid = (sep != '@');
  return 1;
}
#endif

int main(void) {
#if defined(__x86_64__) || defined(__i386__)
  FILE *f = kasld_fopen("/proc/cmdline", "r");
  if (!f) {
    kasld_err("/proc/cmdline unavailable");
    return 1;
  }
  char buf[2048];
  if (!fgets(buf, sizeof(buf), f)) {
    fclose(f);
    return 1;
  }
  fclose(f);

  const char *key = "memmap=";
  size_t klen = sizeof("memmap=") - 1;
  int emitted_avoid = 0;
  unsigned long with_offset = 0; /* counts ALL `@$!#` separators */
  const char *p = buf;
  while ((p = strstr(p, key)) != NULL) {
    /* Word-boundary check (mirrors the kernel's parsers). */
    if (p == buf || p[-1] == ' ' || p[-1] == '\t' || p[-1] == '\n') {
      unsigned long lo = 0, hi = 0;
      char sep = 0;
      int is_avoid = 0;
      if (parse_one_memmap(p + klen, &lo, &hi, &sep, &is_avoid)) {
        with_offset++;
        if (is_avoid) {
          char name[16];
          snprintf(name, sizeof(name), "memmap%c", sep);
          kasld_info("cmdline %s -> [%#lx, %#lx]", name, lo, hi);
          kasld_result_range(KASLD_TYPE_PHYS, REGION_CMDLINE_MEMMAP, lo, hi,
                             name, CONF_PARSED);
          emitted_avoid++;
        }
      }
    }
    p += klen;
  }
  /* Emit the count scalar when any with-offset memmap= was seen — the
   * cmdline_memmap_too_large_phys_pin rule consumes it and fires on
   * count > 4. Skipping the emission when zero keeps the no-signal-on-clean-
   * cmdline path quiet. */
  if (with_offset > 0)
    kasld_emit_scalar(SF_CMDLINE_MEMMAP_COUNT, with_offset, CONF_PARSED);
  if (emitted_avoid == 0 && with_offset == 0)
    kasld_err("no avoidance `memmap=` reservations on cmdline");
#endif
  /* Other arches: emit nothing. */
  return 0;
}
