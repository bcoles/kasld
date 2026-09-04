// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Leak a direct-map witness from the kmemleak debugfs report.
//
// With CONFIG_DEBUG_KMEMLEAK the kernel exposes /sys/kernel/debug/kmemleak.
// Each currently-unreferenced (leaked) object is reported as:
//
//   unreferenced object 0x<addr> (size <n>):
//     <backtrace ...>
//
// The object address is printed raw (0x%08lx) with no kptr_restrict / %pK /
// kallsyms_show_value gate; access is bounded only by the file mode (0644) and
// the debugfs mount. Because the file is 0644, it is the one address-bearing
// debugfs file that becomes readable to an unprivileged process when the mount
// is relaxed (mode=/gid=), where the 0400 files stay root-only.
//
// A leaked slab object lives in the linear (direct) map, so its virtual address
// is an interior witness of the direct map: page_offset_base <= addr. The
// lowest such address bounds the direct-map base from above. This is a bound,
// not a pin — the object sits an unknown distance above the base — so it is
// emitted as an interior sample, never a base.
//
//   Data leaked:      an interior direct-map virtual address (bounds
//                     page_offset_base from above)
//   Kernel subsystem: mm/kmemleak — the leaked-object report
//   Address type:     virtual (direct map)
//   Method:           parsed (debugfs text report)
//   Gate:             file mode 0644 and the debugfs mount (0700 by default);
//                     no kptr_restrict / kallsyms_show_value check.
//   Config:           CONFIG_DEBUG_KMEMLEAK; requires leaked objects to be
//                     present (the report is empty on a system with none).
//
// Non-direct-map objects (vmalloc, percpu, physical) are skipped: they give no
// clean bound on a quantity resolved here. The report is frequently empty, in
// which case the component declines.
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kasld/cli.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Reads /sys/kernel/debug/kmemleak, the report of currently-leaked kernel "
    "objects. Each 'unreferenced object 0x<addr>' line carries a raw object "
    "address with no kptr_restrict gate. A leaked slab object lives in the "
    "direct map, so the lowest reported direct-map address bounds "
    "page_offset_base from above. Requires CONFIG_DEBUG_KMEMLEAK and leaked "
    "objects present; access is bounded by the 0644 file mode and the debugfs "
    "mount.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "discloses:virtual\n"
           "source:files\n"
           "config:CONFIG_DEBUG_KMEMLEAK\n");

int main(int argc, char **argv) {
  kasld_cli(argc, argv);

  int fd = kasld_open("/sys/kernel/debug/kmemleak", O_RDONLY);
  if (fd < 0) {
    if (errno == EACCES || errno == EPERM)
      return kasld_disp_mitigation_denied(
          "debugfs", "/sys/kernel/debug/kmemleak not readable");
    return kasld_disp_absent("no kmemleak report (CONFIG_DEBUG_KMEMLEAK)");
  }
  FILE *f = fdopen(fd, "r");
  if (!f) {
    close(fd);
    return kasld_disp_inconclusive("could not read the kmemleak report");
  }

  char line[1024];
  unsigned long lowest = ~0ul;
  int found = 0;
  while (fgets(line, sizeof(line), f)) {
    char *p = strstr(line, "unreferenced object");
    if (!p)
      continue;
    /* Skip past any qualifier (e.g. "(percpu)") to the address token. */
    p = strstr(p, "0x");
    if (!p)
      continue;
    unsigned long addr;
    if (!kasld_addr_parse(p + 2, 16, &addr, NULL))
      continue;
    /* Decide the region from the classifier, not a bare window test: the
     * direct-map window overlaps the text band on some arches, so a range test
     * could misattribute a text address as direct-map. Only a clean direct-map
     * classification is kept; a vmalloc/percpu object, or an address ambiguous
     * with the text band, is skipped. */
    if (kasld_addr_classify(addr) != REGION_DIRECTMAP_BAND)
      continue;
    if (addr < lowest)
      lowest = addr;
    found = 1;
  }
  fclose(f);

  if (!found)
    return kasld_disp_inconclusive(
        "no direct-map objects in the kmemleak report");

  kasld_found("lowest kmemleak direct-map object: 0x%016lx", lowest);
  /* A range-classified witness, not a source-established one: emitted as the
   * band region, which bounds page_offset from above in the likely window. */
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_DIRECTMAP_BAND, lowest, NULL,
                      CONF_PARSED);
  return 0;
}
