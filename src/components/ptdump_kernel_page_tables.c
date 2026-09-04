// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Leak the kernel virtual text base (_text) from the debugfs page-table dump.
//
// With CONFIG_PTDUMP_DEBUGFS=y the kernel exposes a walk of init_mm's page
// tables. On x86 it is /sys/kernel/debug/page_tables/kernel; on arm64
// /sys/kernel/debug/kernel_page_tables. The walker prints one line per
// contiguous run of same-protection mappings as a raw virtual range
// "0x<start>-0x<end>", with region headers "---[ name ]---" between runs. The
// addresses are printed raw (%lx), with no kptr_restrict / kallsyms_show_value
// gate — the only access control is the file mode (0400) and the debugfs mount.
//
// The randomized text base is recovered from the x86 "High Kernel Mapping"
// region. That region begins at the fixed __START_KERNEL_map and holds an
// unmapped gap [__START_KERNEL_map, _text) followed by the mapped kernel image
// [_text, ...) — the gap width is exactly the KASLR slide. The run addresses
// alone do not distinguish the gap from the image (both are printed), so the
// image is located by the protection column: a present entry prints one of
// "RW "/"ro ", a non-present entry prints only spaces. The first run in the
// region that carries a protection flag starts at _text.
//
//   Data leaked:      _text (virtual text base)
//   Kernel subsystem: mm/ptdump + arch page-table dumper
//   Address type:     virtual (kernel text)
//   Method:           parsed (debugfs page-table dump)
//   Gate:             file mode 0400 and the debugfs mount (0700 by default);
//                     no kptr_restrict / kallsyms_show_value check. Reachable
//                     from an already-privileged vantage, a debugfs mount
//                     relaxed by mode=/gid=, or a container bind-mount.
//   Config:           CONFIG_PTDUMP_DEBUGFS
//
// The dump format carries no ABI guarantee, so parsing is conservative: a base
// is pinned only when a mapped run is unambiguously located inside the kernel-
// text window; anything else declines rather than risk a wrong pin. Only the
// text base is recoverable — the direct-map / vmalloc / vmemmap region bases
// are held in the walker's marker table and never printed, and the first mapped
// run of those regions sits above the region base, so no exact base is
// available there. proc_kcore recovers the same text base (and page_offset)
// from a stable binary format; this covers the vantage where kcore is masked
// but debugfs is readable.
//
// Sound only where the kernel text has a dedicated high mapping distinct from
// the direct map (TEXT_TRACKS_DIRECTMAP == 0). On arm64 the kernel image is
// mapped inside the vmalloc region with no distinct header, so its runs cannot
// be told from module/vmalloc runs — the parse finds no "High Kernel Mapping"
// region and declines there.
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
    "Reads the debugfs page-table dump (/sys/kernel/debug/page_tables/kernel "
    "on "
    "x86, kernel_page_tables on arm64), a raw walk of the kernel page tables "
    "with CONFIG_PTDUMP_DEBUGFS. In the x86 'High Kernel Mapping' region an "
    "unmapped gap precedes the kernel image, so the first mapped run — found "
    "via "
    "the protection column — starts at the randomized _text. Addresses are "
    "printed raw with no kptr_restrict gate; access is bounded by the 0400 "
    "file "
    "mode and the debugfs mount.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "discloses:virtual\n"
           "source:files\n"
           "config:CONFIG_PTDUMP_DEBUGFS\n");

#if !TEXT_TRACKS_DIRECTMAP

/* x86 dumps init_mm under page_tables/kernel; arm64 uses kernel_page_tables.
 * The arm64 file is opened too, but its output carries no "High Kernel Mapping"
 * region, so the parse below declines on it. */
static const char *const PATHS[] = {
    "/sys/kernel/debug/page_tables/kernel",
    "/sys/kernel/debug/kernel_page_tables",
    NULL,
};

/* A present page-table entry prints exactly one of "RW "/"ro " in the
 * protection column; a non-present entry prints only spaces. Either token
 * marks a mapped run. */
static int line_is_mapped(const char *line) {
  return strstr(line, "RW ") != NULL || strstr(line, "ro ") != NULL;
}

int main(int argc, char **argv) {
  kasld_cli(argc, argv);

  FILE *f = NULL;
  int denied = 0;
  for (int i = 0; PATHS[i]; i++) {
    int fd = kasld_open(PATHS[i], O_RDONLY);
    if (fd < 0) {
      if (errno == EACCES || errno == EPERM)
        denied = 1;
      continue;
    }
    f = fdopen(fd, "r");
    if (!f) {
      close(fd);
      continue;
    }
    kasld_info("reading kernel page-table dump from %s", PATHS[i]);
    break;
  }
  if (!f)
    return denied ? kasld_disp_mitigation_denied(
                        "debugfs", "kernel page-table dump not readable")
                  : kasld_disp_absent(
                        "no kernel page-table dump (CONFIG_PTDUMP_DEBUGFS)");

  char line[512];
  int in_text_region = 0;
  unsigned long text = 0;
  while (fgets(line, sizeof(line), f)) {
    /* Region header: "---[ name ]---". Only the x86 high-kernel-image region
     * bounds the randomized text run. */
    if (strstr(line, "---[")) {
      in_text_region = strstr(line, "High Kernel Mapping") != NULL;
      continue;
    }
    if (!in_text_region)
      continue;

    /* Run lines start with the raw range "0x<start>-0x<end>"; headers and
     * "... skipped ..." lines do not. Only the start is needed. */
    if (strncmp(line, "0x", 2) != 0)
      continue;
    unsigned long a;
    const char *end;
    if (!kasld_addr_parse(line + 2, 16, &a, &end) || *end != '-')
      continue;
    /* First mapped run in the region starts at _text (nothing below _text in
     * the high mapping is mapped). An unmapped gap line is skipped. */
    if (line_is_mapped(line)) {
      text = a;
      break;
    }
  }
  fclose(f);

  if (text == 0 || !kasld_addr_is_kernel_text(text))
    return kasld_disp_inconclusive(
        "no mapped kernel-text run in the page-table dump");

  kasld_found("kernel _text from page-table dump: 0x%lx", text);
  /* The first mapped run of the high kernel mapping begins at _text, the image
   * base — the start of the image, not _stext (which sits past the head gap).
   * REGION_KERNEL_IMAGE names the image base directly; REGION_KERNEL_TEXT would
   * be read as _stext and shifted down by the head gap. */
  kasld_result_base(KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, text, "_text",
                    CONF_PARSED);
  return 0;
}

#else /* TEXT_TRACKS_DIRECTMAP: the kernel text sits inside the direct map, so  \
       * a page-table run in the text window can start below _text — no sound \
       * pin. Inert on coupled arches. */

int main(void) { return 0; }

#endif
