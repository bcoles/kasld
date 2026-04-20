// This file is part of KASLD - https://github.com/bcoles/kasld
//
// free_reserved_area() printed virtual memory layout information to dmesg
// for SMP kernels.  The kernel prints one line per freed section:
//
//   pr_info("Freeing %s memory: %ldK (%p - %p)\n", s, ..., start, end);
//
// x86:
// Freeing unused kernel memory: 872K (c19b4000 - c1a8e000)
//
// x86_64:
// Freeing unused kernel memory: 1476K (ffffffff81f41000 - ffffffff820b2000)
//
// arm64:
// Freeing unused kernel memory: 1024K (ffff000008d90000 - ffff000008e90000)
// Freeing initrd memory: 16776K (ffff80005745b000 - ffff8000584bd000)
//
// ppc64:
// Freeing unused kernel memory: 960K (c000000000920000 - c000000000a10000)
//
// Removed in kernel v4.10-rc1 on 2016-10-26:
// https://github.com/torvalds/linux/commit/adb1fe9ae2ee6ef6bc10f3d5a588020e7664dfa7
//
// Leak primitive:
//   Data leaked:      kernel virtual addresses (freed memory section
//   boundaries) Kernel subsystem: mm — free_reserved_area() (pr_info with %p)
//   Data structure:   freed section start/end virtual addresses
//   Address type:     virtual (kernel text / initrd)
//   Method:           parsed (dmesg string)
//   Status:           removed in v4.10 (commit adb1fe9ae2ee)
//   Access check:     do_syslog() → check_syslog_permissions(); gated by
//                     dmesg_restrict
//   Source:
//   https://elixir.bootlin.com/linux/v4.9/source/mm/page_alloc.c
//
// Mitigations:
//   Removed in v4.10 (pr_info with raw %p replaced). Access gated by
//   dmesg_restrict (see dmesg.h for shared access gate details).
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://web.archive.org/web/20171029060939/http://www.blackbunny.io/linux-kernel-x86-64-bypass-smep-kaslr-kptr_restric/
// https://github.com/torvalds/linux/commit/adb1fe9ae2ee6ef6bc10f3d5a588020e7664dfa7
// https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-1000112/poc.c
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/dmesg.h"
#include "include/kasld.h"
#include "include/kasld_internal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

KASLD_EXPLAIN("Searches dmesg for 'Freeing ... memory' messages from "
              "free_reserved_area() that print kernel virtual addresses. These "
              "messages were removed in v4.10. On older kernels, they reveal "
              "kernel text and init section virtual addresses. Access is gated "
              "by dmesg_restrict.");

KASLD_META("method:parsed\n"
           "addr:virtual\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n"
           "patch:v4.10\n");

/* Parse a "Freeing <name> memory: <size>K (<start> - <end>)" line.
 * Emits a kasld_result() for the start address.  Returns 1 on success. */
static int on_match(const char *line, void *ctx) {
  (void)ctx;
  const char *name_start;
  const char *name_end;
  const char *paren;
  char *endptr;
  char label[128];
  unsigned long addr;
  const char *section;
  size_t name_len;

  name_start = strstr(line, "Freeing ");
  if (name_start == NULL)
    return 1;
  name_start += 8; /* skip "Freeing " */

  name_end = strstr(name_start, " memory:");
  if (name_end == NULL)
    return 1;

  paren = strchr(name_end, '(');
  if (paren == NULL)
    return 1;

  addr = strtoul(paren + 1, &endptr, 16);
  if (endptr == paren + 1 || addr == 0)
    return 1;

  if (addr < KERNEL_VAS_START || addr > KERNEL_VAS_END)
    return 1;

  /* Build label: "dmesg_free_reserved_area:<section name>" */
  name_len = (size_t)(name_end - name_start);
  if (name_len >= sizeof(label) - 32)
    name_len = sizeof(label) - 32;
  snprintf(label, sizeof(label), "dmesg_free_reserved_area:%.*s", (int)name_len,
           name_start);

  /* "initrd" addresses live in the physmap/linear region (DRAM).
   * All other sections (unused kernel, SMP alternatives, etc.)
   * are within the kernel image (text). */
  if (name_len >= 6 && strncmp(name_start, "initrd", 6) == 0)
    section = KASLD_SECTION_DRAM;
  else
    section = KASLD_SECTION_TEXT;

  printf("leaked address: %lx\n", addr);
  kasld_result(KASLD_ADDR_VIRT, section, addr, label);

  return 1; /* keep scanning for more sections */
}

int main(void) {
  printf("[.] searching dmesg for free_reserved_area() info ...\n");
  int found = dmesg_search("Freeing ", on_match, NULL);
  if (found < 0)
    return KASLD_EXIT_NOPERM;
  if (!found)
    printf("[-] free_reserved_area info not found in dmesg\n");
  return 0;
}
