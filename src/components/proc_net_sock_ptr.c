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
//                     Otherwise %pK is hashed to a random word, detected and
//                     rejected by the slab-alignment gate below — so only
//                     genuine direct-map addresses are ever emitted.
//
// Hashed-pointer rejection: a real struct sock is slab-allocated from a
// SLAB_HWCACHE_ALIGN kmem_cache (af_unix.c / af_netlink.c register their proto
// with a slab), so its address is cache-line aligned — a fortiori aligned to
// the kmalloc minimum. A hashed %p id is a uniform-random word with no such
// alignment. The kernel-VAS floor alone does NOT catch hashed ids on 32-bit:
// there KERNEL_VIRT_VAS_START is the widest lowest-vmsplit value (0x40000000),
// so a hashed id in [0x40000000, 4 GiB) passes it, and one landing below the
// true PAGE_OFFSET would forge an unsound page_offset ceiling. Pointer hashing
// is all-or-nothing per boot, so a SINGLE misaligned first token proves the
// values are hashed; the whole read is then declined rather than emitting a
// forged direct-map address. This never rejects a real read (every real sock
// pointer is aligned) and costs only completeness on a hashed kernel, where
// there is nothing sound to emit anyway.
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
    "to a random id and discarded by the slab-alignment gate. Mainly useful "
    "on x86_64, where the direct map is randomized.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:virtual\n"
           "sysctl:kptr_restrict>=1\n"
           "bypass:CAP_SYSLOG\n");

struct sock_range {
  unsigned long lo, hi;
  int n;
  int hashed; /* a misaligned first token was seen => %p hashing is on */
};

/* Minimum alignment a real struct sock pointer is guaranteed to have. kmalloc's
 * ARCH_KMALLOC_MINALIGN is at least this on every arch, and the sock slabs are
 * SLAB_HWCACHE_ALIGN (stricter still), so a genuine pointer always clears it; a
 * hashed %p word clears it only 1-in-SOCK_PTR_ALIGN of the time. Kept at the
 * conservative kmalloc floor so a real read is never mistaken for hashed. */
#define SOCK_PTR_ALIGN 8ul

enum sock_ptr_class {
  SOCK_PTR_SKIP,      /* header line, zero, or aligned non-kernel value */
  SOCK_PTR_CANDIDATE, /* aligned, in the kernel VAS: a plausible sock pointer */
  SOCK_PTR_HASHED     /* misaligned: a hashed %p id, not a real pointer */
};

/* Classify one parsed first-token. Alignment is checked BEFORE the kernel-VAS
 * floor, so a hashed id that happens to land inside the (wide, on 32-bit) VAS
 * is still recognised as hashed rather than trusted as a direct-map address. */
static enum sock_ptr_class classify_sock_ptr(unsigned long addr) {
  if (addr == 0)
    return SOCK_PTR_SKIP;
  if (addr & (SOCK_PTR_ALIGN - 1))
    return SOCK_PTR_HASHED;
  if (!kasld_addr_is_kernel_vas(addr))
    return SOCK_PTR_SKIP;
  return SOCK_PTR_CANDIDATE;
}

/* Scan one /proc/net seq-file whose data lines begin with the sock pointer.
 * The first hex token of each line is parsed and classified; a single
 * misaligned (hashed) token condemns the whole read (see the header). */
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
    if (end == line)
      continue; /* header line or non-hex first token */
    switch (classify_sock_ptr(addr)) {
    case SOCK_PTR_HASHED:
      r->hashed = 1;
      break;
    case SOCK_PTR_CANDIDATE:
      r->n++;
      if (r->lo == 0 || addr < r->lo)
        r->lo = addr;
      if (addr > r->hi)
        r->hi = addr;
      break;
    case SOCK_PTR_SKIP:
      break;
    }
  }

  free(line);
  fclose(f);
}

int main(int argc, char *argv[]) {
  kasld_cli(argc, argv);

  int unix_rc = kasld_access("/proc/net/unix", R_OK);
  int unix_errno = errno;
  int nl_rc = kasld_access("/proc/net/netlink", R_OK);
  int nl_errno = errno;
  if (unix_rc != 0 && nl_rc != 0) {
    /* Both sources are inaccessible. Report access-denied if EITHER failed on a
     * permission error — a denied source means the data exists but is hidden
     * (more actionable than "absent"). Classifying on the residual errno alone
     * would let an absent second source mask a denied first one. */
    int denied = (unix_errno == EACCES || unix_errno == EPERM ||
                  nl_errno == EACCES || nl_errno == EPERM);
    return denied ? KASLD_EXIT_NOPERM : KASLD_EXIT_UNAVAILABLE;
  }

  struct sock_range r = {0, 0, 0, 0};
  scan_sock_file("/proc/net/unix", &r);
  scan_sock_file("/proc/net/netlink", &r);

  if (r.hashed) {
    /* A misaligned first token means %pK is hashed; every value (even the ones
     * that happen to be aligned) is a random id, not a direct-map address.
     * Emit nothing rather than forge an unsound page_offset ceiling. */
    kasld_err("sock pointers are hashed (%%pK ids, not real addresses); "
              "boot no_hash_pointers or read as CAP_SYSLOG under "
              "kptr_restrict=1 for the real values");
    return 0;
  }

  if (r.lo == 0) {
    kasld_err("no sock pointers in /proc/net/* "
              "(kptr_restrict denies the value)");
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
