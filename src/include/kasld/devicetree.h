// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Device-tree firmware-region reader (ppc64), without privileges.
//
// On POWER systems the kernel image must fit below the firmware reserved
// regions whose bases live in the device tree (big-endian):
//   OPAL (PowerNV): /sys/firmware/devicetree/base/ibm,opal/opal-base-address
//   (u64) RTAS (pseries): /sys/firmware/devicetree/base/rtas/rtas-base (u32)
// The kernel must fit below BOTH, so the binding constraint is the lower base.
// Read by the engine bridge. Reads
// route through the kasld_* wrappers (KASLD_SYSROOT-aware). Returns 0 when no
// firmware base is present (non-POWER, or the nodes absent).
// ---
// <bcoles@gmail.com>

#ifndef KASLD_DEVICETREE_H
#define KASLD_DEVICETREE_H

#include "sysroot.h"

#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

/* Read a big-endian device-tree integer (4 or 8 bytes) into a host ulong.
 * Returns 0 on failure. width must be 4 or 8. */
__attribute__((unused)) static unsigned long kasld_dt_read_be(const char *path,
                                                              int width) {
  uint8_t buf[8];
  if (width != 4 && width != 8)
    return 0;
  int fd = kasld_open(path, O_RDONLY);
  if (fd < 0)
    return 0;
  ssize_t n = read(fd, buf, (size_t)width);
  close(fd);
  if (n != width)
    return 0;
  unsigned long v = 0;
  for (int i = 0; i < width; i++)
    v = (v << 8) | buf[i];
  return v;
}

/* Read a big-endian DT scalar whose width is whatever the file holds.
 * Many DT chosen scalars are 4 bytes on 32-bit targets and 8 bytes on
 * 64-bit (the #address-cells / #size-cells properties decide); this
 * helper accepts either by reading whatever the file contains and
 * inspecting the actual read length. Stores the value in *out and
 * returns 1 on success; returns 0 if the path is missing, unreadable,
 * or holds an unsupported size. */
__attribute__((unused)) static int kasld_dt_read_be_auto(const char *path,
                                                         unsigned long *out) {
  uint8_t buf[8];
  int fd = kasld_open(path, O_RDONLY);
  if (fd < 0)
    return 0;
  ssize_t n = read(fd, buf, sizeof(buf));
  close(fd);
  if (n != 4 && n != 8)
    return 0;
  unsigned long v = 0;
  for (ssize_t i = 0; i < n; i++)
    v = (v << 8) | buf[i];
  *out = v;
  return 1;
}

/* The lowest ppc64 firmware reserved-region base (OPAL or RTAS) within the
 * first 4 GiB, or 0 if neither is present/plausible. The kernel must fit below
 * it. */
__attribute__((unused)) static unsigned long
kasld_read_ppc64_fw_reserved_base(void) {
  unsigned long best = 0;
  unsigned long opal = kasld_dt_read_be(
      "/sys/firmware/devicetree/base/ibm,opal/opal-base-address", 8);
  /* PAPR/pseries names the RTAS base `linux,rtas-base` (Linux's instantiation
   * address); `slof,rtas-base` is SLOF's view; plain `rtas-base` is a legacy
   * mis-name that does not exist on real systems. Try in preference order. */
  unsigned long rtas =
      kasld_dt_read_be("/sys/firmware/devicetree/base/rtas/linux,rtas-base", 4);
  if (rtas == 0)
    rtas = kasld_dt_read_be("/sys/firmware/devicetree/base/rtas/slof,rtas-base",
                            4);
  if (rtas == 0)
    rtas = kasld_dt_read_be("/sys/firmware/devicetree/base/rtas/rtas-base", 4);
  /* Plausible firmware bases sit within the first 4 GiB. */
  if (opal > 0 && opal <= 0xffffffffUL)
    best = opal;
  if (rtas > 0 && rtas <= 0xffffffffUL && (best == 0 || rtas < best))
    best = rtas;
  return best;
}

#endif /* KASLD_DEVICETREE_H */
