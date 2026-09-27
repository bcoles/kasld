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
// Engine fit: emitted as PHYS windows (range when a length is known, else a
// base). An address /proc/iomem places outside System RAM is a device window
// (REGION_MMIO), which mmio_floor_phys_ceiling uses to ceiling
// Q_PHYS_IMAGE_BASE (the image must sit in DRAM below the lowest MMIO above
// it); one inside System RAM is DRAM the driver exposed — a framebuffer
// carve-out, say — and is emitted as a reserved DRAM band instead. Decoupled
// arches only; loose, and additive mainly when /proc/iomem is masked, which is
// also when the classification falls back to the MMIO label.
//
// Mitigations:
//   CONFIG_FB=n / CONFIG_SERIAL_CORE=n remove the respective source; tightening
//   device-node group permissions removes the access. No runtime sysctl gate.
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include "include/kasld/iomem.h"

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
    "bases ceiling the physical kernel base on decoupled arches - a fallback "
    "for when /proc/iomem is masked and for platform (non-PCI) devices.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "discloses:physical\n"
           "source:live\n");

/* Emit one window as a PHYS landmark: a range when a length is known, else a
 * base (lo edge). Both set HAS_LO, which mmio_floor_phys_ceiling consumes.
 * Returns 1 if emitted, 0 for a zero (absent) base.
 *
 * Not every address these ioctls hand back is a device register window.
 * fb_fix_screeninfo.smem_start is whatever backs the framebuffer, which on a
 * SoC is routinely a DRAM carve-out or a CMA allocation rather than MMIO, and
 * a UART's mapbase can be reported on a board whose serial is memory-backed.
 * /proc/iomem settles it: an address the kernel places inside System RAM is
 * DRAM the driver exposed, so it is emitted as a reserved DRAM band instead.
 * The distinction matters downstream — REGION_MMIO feeds the MMIO ceiling and
 * carries "the image was never allowed here", while a reserved DRAM band is a
 * DRAM landmark that only forbids the band itself.
 *
 * A masked or absent /proc/iomem classifies as unknown and the MMIO label
 * stands: calling true MMIO "DRAM" would feed a device window to the DRAM
 * bounds, which is the damaging direction. That fallback is the unprivileged
 * norm, not an edge case — r_show() zeroes every range for a reader without
 * CAP_SYS_ADMIN and no sysctl relaxes it — so the reclassification reaches
 * only a privileged run, such as the one that captures a bundle. */
static int emit_mmio(unsigned long start, unsigned long len, const char *name) {
  unsigned long hi;
  if (!start)
    return 0;
  enum kasld_region region =
      kasld_iomem_classify(start) == KASLD_IOMEM_SYSTEM_RAM
          ? REGION_RESERVED_MEM
          : REGION_MMIO;
  if (len && !kasld_add_ovf(start, len - 1, &hi))
    kasld_result_range(KASLD_TYPE_PHYS, region, start, hi, name, CONF_PARSED);
  else
    kasld_result_base(KASLD_TYPE_PHYS, region, start, name, CONF_PARSED);
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
  /* Prefixes rather than formats: a format reaching snprintf through an array
   * cannot be checked against its argument, while one literal with the varying
   * parts passed as arguments is checked in full. */
  static const char *const prefix[] = {"/dev/ttyS", "/dev/ttyAMA"};
  int found = 0;
  for (unsigned t = 0; t < sizeof(prefix) / sizeof(prefix[0]); t++) {
    for (int i = 0; i < 4; i++) {
      char dev[32];
      snprintf(dev, sizeof(dev), "%s%d", prefix[t], i);
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
  /* Live host probe: the device ioctls read the executing machine's hardware
   * MMIO layout, which is not reproducible from a captured tree — skip under a
   * KASLD_SYSROOT replay so it never reports the analysis host's addresses. */
  if (kasld_skip_live_probe("ioctl_mmio_phys"))
    return 0;

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
