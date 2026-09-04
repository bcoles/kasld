// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Emit x86 setup-header scalar facts: the exact in-memory kernel size
// (init_size, emitted as both SF_IMAGE_SIZE_MIN and SF_IMAGE_SIZE_MAX since it
// is sound in both directions), SF_PHYS_KERNEL_ALIGN (CONFIG_PHYSICAL_ALIGN,
// the KASLR slot granularity), and the KASLR-off scalars for a kernel built
// without CONFIG_RELOCATABLE.
//
// Two places carry the same header. /sys/kernel/boot_params/data is the
// structure the kernel copied it into, and /boot/vmlinuz-<release> is the image
// it came from -- same fields, same offsets. Neither is reliably the readable
// one: the sysfs file is absent on a kernel built without it and hidden by some
// container filesystems, while the image is 0600 on some distros and
// world-readable on others. Each BUILD-TIME field is taken from sysfs and falls
// back to the image, so a vantage holding either answers.
//
// The KASLR flag is the exception and takes no fallback: it is written at
// runtime into the copy the kernel kept, and the image's own copy is clear on
// every kernel ever built. Reading it from there would report that KASLR did
// not run, universally and confidently.
//
// x86 only; the readers return nothing elsewhere.
// ---
// <bcoles@gmail.com>
#define _POSIX_C_SOURCE 200809L /* pread() in boot_params.h */
#include "include/kasld/api.h"
#include "include/kasld/boot_params.h"
#include "include/kasld/kernel_image.h"

#include <sys/utsname.h>

KASLD_EXPLAIN(
    "Reads the x86 setup header, from /sys/kernel/boot_params/data or "
    "the /boot image it was copied from, for the exact kernel "
    "init_size, CONFIG_PHYSICAL_ALIGN and whether the kernel is "
    "relocatable at all. Emitted as scalar facts tightening the "
    "KASLR ceiling, the slot granularity, and — for a "
    "non-relocatable kernel, which cannot be randomized — the base "
    "itself. x86 only.");
KASLD_META("method:parsed\n"
           "phase:inference\n"
           "discloses:facts\n"
           "source:files\n");

int main(void) {
  unsigned long init_size = 0, align = 0;
  int relocatable = -1;
  struct utsname uts;

  init_size = kasld_read_boot_init_size();
  align = kasld_read_boot_kernel_align();
  relocatable = kasld_read_boot_relocatable();

  /* The image supplies only what sysfs did not: reading it is the fallback
   * path, so a run with boot_params present does not open /boot at all. */
  if ((!init_size || !align || relocatable < 0) && kasld_uname(&uts) == 0) {
    unsigned long f_size = 0, f_align = 0;
    int f_reloc = -1;
    if (kasld_read_bzimage_hdr(uts.release, &f_size, &f_align, &f_reloc)) {
      if (!init_size)
        init_size = f_size;
      if (!align)
        align = f_align;
      if (relocatable < 0)
        relocatable = f_reloc;
    }
  }

  if (init_size) {
    /* Exact footprint: feeds both the ceiling (MIN) and the floor (MAX). */
    kasld_emit_scalar(SF_IMAGE_SIZE_MIN, init_size, CONF_PARSED);
    kasld_emit_scalar(SF_IMAGE_SIZE_MAX, init_size, CONF_PARSED);
  }
  if (align)
    kasld_emit_scalar(SF_PHYS_KERNEL_ALIGN, align, CONF_PARSED);
  /* Whether the stub randomized the kernel this boot. The set case is a fact
   * nothing else can state -- the cmdline, the config and the dmesg string all
   * describe intent, while this is the randomizer's own record of what it did,
   * and it carries CONFIG_RANDOMIZE_BASE with it. The clear case is the
   * KASLR-off signal the existing vocabulary already carries, so it is emitted
   * in those terms rather than as a second way of saying the same thing. */
  switch (kasld_read_boot_kaslr_randomized()) {
  case 1:
    kasld_emit_scalar(SF_KASLR_RANDOMIZED, 1, CONF_PARSED);
    break;
  case 0:
    kasld_emit_scalar(SF_VIRT_KASLR_DISABLED, 1, CONF_PARSED);
    kasld_emit_scalar(SF_PHYS_KASLR_DISABLED, 1, CONF_PARSED);
    break;
  default:
    break;
  }

  if (relocatable == 0) {
    /* CONFIG_RANDOMIZE_BASE depends on CONFIG_RELOCATABLE, so a kernel that
     * cannot be relocated cannot be randomized either — and it goes further
     * than a disabled-KASLR signal does: it ignores the address the boot
     * loader chose and decompresses to the one it was compiled for. The
     * KASLR-off scalars are the vocabulary for that, and the pin rules behind
     * them already decide how much of the base a given build's evidence
     * supports. */
    kasld_emit_scalar(SF_VIRT_KASLR_DISABLED, 1, CONF_PARSED);
    kasld_emit_scalar(SF_PHYS_KASLR_DISABLED, 1, CONF_PARSED);
  }
  return 0;
}
