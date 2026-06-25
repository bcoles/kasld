// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Emit SF_IMAGE_SIZE: the kernel image size estimate (from /boot artifacts),
// which bounds how high the randomized base can sit within the KASLR window.
// ---
// <bcoles@gmail.com>
#include "include/kasld/api.h"
#include "include/kasld/kernel_image.h"

KASLD_EXPLAIN("Estimates the kernel image size from /boot (PE header / vmlinuz "
              "/ System.map) and emits it as a scalar fact that bounds the "
              "KASLR ceiling. No privileges.");
KASLD_META("method:parsed\n"
           "phase:inference\n");

int main(void) {
  unsigned long sz = kasld_estimate_kernel_size();
  if (sz)
    kasld_emit_scalar(SF_IMAGE_SIZE, sz, CONF_PARSED);

  /* The arm64/riscv64 EFI Image header carries the exact in-memory image size
   * (image_size = _end - _text, including BSS) — the same quantity x86 exposes
   * via boot_params init_size. Emit it as SF_INIT_SIZE so the rules that need a
   * size guaranteed >= the in-memory extent (image_floor_from_init_size, and
   * the image-fits ceilings) get a sound value on these arches too, rather than
   * the SF_IMAGE_SIZE estimate which can fall back to the compressed file size.
   * Only fires on a readable, uncompressed Image: the header magic gate rejects
   * gzip and x86 bzImages (x86 already supplies SF_INIT_SIZE from boot_params).
   */
  struct utsname uts;
  if (kasld_uname(&uts) == 0) {
    unsigned long memsz = kasld_image_size_from_header(uts.release);
    if (memsz)
      kasld_emit_scalar(SF_INIT_SIZE, memsz, CONF_PARSED);
  }
  return 0;
}
