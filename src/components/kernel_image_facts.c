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
  return 0;
}
