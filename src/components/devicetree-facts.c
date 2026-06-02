// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Emit SF_FW_RESERVED_BASE: the ppc64 firmware reserved-region base (OPAL/RTAS)
// from the device tree, below which the kernel image must fit. ppc64 only.
// ---
// <bcoles@gmail.com>
#include "include/kasld/api.h"
#include "include/kasld/devicetree.h"

KASLD_EXPLAIN("Reads the OPAL/RTAS firmware reserved-region base from the "
              "device tree (/sys/firmware/devicetree) and emits it as a scalar "
              "fact bounding the kernel ceiling. ppc64 only.");
KASLD_META("method:parsed\n"
           "phase:inference\n");

int main(void) {
  unsigned long v = kasld_read_ppc64_fw_reserved_base();
  if (v)
    kasld_emit_scalar(SF_FW_RESERVED_BASE, v, CONF_PARSED);
  return 0;
}
