// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Emit kernel-config scalar facts from /boot/config-*:
// SF_VIRT_RANDOMIZE_MAX_OFFSET (CONFIG_RANDOMIZE_BASE_MAX_OFFSET,
// MIPS/LoongArch) and SF_VIRT_CONFIG_PAGE_OFFSET (CONFIG_PAGE_OFFSET /
// VMSPLIT).
// ---
// <bcoles@gmail.com>
#include "include/kasld/api.h"
#include "include/kasld/bootconfig.h"

KASLD_EXPLAIN("Reads the kernel boot config (/boot/config-*, /lib/modules/...) "
              "for CONFIG_RANDOMIZE_BASE_MAX_OFFSET and CONFIG_PAGE_OFFSET, "
              "emitted as scalar facts. No privileges.");
KASLD_META("method:parsed\n"
           "phase:inference\n");

int main(void) {
  unsigned long v;
  int is_unkeyed = 0;

  /* Facts from the unkeyed /boot/config (no release binding) stay below the
   * guaranteed floor — a stale/foreign config must not narrow a guaranteed
   * window. Release-keyed sources are authoritative and stay at CONF_PARSED. */
  if ((v = kasld_read_randomize_max_offset(&is_unkeyed)))
    kasld_emit_scalar(SF_VIRT_RANDOMIZE_MAX_OFFSET, v,
                      is_unkeyed ? CONF_HEURISTIC : CONF_PARSED);
  if ((v = kasld_read_config_page_offset(&is_unkeyed)))
    kasld_emit_scalar(SF_VIRT_CONFIG_PAGE_OFFSET, v,
                      is_unkeyed ? CONF_HEURISTIC : CONF_PARSED);
  return 0;
}
