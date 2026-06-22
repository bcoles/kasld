// This file is part of KASLD - https://github.com/bcoles/kasld
//
// CMA/DMA reserved memory pool physical addresses from dmesg.
//
// The kernel prints physical addresses when creating CMA, DMA, and
// restricted DMA memory pools, and when finalizing CMA reservations:
//
//   Reserved memory: created CMA memory pool at 0x000000007a000000, size 96 MiB
//   Reserved memory: created DMA memory pool at 0x0000000070000000, size 32 MiB
//   Reserved memory: created restricted DMA pool at 0x0000000060000000, size 64
//   MiB cma: Reserved 256 MiB at 0x00000000f0000000 on node -1
//
// These are common on ARM/ARM64/embedded and on systems with DMA-constrained
// devices. Less common on x86 desktop but present on many x86 servers.
//
// Leak primitive:
//   Data leaked:      physical addresses of CMA/DMA memory pool reservations
//   Kernel subsystem: kernel/dma, mm/cma — reserved memory initialization
//   Data structure:   CMA/DMA pool base address (physical)
//   Address type:     physical (DRAM)
//   Method:           parsed (dmesg string)
//   Status:           unfixed (boot messages printed unconditionally)
//   Access check:     do_syslog() → check_syslog_permissions(); gated by
//                     dmesg_restrict
//   Source:
//   https://elixir.bootlin.com/linux/v6.6/source/kernel/dma/contiguous.c
//
// Mitigations:
//   Access gated by dmesg_restrict (see dmesg.h for shared access gate
//   details). The messages are printed unconditionally during boot when
//   CMA/DMA pools are configured. On decoupled architectures, physical
//   addresses cannot derive the virtual text base.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v6.6/source/kernel/dma/contiguous.c
// https://elixir.bootlin.com/linux/v6.6/source/kernel/dma/coherent.c
// https://elixir.bootlin.com/linux/v6.6/source/kernel/dma/swiotlb.c
// https://elixir.bootlin.com/linux/v6.6/source/mm/cma.c
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/dmesg.h"
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define range_ctx addr_range

KASLD_EXPLAIN("Searches dmesg for CMA (Contiguous Memory Allocator) or DMA "
              "reserved memory messages that print physical address ranges. "
              "These boot-time messages reveal where the kernel reserved "
              "contiguous physical memory for DMA operations. Access is gated "
              "by dmesg_restrict.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

static void update_range(struct range_ctx *r, unsigned long addr) {
  if (!addr)
    return;
  if (!r->lo || addr < r->lo)
    r->lo = addr;
  if (addr > r->hi)
    r->hi = addr;
}

/* Parse a "<num> MiB" size token at `s` to bytes. These kernel messages always
 * print the pool size in MiB (contiguous.c / cma.c hardcode the unit); return 0
 * (size unknown) for any other unit or on overflow, so the caller falls back to
 * a base-only sample rather than fabricating a wrong extent. */
static unsigned long parse_mib_bytes(const char *s) {
  char *e;
  unsigned long mib = strtoul(s, &e, 10);
  if (e == s)
    return 0;
  while (*e == ' ')
    e++;
  if (strncmp(e, "MiB", 3) != 0)
    return 0;
  unsigned long bytes;
  if (kasld_mul_ovf(mib, MB, &bytes))
    return 0;
  return bytes;
}

/* Each pool is one contiguous reservation [addr, addr + size - 1]; emit it as a
 * bounded range when the size is known so the engine excludes the whole
 * forbidden band, else a base-only sample. Pools are sparse — the gaps between
 * them are NOT known-empty — so range, never a covering extent. */
static void emit_pool(struct range_ctx *r, unsigned long addr,
                      unsigned long bytes) {
  if (!addr)
    return;
  update_range(r, addr);

  unsigned long end;
  if (bytes && !kasld_add_ovf(addr, bytes - 1, &end))
    kasld_result_range(KASLD_TYPE_PHYS, REGION_RESERVED_MEM, addr, end, NULL,
                       CONF_PARSED);
  else
    kasld_result_sample(KASLD_TYPE_PHYS, REGION_RESERVED_MEM, addr, NULL,
                        CONF_PARSED);
}

/* "Reserved memory: created CMA memory pool at 0x..., size N MiB"
 * "Reserved memory: created DMA memory pool at 0x..., size N MiB"
 * "Reserved memory: created restricted DMA pool at 0x..., size N MiB" */
static int on_reserved_pool(const char *line, void *ctx) {
  struct range_ctx *r = ctx;

  const char *p = strstr(line, " at ");
  if (!p)
    return 1;

  unsigned long addr = strtoul(p + 4, NULL, 16);
  if (!addr)
    return 1;

  const char *s = strstr(p, ", size ");
  unsigned long bytes = s ? parse_mib_bytes(s + 7) : 0;

  kasld_info("Reserved memory pool at 0x%016lx", addr);
  emit_pool(r, addr, bytes);
  return 1; /* continue — may be multiple pools */
}

/* "cma: Reserved N MiB at 0x..."
 * v5.x:  "cma: Reserved 64 MiB at 0x00000000b4000000"
 * v6.x+: "cma: Reserved 256 MiB at 0x00000000f0000000 on node -1" */
static int on_cma_reserved(const char *line, void *ctx) {
  struct range_ctx *r = ctx;

  const char *p = strstr(line, " at ");
  if (!p)
    return 1;

  unsigned long addr = strtoul(p + 4, NULL, 16);
  if (!addr)
    return 1;

  const char *sz = strstr(line, "Reserved ");
  unsigned long bytes = sz ? parse_mib_bytes(sz + 9) : 0;

  kasld_info("CMA reservation at 0x%016lx", addr);
  emit_pool(r, addr, bytes);
  return 1; /* continue — may be multiple reservations */
}

int main(void) {
  struct range_ctx r = {0, 0};

  kasld_info("searching dmesg for CMA/DMA reserved memory pools ...");

  int ds = dmesg_search("Reserved memory: created", on_reserved_pool, &r);
  if (ds < 0)
    return KASLD_EXIT_NOPERM;

  dmesg_search("cma: Reserved", on_cma_reserved, &r);

  if (!r.lo) {
    kasld_err("No CMA/DMA reserved memory pools found in dmesg");
    return 0;
  }

  /* CMA pools are firmware/kernel-reserved memory carved out of DRAM —
   * each is emitted as its own RESERVED_MEM band in the parse callbacks. The
   * directmap projection below derives one virtual landmark from the lowest. */
  kasld_info("lowest reserved pool:  0x%016lx", r.lo);
  if (r.hi && r.hi != r.lo)
    kasld_info("highest reserved pool: 0x%016lx", r.hi);

#ifdef phys_to_directmap_virt
  unsigned long virt = phys_to_directmap_virt(r.lo);
  kasld_info("possible direct-map virtual address: 0x%016lx", virt);
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_DIRECTMAP, virt, NULL,
                      CONF_PARSED);
#else
  kasld_info("note: phys and virt KASLR are decoupled on this arch; "
             "cannot derive kernel text virtual address from physical leak");
#endif

  return 0;
}
