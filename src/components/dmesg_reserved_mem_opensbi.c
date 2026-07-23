// This file is part of KASLD - https://github.com/bcoles/kasld
//
// On RISC-V systems, the OpenSBI firmware runs in M-mode (machine mode) and
// reserves physical memory at the DRAM base for its own use before handing
// off to the S-mode kernel. These reserved regions are exposed in dmesg via
// the device tree reserved memory infrastructure.
//
// For example:
//
// [    0.000000] OF: reserved mem: 0x0000000080000000..0x000000008001ffff
//   (128 KiB) nomap non-reusable mmode_resv0@80000000
// [    0.000000] OF: reserved mem: 0x0000000080020000..0x000000008003ffff
//   (128 KiB) nomap non-reusable mmode_resv1@80020000
//
// The physical address of mmode_resv0 reveals the DRAM base address.
// On RISC-V, the kernel is conventionally loaded at DRAM_BASE + 2MB
// (after the OpenSBI firmware reservation).
//
// On systems with a known phys->virt offset mapping (i.e. without KASLR or
// pre-v6.6 kernels), this may be used to identify the kernel virtual address.
//
// Leak primitive:
//   Data leaked:      physical DRAM base address (OpenSBI M-mode reservation)
//   Kernel subsystem: drivers/of/fdt_reserved_mem — mmode_resv0 DT node
//   Data structure:   reserved memory node (physical address of DRAM base)
//   Address type:     physical (DRAM)
//   Method:           parsed (dmesg string)
//   Status:           unfixed (printed unconditionally on RISC-V with OpenSBI)
//   Access check:     do_syslog() → check_syslog_permissions(); gated by
//                     dmesg_restrict
//   Source:
//   https://elixir.bootlin.com/linux/v6.1.1/source/drivers/of/fdt_reserved_mem.c
//
// Mitigations:
//   Access gated by dmesg_restrict (see dmesg.h for shared access gate
//   details). RISC-V only. On RISC-V 64 with KASLR (v6.6+, decoupled),
//   physical addresses cannot derive the virtual text base.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v6.1.1/source/drivers/of/fdt_reserved_mem.c
// https://github.com/riscv-software-src/opensbi
// ---
// <bcoles@gmail.com>

#if !defined(__riscv) && !defined(__riscv__)
#error "Architecture is not supported"
#endif

#define _GNU_SOURCE
#include "include/dmesg.h"
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Searches dmesg for OpenSBI M-mode reserved memory (mmode_resv0@) "
    "messages on RISC-V. The reservation address is typically at the "
    "start of physical DRAM, revealing the DRAM base. RISC-V only. "
    "Access is gated by dmesg_restrict.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

static const char *needle = "mmode_resv0@";

static int on_match(const char *line, void *ctx) {
  unsigned long *result = ctx;
  char *endptr;

  const char *p = strstr(line, needle);
  if (!p)
    return 1;

  /* mmode_resv0@80000000 */
  unsigned long addr = strtoul(p + strlen(needle), &endptr, 16);

  if (addr == 0 || addr >= KERNEL_VIRT_VAS_END)
    return 1;

  kasld_found("leaked OpenSBI DRAM physical address: 0x%016lx", addr);
  *result = addr;
  return 0;
}

int main(void) {
  unsigned long phys_addr = 0;

  kasld_info("searching dmesg for OpenSBI reserved memory regions ...");
  int ds = dmesg_search("mmode_resv0@", on_match, &phys_addr);

  if (!phys_addr) {
    if (ds < 0)
      return KASLD_EXIT_NOPERM;
    kasld_err("OpenSBI reserved memory not found in dmesg");
    return 0;
  }

  kasld_result_sample(KASLD_TYPE_PHYS, REGION_RESERVED_MEM, phys_addr, NULL,
                      CONF_PARSED);

  /* On older firmware, mmode_resv0 started at DRAM_BASE and the kernel
   * loaded at DRAM_BASE + RISCV_PHYS_LOAD_OFFSET. On newer firmware, the
   * reservation may be placed at an arbitrary offset within DRAM. Only derive
   * the kernel text address if the reservation appears DRAM-base-aligned (i.e.
   * aligned to at least KASLR_PHYS_ALIGN). */
  if ((phys_addr & (KASLR_PHYS_ALIGN - 1)) != 0) {
    kasld_info("note: mmode_resv0 at 0x%016lx is not %lu MiB aligned; "
               "skipping text derivation",
               phys_addr, KASLR_PHYS_ALIGN / MB);
    return 0;
  }

  unsigned long kernel_phys = phys_addr + RISCV_PHYS_LOAD_OFFSET;

  kasld_info("possible kernel physical address: 0x%016lx", kernel_phys);
  /* kernel_phys is a firmware CONVENTION (reservation + fixed load offset), not
   * an observed image address. It holds only when mmode_resv0 sits at the DRAM
   * base and the kernel is loaded immediately above it; on firmware that places
   * the reservation at an arbitrary DRAM offset, or where the physical load
   * address is randomized independently of the reservation, the true image base
   * can lie ABOVE kernel_phys. A kernel-image PHYS witness bounds the physical
   * base from above (kernel_image_phys_bound), so promoting this convention to
   * the guaranteed floor (CONF_INFERRED+) would forge a C_UPPER_BOUND that can
   * exclude the true base. Emit at CONF_HEURISTIC: it shapes the likely window
   * but the engine's floor gate keeps it out of the guaranteed one. */
  kasld_result_sample(KASLD_TYPE_PHYS, REGION_KERNEL_IMAGE, kernel_phys, NULL,
                      CONF_HEURISTIC);

#if defined(phys_to_directmap_virt) && TEXT_TRACKS_DIRECTMAP
  /* The directmap projection only yields the kernel-image virt when text
   * sits at the linear-map offset; the second gate makes that precondition
   * explicit so a future (DIRECTMAP_STATIC=1, TEXT_TRACKS_DIRECTMAP=0) arch
   * fails to emit rather than silently misclassifying a directmap alias as
   * a kernel-image virt. */
  unsigned long virt = phys_to_directmap_virt(kernel_phys);
  kasld_info("possible kernel virtual address: 0x%016lx", virt);
  /* Derived from the same convention-based kernel_phys (see above), so it
   * carries the same confidence — likely window only, never a guaranteed
   * bound. */
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, virt, NULL,
                      CONF_HEURISTIC);
#else
  kasld_info("note: kernel text virtual address cannot be derived from phys on "
             "this arch (text does not track the linear map)");
#endif

  return 0;
}
