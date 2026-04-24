// This file is part of KASLD - https://github.com/bcoles/kasld
//
// The ACPI subsystem prints table headers via acpi_tb_print_table_header()
// whenever a table is installed. For statically-discovered tables (XSDT,
// FACP, DSDT, ...) the kernel prints the *physical* address the firmware
// placed the table at:
//
//   ACPI: SSDT 0x000000002823FB28 00046D (v01 SataRe SataTabl ...)
//
// For *dynamically* loaded OEM tables — most commonly the SSDTs that
// firmware hands to the kernel during early boot to describe CPU power
// management (Cpu0Ist, Cpu0Cst, ApIst, ApCst), loaded by ACPICA via
// acpi_tb_install_and_load_table() — the kernel prints the *virtual*
// address where it mapped the freshly-allocated table:
//
//   ACPI: Dynamic OEM Table Load:
//   ACPI: SSDT 0xFFFF8881010B6000 0005DC (v02 PmRef  Cpu0Ist  ...)
//
// These dynamic-load addresses land in the kernel direct-map region
// (page_offset_base + phys), so they leak a direct-map virtual address
// and bound page_offset_base to KASLR granularity (1 GiB on x86_64).
// The static-table lines are filtered out by range-checking the parsed
// address against the direct-map region.
//
// On any Intel x86 system with acpi_processor / intel_pstate drivers the
// four P-state/C-state SSDTs are loaded unconditionally at boot, so this
// pattern is present on the vast majority of real-world Linux installs,
// not just those with exotic firmware.
//
// Leak primitive:
//   Data leaked:      direct-map virtual address of a dynamically-loaded
//                     ACPI table (bounds page_offset_base / physmap base)
//   Kernel subsystem: drivers/acpi/acpica — acpi_tb_print_table_header()
//   Data structure:   ACPI SSDT (or other dynamic OEM table) header
//   Address type:     virtual (direct-map / page_offset)
//   Method:           parsed (dmesg string)
//   Status:           unfixed (printed unconditionally when dynamic OEM
//                     tables are loaded)
//   Access check:     do_syslog() → check_syslog_permissions(); gated by
//                     dmesg_restrict
//   Source:
//   https://elixir.bootlin.com/linux/v6.12/source/drivers/acpi/acpica/tbprint.c
//
// Mitigations:
//   Access gated by dmesg_restrict (see dmesg.h for shared access gate
//   details). The address format (virtual vs physical) cannot be
//   controlled from userspace — it reflects where ACPICA mapped the
//   table, which is direct-map for dynamically-allocated tables.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
// - ACPI enabled (CONFIG_ACPI); an ACPI-using architecture (typically
//   x86_64, x86_32, arm64, ia64).
// - Firmware that supplies dynamic OEM tables (nearly all Intel x86
//   systems via acpi_processor P-state/C-state SSDTs).
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/drivers/acpi/acpica/tbprint.c
// https://elixir.bootlin.com/linux/v6.12/source/drivers/acpi/acpica/tbxfload.c
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/dmesg.h"
#include "include/kasld.h"
#include "include/kasld_internal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct ssdt_ctx {
  unsigned long addr;
  char label[32];
};

KASLD_EXPLAIN(
    "Searches dmesg for ACPI dynamic OEM table load messages. When the "
    "kernel loads dynamic tables (most commonly the four CPU P-state / "
    "C-state SSDTs on Intel systems), it prints the direct-map virtual "
    "address of the mapped table. This bounds page_offset_base / the "
    "direct-map base to KASLR granularity. Access is gated by "
    "dmesg_restrict.");

KASLD_META("method:parsed\n"
           "addr:virtual\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

static int on_match(const char *line, void *ctx) {
  struct ssdt_ctx *s = ctx;

  /* Expected forms:
   *   ACPI: SSDT 0xFFFF8881010B6000 0005DC (v02 PmRef  Cpu0Ist  ...)
   *   ACPI: SSDT 0x000000002823FB28 00046D (v01 SataRe SataTabl ...)
   * The second (physical) form is filtered out by range check below. */
  const char *p = strstr(line, " 0x");
  if (!p)
    return 1;

  char *endptr;
  unsigned long addr = strtoul(p + 1, &endptr, 16);
  if (!addr)
    return 1;

  /* Direct-map addresses land between PAGE_OFFSET (VAS upper-half start)
   * and KERNEL_BASE_MIN (start of kernel text region). Physical addresses
   * printed for static tables are well below PAGE_OFFSET and get rejected. */
  if (addr < PAGE_OFFSET || addr >= KERNEL_BASE_MIN)
    return 1;

  /* Capture OEM table id (e.g. "Cpu0Ist", "ApCst") for the result label.
   * Format: "... (vNN OEMID OEMTABLEID ..." — the OEMTABLEID is the
   * 3rd whitespace-separated token inside the parens. */
  const char *paren = strchr(endptr, '(');
  if (paren) {
    const char *tok = paren + 1;
    /* skip version token */
    while (*tok && *tok != ' ')
      tok++;
    while (*tok == ' ')
      tok++;
    /* skip OEM id token */
    while (*tok && *tok != ' ')
      tok++;
    while (*tok == ' ')
      tok++;
    /* copy OEM table id token */
    int i = 0;
    while (*tok && *tok != ' ' && (size_t)i < sizeof(s->label) - 1)
      s->label[i++] = *tok++;
    s->label[i] = '\0';
  }

  /* First match wins; all dynamic SSDTs live in the same direct-map
   * region, so one address fully constrains page_offset_base. */
  s->addr = addr;
  return 0;
}

int main(void) {
  struct ssdt_ctx s = {0, {0}};

  printf("[.] searching dmesg for ACPI dynamic OEM table loads ...\n");
  int ds = dmesg_search("ACPI: SSDT 0x", on_match, &s);

  if (!s.addr) {
    printf("[-] no ACPI dynamic OEM table load with a direct-map virtual "
           "address found in dmesg\n");
    if (ds < 0)
      return KASLD_EXIT_NOPERM;
    return 0;
  }

  printf("ACPI dynamic SSDT direct-map virtual address: 0x%016lx", s.addr);
  if (s.label[0])
    printf(" (%s)", s.label);
  printf("\n");

  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, s.addr,
               "dmesg_acpi_dynamic_ssdt:directmap");

  return 0;
}
