// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read EFI runtime service virtual and physical addresses from
// /sys/firmware/efi/runtime-map/. Each numbered entry exposes five sysfs
// files: phys_addr, virt_addr, num_pages, attribute, and type. On current
// kernels these are created with __ATTR_RO_MODE(.., 0400) — root-only; an
// unprivileged user cannot read them (older kernels exposed them 0444).
//
// CONFIG_EFI_RUNTIME_MAP, which creates this directory, is an x86 option
// (arch/x86/Kconfig, selected when KEXEC_CORE is enabled); the sysfs
// interface is x86-only.
//
// Where the virtual addresses come from is a FIRMWARE-PATH question, not a
// version one. arch/x86/platform/efi/efi_64.c efi_map_region() has two
// branches: under efi_is_mixed() (32-bit firmware, 64-bit kernel) it sets
// `md->virt_addr = md->phys_addr`, a 1:1 mapping; otherwise it assigns from
// `efi_va`, which descends from EFI_VA_START through a region dedicated to EFI
// runtime services. The dedicated region is therefore the DEFAULT 64-bit path
// and has been for far longer than this component assumed. The direct-mapped
// case the technique wants came from the retired `efi=old_map` path, where
// efi_ioremap() returned __va(phys) for writeback memory.
//
// Which path a machine took cannot be read off a version — and distro version
// strings would not settle it even if it could. It is decided at runtime
// instead: a linear mapping yields ONE virt-minus-phys offset shared by every
// entry, while the dedicated region hands out addresses descending as physical
// addresses ascend, so its entries disagree. See the agreement check below,
// which is what separates them.
//
// Leak primitive:
//   Data leaked:      EFI runtime service virtual and physical addresses
//   Kernel subsystem: arch/x86/platform/efi/runtime-map.c (x86-only)
//   Data structure:   EFI memory map descriptors (efi_memory_desc_t)
//   Address type:     virtual (EFI runtime region, or direct-map on the
//                     retired efi=old_map path)
//   Method:           parsed (sysfs text files)
//   Status:           unfixed (information exposure by design)
//   Access check:     root-only (__ATTR_RO_MODE(.., 0400)) on current kernels
//   Source:
//   https://elixir.bootlin.com/linux/latest/source/arch/x86/platform/efi/runtime-map.c
//
// Mitigations:
//   On current kernels the sysfs files are mode 0400 (root-only), so an
//   unprivileged user cannot read them; the technique requires root or an
//   older kernel that exposed them world-readable.
//   Utility depends on the firmware path, not a version: where EFI runtime
//   services live in their own VA region (the default 64-bit path) the
//   virt-phys difference is not the linear-map base and is not published.
//   CONFIG_EFI_RUNTIME_MAP=n removes the sysfs entries entirely.
//
// Requires:
// - CONFIG_EFI
// - CONFIG_KEXEC_CORE (enables CONFIG_EFI_RUNTIME_MAP which creates the sysfs
//   directory; absent on stripped/virt kernels that omit kexec support)
// - UEFI-booted system (/sys/firmware/efi/runtime-map/ must exist)
//
// References:
// https://elixir.bootlin.com/linux/latest/source/arch/x86/platform/efi/runtime-map.c
// https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-firmware-efi-runtime-map
// ---
// <bcoles@gmail.com>

#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

KASLD_EXPLAIN(
    "Reads EFI runtime service virtual and physical addresses from "
    "/sys/firmware/efi/runtime-map/N/virt_addr and /phys_addr. On "
    "the retired efi=old_map firmware path, runtime service virtual "
    "addresses fall in the kernel direct-map; where phys_addr is also "
    "readable, subtracting it yields virt_page_offset_base. The default "
    "path instead maps them into a dedicated EFI region, where that "
    "difference is not the base, so a value is published only when two or "
    "more entries agree on it. "
    "On current kernels these files are mode "
    "0400 (root-only via __ATTR_RO_MODE), so an unprivileged user cannot read "
    "them; older kernels exposed them world-readable (0444). The interface is "
    "x86-only (CONFIG_EFI_RUNTIME_MAP) and requires a UEFI-booted system.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "discloses:virtual\n"
           "source:files\n"
           "config:CONFIG_EFI\n"
           "config:CONFIG_KEXEC_CORE\n");

/* (virt - phys) is the linear-map base only where the linear map anchors at
 * physical zero. Elsewhere the difference is PAGE_OFFSET - PHYS_OFFSET
 * (riscv64, PHYS_OFFSET 0x80000000), or it anchors on a base known only at
 * runtime — LM_ANCHOR_DRAM_BASE on arm32/ppc32/riscv32, LM_ANCHOR_UNKNOWABLE on
 * arm64 — and the subtraction then yields a number that is not the base and
 * must not be published as one. Checking PHYS_OFFSET alone would not do: arm32
 * declares PHYS_OFFSET 0 and still anchors on the DRAM base.
 *
 * The precondition is carried here rather than inferred from the sysfs
 * interface being x86-only. Nothing gates the read, so the guarantee would
 * otherwise rest on where the kernel happens to keep runtime-map.c.
 *
 * Spelled without a cast: this is tested with #if, where the preprocessor knows
 * no types and a cast is a syntax error. */
#define EFI_VIRT_MINUS_PHYS_IS_PAGE_OFFSET                                     \
  (LINEAR_MAP_ANCHOR == LM_ANCHOR_PHYS_OFFSET && PHYS_OFFSET == 0)

/* Candidate linear-map bases, one per entry that yielded both addresses. Capped
 * because a firmware memory map is attacker-visible input; entries past the cap
 * still publish their virtual sample, they just stop voting. */
#define EFI_MAX_OFFSETS 128

int main(void) {
  const char *base = "/sys/firmware/efi/runtime-map";
  unsigned long cand[EFI_MAX_OFFSETS];
  int n_cand = 0;
  DIR *d;
  struct dirent *ent;
  char path[512];
  char buf[64];
  int count = 0;

  kasld_info("searching %s for EFI runtime service virtual addresses ...",
             base);

  d = kasld_opendir(base);
  if (!d) {
    int e = errno;
    perror("[-] opendir");
    return (e == EACCES || e == EPERM) ? KASLD_EXIT_NOPERM
                                       : KASLD_EXIT_UNAVAILABLE;
  }

  int denied = 0; /* a per-entry read failed with EACCES/EPERM */
  while ((ent = readdir(d)) != NULL) {
    if (ent->d_name[0] == '.')
      continue;

    snprintf(path, sizeof(path), "%s/%s/virt_addr", base, ent->d_name);
    if (kasld_read_file_line(path, buf, sizeof(buf)) < 0) {
      if (errno == EACCES || errno == EPERM)
        denied = 1;
      continue;
    }

    unsigned long virt;
    if (!kasld_addr_parse(buf, 16, &virt, NULL) || !virt)
      continue;

    /* Must land in the direct-map window: at or above PAGE_OFFSET, below kernel
     * text. Rejects physical-range values on systems where
     * SetVirtualAddressMap was never called or used identity mapping.
     *
     * It does NOT establish that the address IS direct-map. The window is drawn
     * as "below the text window" and so also spans the dedicated EFI runtime VA
     * region, which is where efi_map_region() puts these on the default x86_64
     * path. kasld_addr_classify() reports that ambiguity instead of resolving
     * it, so the sample is published as a band where the windows overlap. */
    if (!kasld_addr_is_directmap(virt))
      continue;
    /* Having passed the window test this cannot come back REGION_UNKNOWN --
     * classify answers MODULE_BAND or DIRECTMAP_BAND for anything inside it --
     * so there is no unknown case to handle here. */
    enum kasld_region vregion = kasld_addr_classify(virt);

    /* The virtual address is evidence in its own right, and it is the same
     * evidence whether or not phys_addr can be read: publish it for every
     * accepted entry. Emitting it only on the phys-failure paths made the
     * component disclose MORE when it understood LESS -- an unreadable
     * phys_addr yielded a sample, while a readable one whose offsets disagreed
     * yielded nothing at all. */
    kasld_info("EFI runtime entry %s: virt=0x%016lx", ent->d_name, virt);
    kasld_result_sample(KASLD_TYPE_VIRT, vregion, virt, NULL, CONF_PARSED);
    count++;

    snprintf(path, sizeof(path), "%s/%s/phys_addr", base, ent->d_name);
    if (kasld_read_file_line(path, buf, sizeof(buf)) < 0)
      continue;

    /* An unparseable phys_addr — including one too wide for this build — falls
     * through to the same handling as a nonsensical one: publish the virtual
     * sample alone rather than deriving a page offset from a value that was
     * never read. */
    unsigned long phys;
    if (!kasld_addr_parse(buf, 16, &phys, NULL) || phys > virt)
      continue;

    /* A candidate linear-map base, NOT yet a result: one entry cannot show that
     * the mapping it came from is linear. Collected and decided after the loop.
     */
    unsigned long virt_page_offset = virt - phys;
    if (!kasld_addr_in_window(virt_page_offset,
                              (unsigned long)KERNEL_VIRT_VAS_START,
                              (unsigned long)KERNEL_VIRT_TEXT_MIN))
      continue;

    kasld_info("EFI runtime entry %s: virt=0x%016lx phys=0x%016lx"
               " => candidate virt_page_offset=0x%016lx",
               ent->d_name, virt, phys, virt_page_offset);
    if (n_cand < EFI_MAX_OFFSETS)
      cand[n_cand++] = virt_page_offset;
  }
  closedir(d);

  /* A linear mapping is ONE offset: virt - phys is identical for every address
   * mapped through it. The EFI runtime mapping is not linear — efi_map_region()
   * walks efi_va DOWNWARD while physical addresses ascend — so its entries
   * disagree, and agreement is what separates the two.
   *
   * That test needs no EFI constant. EFI_VA_START/END are x86-only, have
   * already moved once, and describe one firmware path; "the offset is the same
   * every time" is what being a linear map MEANS.
   *
   * Reproduced before this check existed: three entries from a default x86_64
   * UEFI map yielded three different offsets, and the lowest pinned the
   * GUARANTEED direct-map base to a single wrong value. */
  unsigned long agreed = 0;
  int best = 0;
  for (int i = 0; i < n_cand; i++) {
    int votes = 0;
    for (int j = 0; j < n_cand; j++)
      if (cand[j] == cand[i])
        votes++;
    if (votes > best) {
      best = votes;
      agreed = cand[i];
    }
  }

#if EFI_VIRT_MINUS_PHYS_IS_PAGE_OFFSET
  if (best >= 2) {
    /* Second, independent net where the architecture models it:
     * RANDOMIZE_MEMORY_ALIGN is the alignment the kernel places
     * page_offset_base on (PUD, 1 GiB on x86_64), and 0 elsewhere, where the
     * mask collapses and this is a no-op — the same idiom as
     * directmap_page_offset_bounds.
     *
     * Which net carries the weight depends on the target: on x86_64 both apply,
     * and the alignment one is the stronger of the two because a coincidental
     * offset shared by two entries in the dedicated region is unlikely to also
     * be PUD-aligned. On x86_32 -- the only other arch that can reach this
     * code, since the precondition admits seven arches but the sysfs interface
     * is x86-only -- RANDOMIZE_MEMORY_ALIGN is 0 and agreement carries alone.
     */
    const unsigned long align = (unsigned long)RANDOMIZE_MEMORY_ALIGN;
    if (align && (agreed & (align - 1))) {
      kasld_err("EFI entries agree on 0x%016lx but it is not %lu-aligned;"
                " not a linear-map base",
                agreed, align);
    } else {
      kasld_info("%d EFI entries agree: virt_page_offset=0x%016lx", best,
                 agreed);
      /* CONF_DERIVED, not CONF_PARSED. The ladder is a TRUST ordering, and what
       * is trusted here is not a parse: the two addresses come straight from
       * sysfs, but the claim that their difference is the linear-map base rests
       * on the agreement inference above. Above the sound floor either way, so
       * this is lineage honesty rather than a window change — a reader asking
       * "what is this number's provenance" gets the right answer. */
      kasld_result_sample(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, agreed, NULL,
                          CONF_DERIVED);
      count++;
    }
  } else if (n_cand > 0) {
    kasld_err("EFI runtime entries disagree on virt - phys (%d candidates,"
              " %d agreeing) — a dedicated EFI mapping, not the linear map",
              n_cand, best);
  }
#else
  if (n_cand > 0)
    kasld_err("virt - phys is not the linear-map base on this architecture"
              " (%d candidates dropped)",
              n_cand);
  (void)agreed;
  (void)best;
#endif

  if (!count) {
    /* The virt_addr/phys_addr attributes are root-only (0400). If the directory
     * listed but every entry read was denied, report access-denied rather than
     * data-absent. */
    if (denied) {
      kasld_err("EFI runtime map entries are not readable (needs root)");
      return KASLD_EXIT_NOPERM;
    }
    kasld_err("no EFI runtime map entries with direct-map virtual addresses"
              " found");
    return 0;
  }

  return 0;
}
