// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Leak the kernel virtual text base (_stext) — and, where recoverable, the
// direct-map base (page_offset_base) — from /proc/kcore's ELF program headers.
//
// /proc/kcore is the ELF core image of kernel virtual memory. It carries one
// PT_LOAD program header per kernel VA region (direct/linear map, vmalloc,
// vmemmap, and — on architectures where the kernel text has its own high
// mapping — the text). The header for the text region is built from _stext
// verbatim (fs/proc/kcore.c: kclist_add(&kcore_text, _stext, _end - _stext,
// KCORE_TEXT)), so its p_vaddr is the randomized virtual text base. Only the
// ELF header + program headers are read — never the (huge, sparse) segment
// data — so this touches a few kilobytes, not gigabytes of kernel memory.
//
// The linear-map (KCORE_RAM) headers additionally carry both the direct-map VA
// (p_vaddr) and the physical base (p_paddr) of each RAM region. The linear map
// satisfies __va(p) = page_offset_base + (p - PHYS_OFFSET), so for any RAM
// segment page_offset_base = p_vaddr - p_paddr + PHYS_OFFSET — exact, and equal
// across every RAM segment. This recovers the randomized direct-map base
// directly (a parsed pin), where existing direct-map leaks only bound it. It is
// emitted only where PHYS_OFFSET is the true runtime physical base of the map
// (PHYS_OFFSET_EXACT — x86_64); a p_paddr of 0/-1, an implausible result, or
// disagreement across segments is rejected rather than pinned.
//
//   Data leaked:      _stext (virtual text base); page_offset_base (direct-map
//                     base, where PHYS_OFFSET_EXACT)
//   Kernel subsystem: fs/proc/kcore — ELF program headers
//   Address type:     virtual (kernel text; direct map)
//   Method:           parsed (Elf phdr p_vaddr / p_paddr)
//   Gate:             opening /proc/kcore needs CAP_SYS_RAWIO (init_user_ns);
//                     reads are additionally blocked by kernel lockdown
//                     (confidentiality). The file is mode 0400 root, so an
//                     unprivileged process cannot open it — but a container
//                     granted CAP_SYS_RAWIO (e.g. docker --cap-add=SYS_RAWIO)
//                     runs as init-ns root for this check and can. This
//                     component does not test the capability: it simply tries
//                     the open, so it also fires if the file is readable for
//                     any other reason.
//
// Sound only where the kernel text has a dedicated high mapping distinct from
// the direct map (TEXT_TRACKS_DIRECTMAP == 0: x86_64, arm64, riscv64, s390).
// There, the text window contains exactly one PT_LOAD — the KCORE_TEXT segment
// — whose p_vaddr is _stext; the direct/linear map, vmalloc and vmemmap
// segments sit at distinct, lower VAs outside the text window. On coupled
// architectures the text lives inside the direct map, where a RAM segment's
// p_vaddr can fall in the text window below _stext, so the parse would be
// unsound — the component is inert there.
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kasld/cli.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:virtual\n"
           "lockdown:confidentiality\n"
           "bypass:CAP_SYS_RAWIO\n");

#if !TEXT_TRACKS_DIRECTMAP

int main(int argc, char **argv) {
  kasld_cli(argc, argv);

  int fd = kasld_open("/proc/kcore", O_RDONLY);
  if (fd < 0)
    return (errno == EACCES || errno == EPERM) ? KASLD_EXIT_NOPERM
                                               : KASLD_EXIT_UNAVAILABLE;

  /* All decoupled-text arches are LP64, so kcore is a 64-bit ELF core. */
  Elf64_Ehdr eh;
  if (pread(fd, &eh, sizeof(eh), 0) != (ssize_t)sizeof(eh) ||
      memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
      eh.e_ident[EI_CLASS] != ELFCLASS64 || eh.e_type != ET_CORE ||
      eh.e_phentsize < sizeof(Elf64_Phdr) || eh.e_phnum == 0 ||
      eh.e_phnum == PN_XNUM) {
    close(fd);
    kasld_err("/proc/kcore is not a parseable 64-bit ELF core");
    return KASLD_EXIT_UNAVAILABLE;
  }

  /* Scan the PT_LOAD program headers. The kernel-text segment's p_vaddr is
   * _stext (take the lowest text-window p_vaddr defensively — the text mapping
   * starts at its lowest address). Where PHYS_OFFSET is exact, a RAM segment's
   * p_vaddr - p_paddr + PHYS_OFFSET is page_offset_base. e_phnum is bounded so
   * a garbage header cannot spin. */
  unsigned int nph = eh.e_phnum > 8192 ? 8192 : eh.e_phnum;
  unsigned long stext = 0;
#if PHYS_OFFSET_EXACT
  unsigned long directmap_base = 0;
  int directmap_conflict = 0;
#endif
  for (unsigned int i = 0; i < nph; i++) {
    Elf64_Phdr ph;
    off_t off = (off_t)eh.e_phoff + (off_t)i * eh.e_phentsize;
    if (pread(fd, &ph, sizeof(ph), off) != (ssize_t)sizeof(ph))
      break;
    if (ph.p_type != PT_LOAD)
      continue;
    unsigned long va = (unsigned long)ph.p_vaddr;
    if (kasld_addr_is_kernel_text(va)) {
      if (stext == 0 || va < stext)
        stext = va;
      continue;
    }
#if PHYS_OFFSET_EXACT
    /* Linear-map segment: p_vaddr is a direct-map VA, p_paddr its physical
     * base. vmalloc/vmemmap headers carry p_paddr 0 (skipped); a value that
     * does not land at a plausible linear-map base, or that disagrees with an
     * earlier RAM segment, is discarded rather than pinned. */
    if (kasld_addr_is_directmap(va)) {
      unsigned long pa = (unsigned long)ph.p_paddr;
      if (pa == 0 || pa == (unsigned long)-1 || pa >= va)
        continue;
      unsigned long cand = va - pa + (unsigned long)PHYS_OFFSET;
      if (!kasld_addr_is_directmap(cand))
        continue;
      if (directmap_base == 0)
        directmap_base = cand;
      else if (cand != directmap_base)
        directmap_conflict = 1;
    }
#endif
  }
  close(fd);

  int found = 0;
  if (stext != 0) {
    kasld_found("kernel _stext from /proc/kcore program headers: 0x%lx", stext);
    kasld_result_base(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, stext, "_stext",
                      CONF_PARSED);
    found = 1;
  }
#if PHYS_OFFSET_EXACT
  if (directmap_base != 0 && !directmap_conflict) {
    kasld_found("direct-map base (page_offset_base) from /proc/kcore program "
                "headers: 0x%lx",
                directmap_base);
    /* The exact left edge of the linear map, not merely a directmap address:
     * emit it as the SF_VIRT_PAGE_OFFSET scalar so the engine pins
     * Q_PAGE_OFFSET outright, rather than as a REGION_DIRECTMAP base (which
     * memory-map projections use for __va(lowest_RAM) — an upper bound on the
     * base). */
    kasld_emit_scalar(SF_VIRT_PAGE_OFFSET, directmap_base, CONF_PARSED);
    found = 1;
  }
#endif

  if (!found) {
    kasld_err("no kernel-text or direct-map PT_LOAD segment found in "
              "/proc/kcore");
    return 0;
  }
  return 0;
}

#else /* TEXT_TRACKS_DIRECTMAP: kernel text sits inside the direct map, so a   \
       * kcore PT_LOAD p_vaddr in the text window could be a direct-map        \
       * segment start below _stext — an unsound base. Inert on coupled      \
       * arches. */

int main(void) { return 0; }

#endif
