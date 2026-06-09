// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Parses the kernel binary fingerprint from /sys/kernel/notes — the ELF
// notes section of vmlinux, exposed by every architecture since v2.6.23.
// World-readable (0444), no sysctl gate, no CONFIG dependency, built into
// every kernel (NOTES placement in arch/*/kernel/vmlinux.lds.S). Survives
// kptr_restrict / lockdown / kernel.dmesg_restrict because the data is
// vmlinux metadata, not kernel-state.
//
// The fingerprint is metadata-only — it is not consumed by any inference
// rule. The build_id uniquely identifies the running kernel binary; an
// operator who has obtained a vmlinux through some other means can
// cross-check it with `readelf -n` to confirm it matches the live
// kernel before trusting any symbol lookup against it. How the operator
// obtains that vmlinux is out of scope — analysis host distro often
// differs from target distro, custom-built kernels have no package at
// all, and debuginfod has narrow kernel coverage. The component just
// emits the identifier.
//
// Recognised notes:
//
//   NT_GNU_BUILD_ID                 (type 3,     name "GNU")
//     16- or 20-byte content hash of vmlinux at link time. Identifies the
//     exact binary; same source + toolchain → same value.
//
//   LINUX_ELFNOTE_BUILD_SALT        (type 0x100, name "Linux")
//     NUL-terminated CONFIG_BUILD_SALT (init/version.c:40 +
//     include/linux/build-salt.h:6). Empty in mainline; distros set it to
//     a version string (e.g. Debian "6.12.90+deb13-riscv64").
//
//   LINUX_ELFNOTE_LTO_INFO          (type 0x101, name "Linux")
//     4-byte int. 1 = LTO build (CONFIG_LTO_CLANG=y).
//
//   FDO_PACKAGING_METADATA          (type 0xCAFE1A7E, name "FDO")
//     JSON blob carrying distro / package / version. Adopted by Ubuntu
//     since 24.04; example: {"type":"deb","os":"ubuntu","name":"linux",
//     "version":"7.0.0-14.14","architecture":"x86_64"}.
//
// Output is informational printed lines (visible under -v):
//
//   kernel.build_id: 30ceb89f003c24fa1eeae3e2a62780c0e09d9007
//   kernel.build_salt: "6.12.90+deb13-riscv64"
//   kernel.lto: 0
//   kernel.fdo_packaging: {"type":"deb",...}
//
// No tagged results, no scalar facts. The fingerprint is opaque to the
// inference engine and the orchestrator just prints it under -v.
//
// Endianness: the orchestrator and component are built for the target
// arch; /sys/kernel/notes is written by the host kernel in host
// endianness, so the uint32_t reads match without conversion. Big-endian
// targets (ppc / ppc64-BE, s390) parse correctly under the matching
// cross-built binary.
//
// Leak primitive:
//   Data leaked:      vmlinux build-id, build salt, LTO flag, FDO metadata
//   Kernel subsystem: arch/*/kernel/vmlinux.lds.S (NOTES placement) +
//                     init/version.c emission
//   Data structure:   ELF notes (struct Elf_Nhdr + name + desc, 4-byte
//                     aligned)
//   Address type:     none (metadata, not addresses)
//   Method:           parsed (binary ELF notes)
//   Status:           unfixed; vmlinux metadata, KASLR-independent
//   Access check:     none (0444; no sysctl, no lockdown gate)
//   Source:
//   https://elixir.bootlin.com/linux/v6.12/source/init/version.c#L40
//   https://elixir.bootlin.com/linux/v6.12/source/include/linux/build-salt.h
//   https://elixir.bootlin.com/linux/v6.12/source/include/linux/elfnote-lto.h
//
// Mitigations:
//   None. The fingerprint identifies the binary, not the running kernel
//   state. A distro that builds with CONFIG_BUILD_SALT unset still ships
//   a unique build_id. The only way to hide this on a stock kernel is to
//   patch out the NOTES placement (no upstream distro does so).
//
// Requires:
// - Readable /sys/kernel/notes (universal since v2.6.23).
//
// /sys/kernel/notes was introduced in kernel v2.6.23-rc1~389 on 2007-07-20:
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=da1a679cde9b12d6e331f43d2d92a234f2d1f9b0
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define ALIGN4(x) (((x) + 3u) & ~3u)

/* Note types per include/uapi/linux/elf.h (GNU) and include/linux/build-salt.h
 * + include/linux/elfnote-lto.h (Linux), plus the systemd-defined FDO
 * packaging metadata convention. The "type" field on a note is a 32-bit
 * unsigned int; the "name" disambiguates the namespace. */
#define NT_GNU_BUILD_ID 3                 /* name "GNU" */
#define LINUX_ELFNOTE_BUILD_SALT 0x100    /* name "Linux" */
#define LINUX_ELFNOTE_LTO_INFO 0x101      /* name "Linux" */
#define FDO_PACKAGING_METADATA 0xCAFE1A7E /* name "FDO" — distro JSON blob */

/* Maximum descriptor we will read. NT_GNU_BUILD_ID is 20 bytes (SHA-1);
 * FDO JSON can run into low hundreds of bytes on rich distro entries;
 * BUILD_SALT is bounded by Kconfig string length (typically under 64).
 * 1024 covers every realistic case while keeping the stack buffer small. */
#define KNB_MAX_DESC 1024u

KASLD_EXPLAIN(
    "Reads /sys/kernel/notes (world-readable, 0444) and emits the kernel "
    "binary fingerprint: GNU build_id (content hash of vmlinux), "
    "CONFIG_BUILD_SALT (distro version string when set), CONFIG_LTO_CLANG "
    "flag, and FDO packaging metadata JSON. The fingerprint identifies "
    "the exact kernel binary independent of KASLR. Metadata-only — not "
    "consumed by any inference rule. Built into every kernel since "
    "v2.6.23.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:none\n");

/* Print a hex-encoded descriptor (build_id is binary; render lowercase
 * without separators to match `readelf -n` and debuginfod lookup keys). */
static void print_hex_desc(const char *label, const unsigned char *p,
                           size_t n) {
  printf("%s: ", label);
  for (size_t i = 0; i < n; i++)
    printf("%02x", p[i]);
  putchar('\n');
}

/* Print a string descriptor with safe display: escape control characters
 * and quotes so a malformed descriptor cannot disrupt the verbose log. */
static void print_str_desc(const char *label, const char *p, size_t n) {
  /* Trim any trailing NULs from the descriptor (BUILD_SALT is
   * NUL-terminated and 4-byte aligned, so a 14-byte payload comes back
   * with 2 trailing NULs). */
  while (n > 0 && p[n - 1] == '\0')
    n--;
  printf("%s: \"", label);
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)p[i];
    if (c == '\\' || c == '"')
      printf("\\%c", c);
    else if (c >= 0x20 && c < 0x7f)
      putchar(c);
    else
      printf("\\x%02x", c);
  }
  printf("\"\n");
}

int main(void) {
  const char *path = "/sys/kernel/notes";
  int fd;
  uint32_t hdr[3]; /* namesz, descsz, type */
  unsigned char namebuf[16];
  unsigned char descbuf[KNB_MAX_DESC];
  int seen_buildid = 0;
  int seen_salt = 0;
  int seen_lto = 0;
  int seen_fdo = 0;

  kasld_info("reading %s ...", path);

  fd = kasld_open(path, O_RDONLY);
  if (fd < 0) {
    perror("[-] open(/sys/kernel/notes)");
    return (errno == EACCES || errno == EPERM) ? KASLD_EXIT_NOPERM
                                               : KASLD_EXIT_UNAVAILABLE;
  }

  while (read(fd, hdr, sizeof hdr) == (ssize_t)sizeof hdr) {
    uint32_t namesz = hdr[0];
    uint32_t descsz = hdr[1];
    uint32_t type = hdr[2];
    uint32_t name_padded = ALIGN4(namesz);
    uint32_t desc_padded = ALIGN4(descsz);

    /* Bound the name to a small fixed buffer; anything longer is a
     * malformed note and we abort the scan rather than allocate. */
    if (name_padded == 0 || name_padded > sizeof namebuf) {
      /* Skip the body to stay aligned, but stop interpreting. */
      break;
    }
    if (read(fd, namebuf, name_padded) != (ssize_t)name_padded)
      break;
    /* The kernel's emitters always NUL-terminate the name field; the
     * NUL is counted in namesz. Defensive: force NUL at the last byte
     * so strcmp cannot overrun on a malformed payload. */
    namebuf[name_padded - 1] = '\0';

    /* Read the descriptor, bounded by KNB_MAX_DESC. Anything larger is
     * skipped (lseek over the padded body) so we can continue the scan
     * — distros may add notes we do not recognise. */
    if (desc_padded > KNB_MAX_DESC) {
      if (lseek(fd, (off_t)desc_padded, SEEK_CUR) == (off_t)-1)
        break;
      continue;
    }
    if (desc_padded > 0 &&
        read(fd, descbuf, desc_padded) != (ssize_t)desc_padded)
      break;

    const char *name = (const char *)namebuf;

    /* --- NT_GNU_BUILD_ID ---------------------------------------------- */
    if (strcmp(name, "GNU") == 0 && type == NT_GNU_BUILD_ID && descsz > 0 &&
        descsz <= 64) {
      print_hex_desc("kernel.build_id", descbuf, descsz);
      seen_buildid = 1;
      continue;
    }

    /* --- LINUX_ELFNOTE_BUILD_SALT and LINUX_ELFNOTE_LTO_INFO --------- */
    if (strcmp(name, "Linux") == 0) {
      if (type == LINUX_ELFNOTE_BUILD_SALT) {
        print_str_desc("kernel.build_salt", (const char *)descbuf, descsz);
        seen_salt = 1;
        continue;
      }
      if (type == LINUX_ELFNOTE_LTO_INFO && descsz == 4) {
        uint32_t lto;
        memcpy(&lto, descbuf, sizeof lto);
        printf("kernel.lto: %u\n", lto);
        seen_lto = 1;
        continue;
      }
    }

    /* --- FDO_PACKAGING_METADATA --------------------------------------- */
    if (strcmp(name, "FDO") == 0 && type == FDO_PACKAGING_METADATA &&
        descsz > 0) {
      /* The FDO descriptor is a NUL-terminated JSON string. Print it
       * with the same escape rules as build_salt so a misformatted blob
       * cannot break the verbose log. */
      print_str_desc("kernel.fdo_packaging", (const char *)descbuf, descsz);
      seen_fdo = 1;
      continue;
    }
  }

  close(fd);

  if (!seen_buildid && !seen_salt && !seen_lto && !seen_fdo) {
    kasld_err("no recognised fingerprint notes in %s", path);
    return 0;
  }

  return 0;
}
