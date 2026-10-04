// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read the x86_64 PVH physical-relocation ELF note from /sys/kernel/notes and
// emit the build constants it carries as scalar facts.
//
// XEN_ELFNOTE_PHYS32_RELOC (type 19) is emitted by arch/x86/platform/pvh/head.S
// under CONFIG_PVH on x86_64 as up to three 32-bit values, read in this order:
//
//   CONFIG_PHYSICAL_ALIGN   the required load alignment
//   LOAD_PHYSICAL_ADDR      the lowest address the image may start at
//   KERNEL_IMAGE_SIZE - 1   the highest address its last byte may occupy
//
// Its presence tells a monitor the kernel can relocate itself physically; what
// it is read for here is the three constants, which are otherwise only
// available from a kernel config.
//
// Why this source is worth having beside the config readers:
//
//   - It is the RUNNING kernel's own .notes section, published by
//     kernel/ksysfs.c, so it is bound to the kernel being analysed. An unkeyed
//     /boot/config may belong to a different build.
//   - /sys/kernel/notes is mode 0444 and no sysctl gates it, so these facts
//     survive kptr_restrict, dmesg_restrict and perf_event_paranoid alike.
//   - A kernel entered through the PVH entry point has a boot_params the kernel
//     synthesized itself, carrying no "HdrS" magic and therefore no build-time
//     setup-header fields at all; and a guest need not ship
//     CONFIG_IKCONFIG_PROC. This note answers where both of those are silent.
//
// These are BUILD facts, true whichever way the kernel was entered, so the note
// is equally present and equally valid on an ordinary compressed boot.
//
// KERNEL_IMAGE_SIZE is 1 GiB under CONFIG_RANDOMIZE_BASE and 512 MiB without it
// (arch/x86/include/asm/page_64_types.h), an exact two-way split, so the third
// value answers whether that option was configured. Only those two sizes are
// recognised: a kernel using some third value is not described by this
// reasoning and nothing is emitted for it.
//
// What the note cannot say: whether the randomizer actually RAN. That is
// written at boot into boot_params.hdr.loadflags by the boot stub, which a PVH
// entry never reaches. CONFIG_RANDOMIZE_BASE=y selects compile-time sizes and
// no more, so the positive case emits SF_KASLR_COMPILED_IN and never
// SF_KASLR_RANDOMIZED.
//
// The note was added in v6.12 (47ffe0578aee); kernels before it carry the PVH
// entry note alone and this component emits nothing.
//
// x86_64 only: the note sits inside the CONFIG_X86_64 arm of head.S.
// ---
// <bcoles@gmail.com>
#if !defined(__x86_64__) && !defined(__amd64__)
#error "Architecture is not supported"
#endif

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Reads XEN_ELFNOTE_PHYS32_RELOC from /sys/kernel/notes, the PVH "
    "physical-relocation note the running kernel publishes from its own .notes "
    "section. It carries CONFIG_PHYSICAL_ALIGN, LOAD_PHYSICAL_ADDR and "
    "KERNEL_IMAGE_SIZE-1 as build constants, giving the KASLR slot "
    "granularity, "
    "the physical floor, and - from the image size, an exact two-way split - "
    "whether CONFIG_RANDOMIZE_BASE was configured at all. The file is mode "
    "0444 "
    "and no sysctl gates it, so these facts survive kptr_restrict, "
    "dmesg_restrict and perf_event_paranoid; they are also readable where a "
    "synthesized boot_params carries no setup header and no kernel config is "
    "exposed. x86_64 kernels built with CONFIG_PVH that carry the note: it "
    "appeared "
    "upstream in v6.12 and may be carried on an older base, so what is read is "
    "the note itself and never a version.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "discloses:facts\n"
           "source:files\n"
           "config:CONFIG_PVH\n");

#define XEN_ELFNOTE_PHYS32_RELOC 19

/* KERNEL_IMAGE_SIZE - 1, the only two values x86_64 defines. */
#define KIMG_SIZE_RANDOMIZE_BASE (0x40000000ul - 1) /* 1 GiB   => =y */
#define KIMG_SIZE_PLAIN (0x20000000ul - 1)          /* 512 MiB => =n */

#define ALIGN4(x) (((x) + 3u) & ~3u)

int main(void) {
  uint32_t hdr[3]; /* namesz, descsz, type */
  char buf[512];
  int found = 0;

  kasld_info("checking /sys/kernel/notes for the PVH relocation note ...");

  int fd = kasld_open("/sys/kernel/notes", O_RDONLY);
  if (fd < 0) {
    kasld_err("/sys/kernel/notes unavailable");
    return (errno == EACCES || errno == EPERM) ? KASLD_EXIT_NOPERM
                                               : KASLD_EXIT_UNAVAILABLE;
  }

  while (read(fd, hdr, sizeof hdr) == (ssize_t)sizeof hdr) {
    uint32_t namesz = hdr[0], descsz = hdr[1], type = hdr[2];

    /* namesz and descsz come from a structure this process does not own. Reject
     * anything too large before aligning, so ALIGN4 cannot wrap a huge value
     * into a small total and walk past the buffer. */
    if (namesz > sizeof buf || descsz > sizeof buf)
      break;
    uint32_t name_aligned = ALIGN4(namesz);
    uint32_t total = name_aligned + ALIGN4(descsz);
    if (total > sizeof buf)
      break;
    if (total > 0 && read(fd, buf, total) != (ssize_t)total)
      break;
    if (namesz == 0 || descsz == 0)
      continue;

    char *name = buf;
    char *desc = buf + name_aligned;
    name[namesz - 1] = '\0'; /* namesz counts the trailing NUL */

    if (type != XEN_ELFNOTE_PHYS32_RELOC || strcmp(name, "Xen") != 0)
      continue;

    /* Up to three 32-bit values. A trailing value the kernel omitted is not an
     * answer: the documented defaults stand in for a LOADER, which can also see
     * the program headers this process cannot, so nothing is emitted for a
     * field that is not there. */
    unsigned n = descsz / 4;
    if (n == 0)
      continue;
    if (n > 3)
      n = 3;
    uint32_t v[3] = {0, 0, 0};
    memcpy(v, desc, (size_t)n * 4);
    found = 1;

    if (v[0]) {
      kasld_info("CONFIG_PHYSICAL_ALIGN: %#lx", (unsigned long)v[0]);
      kasld_emit_scalar(SF_PHYS_KERNEL_ALIGN, v[0], CONF_PARSED);
    }

    if (n > 1 && v[1]) {
      kasld_info("LOAD_PHYSICAL_ADDR: %#lx", (unsigned long)v[1]);
      kasld_emit_scalar(SF_PHYSICAL_START, v[1], CONF_PARSED);
    }

    if (n > 2) {
      unsigned long last = v[2];
      if (last == KIMG_SIZE_RANDOMIZE_BASE) {
        kasld_info("KERNEL_IMAGE_SIZE 1 GiB: CONFIG_RANDOMIZE_BASE=y");
        kasld_emit_scalar(SF_KASLR_COMPILED_IN, 1, CONF_PARSED);
      } else if (last == KIMG_SIZE_PLAIN) {
        /* The randomizer is compiled only under CONFIG_RANDOMIZE_BASE, so an
         * image window of 512 MiB means no code exists to have moved the base,
         * on either axis. */
        kasld_info(
            "KERNEL_IMAGE_SIZE 512 MiB: CONFIG_RANDOMIZE_BASE is not set");
        kasld_emit_scalar(SF_VIRT_KASLR_DISABLED, 1, CONF_PARSED);
        kasld_emit_scalar(SF_PHYS_KASLR_DISABLED, 1, CONF_PARSED);
      } else {
        kasld_err("unrecognised image window %#lx; stating nothing about "
                  "CONFIG_RANDOMIZE_BASE",
                  last);
      }
    }
    break; /* one such note per kernel */
  }

  close(fd);
  if (!found)
    kasld_err("no PVH relocation note: this kernel does not carry one");
  return 0;
}
