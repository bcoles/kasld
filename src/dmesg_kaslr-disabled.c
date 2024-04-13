// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Search kernel log for messages stating KASLR is disabled.
//
// x86/x86_64:
// KASLR disabled: 'kaslr' not on cmdline (hibernation selected).
// KASLR disabled: 'nokaslr' on cmdline.
//
// ARM64:
// KASLR disabled on command line
// KASLR disabled due to lack of seed
// KASLR disabled due to FDT remapping failure
//
// LoongArch:
// KASLR is disabled.
//
// S390:
// KASLR disabled: CPU has no PRNG
// KASLR disabled: not enough memory
//
// Introduced for ARM64 in kernel v5.5-rc1~22^2~11^9~1 on 2019-11-09:
// https://github.com/torvalds/linux/commit/294a9ddde6cdbf931a28b8c8c928d3f799b61cb5
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v5.19.17/source/arch/arm64/kernel/kaslr.c#L197
// https://elixir.bootlin.com/linux/v5.19.17/source/arch/arm64/kernel/kaslr.c#L200
// https://elixir.bootlin.com/linux/v6.1.6/source/arch/arm64/kernel/kaslr.c#L45
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/s390/boot/kaslr.c#L35
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/s390/boot/kaslr.c#L201
// https://elixir.bootlin.com/linux/v6.8.5/source/arch/loongarch/kernel/relocate.c#L107
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/syslog.h"
#include "include/kasld.h"
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

unsigned long search_dmesg_kaslr_disabled() {
  int size;
  char *syslog = 0;
  char *line = 0;
  const char *needle = "KASLR disabled";
  const char *needle2 = "KASLR is disabled";
  bool nokaslr = false;

  printf("[.] searching dmesg for '%s' or '%s' ...\n", needle, needle2);

  if (mmap_syslog(&syslog, &size))
    return 0;

  line = strtok(syslog, "\n");
  while ((line = strtok(NULL, "\n")) != NULL) {
    if (strstr(line, needle) || strstr(line, needle2)) {
      // printf("%s\n", line);
      nokaslr = true;
      break;
    }
  }

  if (nokaslr) {
    printf("[.] Kernel was booted with KASLR disabled\n");
    return (unsigned long)KERNEL_TEXT_DEFAULT;
  }

  return 0;
}

unsigned long search_dmesg_log_file_kaslr_disabled() {
  FILE *f;
  char *line = 0;
  size_t size = 0;
  const char *path = "/var/log/dmesg";
  const char *needle = "KASLR disabled";
  const char *needle2 = "KASLR is disabled";
  bool nokaslr = false;

  printf("[.] searching %s for '%s' or '%s' ...\n", path, needle, needle2);

  f = fopen(path, "rb");

  if (f == NULL) {
    perror("[-] fopen");
    return 0;
  }

  while ((getline(&line, &size, f)) != -1) {
    if (strstr(line, needle) || strstr(line, needle2)) {
      // printf("%s\n", line);
      nokaslr = true;
      break;
    }
  }

  free(line);
  fclose(f);

  if (nokaslr) {
    printf("[.] Kernel was booted with KASLR disabled\n");
    return (unsigned long)KERNEL_TEXT_DEFAULT;
  }

  return 0;
}

int main() {
  unsigned long addr = search_dmesg_kaslr_disabled();
  if (!addr)
    addr = search_dmesg_log_file_kaslr_disabled();

  if (!addr)
    return 1;

  printf("common default kernel text for arch: %lx\n", addr);

  return 0;
}
