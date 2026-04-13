// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Parse /proc/config.gz for kernel configuration.
//
// Checks for CONFIG_RELOCATABLE, CONFIG_RANDOMIZE_BASE,
// and CONFIG_PAGE_OFFSET (32-bit vmsplit).
//
// Uses zlib for native gzip decompression when available (HAVE_ZLIB),
// otherwise falls back to popen("zcat").
//
// Requires:
// - CONFIG_PROC_FS=y
// - CONFIG_IKCONFIG=y
// - CONFIG_IKCONFIG_PROC=y
// - zlib or zcat utility
//
// References:
// https://lwn.net/Articles/444556/
// https://cateee.net/lkddb/web-lkddb/RANDOMIZE_BASE.html
// https://cateee.net/lkddb/web-lkddb/RELOCATABLE.html
// https://cateee.net/lkddb/web-lkddb/PAGE_OFFSET.html
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#define PROC_CONFIG_GZ "/proc/config.gz"

/* Decompress /proc/config.gz into a seekable FILE*.
 * Uses zlib if available, otherwise falls back to popen("zcat"). */
static FILE *open_proc_config(void) {
  FILE *fp;
  char buf[4096];

  printf("[.] checking %s ...\n", PROC_CONFIG_GZ);

  if (access(PROC_CONFIG_GZ, R_OK) != 0) {
    fprintf(stderr, "[-] Could not read %s\n", PROC_CONFIG_GZ);
    return NULL;
  }

#ifdef HAVE_ZLIB
  gzFile gz = gzopen(PROC_CONFIG_GZ, "rb");
  if (gz) {
    fp = tmpfile();
    if (fp) {
      int n;
      while ((n = gzread(gz, buf, sizeof(buf))) > 0)
        fwrite(buf, 1, (size_t)n, fp);
      gzclose(gz);
      rewind(fp);
      return fp;
    }
    gzclose(gz);
  }
#endif

  /* Fallback: decompress via zcat and buffer into a seekable tmpfile. */
  FILE *proc = popen("zcat " PROC_CONFIG_GZ, "r");
  if (!proc) {
    perror("[-] popen");
    return NULL;
  }

  fp = tmpfile();
  if (!fp) {
    perror("[-] tmpfile");
    pclose(proc);
    return NULL;
  }

  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), proc)) > 0)
    fwrite(buf, 1, n, fp);
  pclose(proc);

  fseek(fp, 0, SEEK_END);
  if (ftell(fp) <= 0) {
    fprintf(stderr, "[-] Failed to decompress %s\n", PROC_CONFIG_GZ);
    fclose(fp);
    return NULL;
  }
  rewind(fp);

  return fp;
}

static int is_kconfig_set(FILE *fp, const char *config) {
  char pattern[BUFSIZ], buf[BUFSIZ];

  snprintf(pattern, sizeof(pattern), "%s=y", config);
  rewind(fp);

  printf("[.] checking for %s... \n", config);

  while (fgets(buf, sizeof(buf), fp) != NULL) {
    if (strncmp(buf, pattern, strlen(pattern)) == 0)
      return 1;
  }

  return 0;
}

/* Search for CONFIG_PAGE_OFFSET=0x... in the kernel config.
 * Returns the value, or 0 if not found. */
static unsigned long get_kconfig_page_offset(FILE *fp) {
  const char *key = "CONFIG_PAGE_OFFSET=";
  size_t keylen = strlen(key);
  char buf[BUFSIZ];

  rewind(fp);

  while (fgets(buf, sizeof(buf), fp) != NULL) {
    if (strncmp(buf, key, keylen) == 0) {
      unsigned long val = strtoul(buf + keylen, NULL, 0);
      if (val)
        return val;
    }
  }

  /* Fallback: check CONFIG_VMSPLIT_* choices (x86_32, arm32) */
  const struct {
    const char *config;
    unsigned long page_offset;
  } vmsplit_map[] = {
      {"CONFIG_VMSPLIT_1G", 0x40000000ul},
      {"CONFIG_VMSPLIT_2G", 0x80000000ul},
      {"CONFIG_VMSPLIT_2G_OPT", 0x78000000ul},
      {"CONFIG_VMSPLIT_3G", 0xc0000000ul},
      {"CONFIG_VMSPLIT_3G_OPT", 0xb0000000ul},
      {NULL, 0},
  };

  for (int i = 0; vmsplit_map[i].config; i++) {
    if (is_kconfig_set(fp, vmsplit_map[i].config))
      return vmsplit_map[i].page_offset;
  }

  return 0;
}

static unsigned long get_kernel_addr_proc_config(FILE *fp) {
  int relocatable = is_kconfig_set(fp, "CONFIG_RELOCATABLE");
  int randomize_base = is_kconfig_set(fp, "CONFIG_RANDOMIZE_BASE");

  if (relocatable && randomize_base)
    return 0;

  printf("[.] Kernel appears to have been compiled without both "
         "CONFIG_RELOCATABLE and CONFIG_RANDOMIZE_BASE\n");

  return (unsigned long)KERNEL_TEXT_DEFAULT;
}

int main(void) {
  FILE *fp = open_proc_config();
  if (!fp)
    return 1;

  /* Detect PAGE_OFFSET (32-bit vmsplit) */
  unsigned long page_offset = get_kconfig_page_offset(fp);
  if (page_offset) {
    printf("[.] CONFIG_PAGE_OFFSET: %#lx\n", page_offset);
    kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_PAGEOFFSET, page_offset,
                 "proc-config:page_offset");
  }

  /* Detect KASLR disabled */
  unsigned long addr = get_kernel_addr_proc_config(fp);
  if (addr) {
    printf("common default kernel text for arch: %lx\n", addr);
    kasld_result(KASLD_ADDR_DEFAULT, KASLD_SECTION_NONE, addr,
                 "proc-config:nokaslr");
  }

  fclose(fp);

  return (page_offset || addr) ? 0 : 1;
}
