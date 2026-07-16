// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Parser unit test for proc_kcore. The component is #included with its main()
// renamed and driven over a staged KASLD_SYSROOT /proc/kcore — a synthetic
// 64-bit ELF core whose PT_LOAD program headers we control. This is the only
// automated coverage of the ELF phdr scan: the live component is CAP_SYS_RAWIO-
// gated, so it never fires in the fixture corpus.
//
// Asserts the scan pins _stext from the kernel-text PT_LOAD, ignores the
// direct-map / vmalloc segments (outside the text window), takes the lowest of
// multiple text-window segments, and emits nothing on a malformed core.
//
// proc_kcore is decoupled-arch only (the text has a dedicated high mapping);
// on a coupled host the component's body compiles out, so the suite is inert.
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE /* pread / mkstemp / mkdtemp / setenv under -std=c99 */
#include "../src/include/kasld/api.h"

#if !TEXT_TRACKS_DIRECTMAP

/* Neutralise the ELF-section macros so the component's KASLD_META does not emit
 * a colliding section array. */
#undef KASLD_EXPLAIN
#undef KASLD_META
#define KASLD_EXPLAIN(t) extern char kasld_explain_unused[]
#define KASLD_META(t) extern char kasld_meta_unused[]

int kcore_test_main(int argc, char **argv);
#define main kcore_test_main
#include "../src/components/proc_kcore.c"
#undef main

#include "test_harness.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_root[256];
static char cap[65536];

static void put_le(unsigned char *p, unsigned long long v, int n) {
  for (int i = 0; i < n; i++)
    p[i] = (unsigned char)(v >> (8 * i));
}

/* Stage a 64-bit ELF core at $KASLD_SYSROOT/proc/kcore with the given PT_LOAD
 * p_vaddrs. paddr (may be NULL → all-zero, as for vmalloc/vmemmap headers)
 * supplies each segment's p_paddr. magic_ok=0 corrupts the ELF magic
 * (malformed-core negative test). */
static void make_kcore_pp(const unsigned long *vaddr,
                          const unsigned long *paddr, int n, int magic_ok) {
  char path[512];
  snprintf(path, sizeof(path), "%s/proc", g_root);
  mkdir(path, 0755);
  snprintf(path, sizeof(path), "%s/proc/kcore", g_root);

  unsigned char eh[64] = {0};
  eh[0] = 0x7f;
  eh[1] = magic_ok ? 'E' : 'X';
  eh[2] = 'L';
  eh[3] = 'F';
  eh[4] = 2;                       /* ELFCLASS64 */
  eh[5] = 1;                       /* ELFDATA2LSB */
  eh[6] = 1;                       /* EV_CURRENT */
  put_le(eh + 16, 4, 2);           /* e_type = ET_CORE */
  put_le(eh + 18, 62, 2);          /* e_machine (not checked) */
  put_le(eh + 20, 1, 4);           /* e_version */
  put_le(eh + 32, 64, 8);          /* e_phoff (right after the ehdr) */
  put_le(eh + 52, 64, 2);          /* e_ehsize */
  put_le(eh + 54, 56, 2);          /* e_phentsize = sizeof(Elf64_Phdr) */
  put_le(eh + 56, (unsigned)n, 2); /* e_phnum */

  FILE *f = fopen(path, "wb");
  assert(f);
  assert(fwrite(eh, 1, 64, f) == 64);
  for (int i = 0; i < n; i++) {
    unsigned char ph[56] = {0};
    put_le(ph + 0, 1, 4);                     /* p_type = PT_LOAD */
    put_le(ph + 16, vaddr[i], 8);             /* p_vaddr */
    put_le(ph + 24, paddr ? paddr[i] : 0, 8); /* p_paddr */
    put_le(ph + 40, 0x1000000, 8);            /* p_memsz */
    assert(fwrite(ph, 1, 56, f) == 56);
  }
  fclose(f);
}

/* p_paddr-less variant (all headers p_paddr 0), for the text-only cases. */
static void make_kcore(const unsigned long *vaddr, int n, int magic_ok) {
  make_kcore_pp(vaddr, NULL, n, magic_ok);
}

/* Call the (renamed) component main under a captured stdout; result in cap[].
 */
static int kcore_run(void) {
  char arg0[] = "proc_kcore";
  char *argv[] = {arg0, NULL};
  return kcore_test_main(1, argv);
}

static void run_capture(int (*fn)(void)) {
  fflush(stdout);
  char tmpl[] = "/tmp/kasld_kcore_capXXXXXX";
  int fd = mkstemp(tmpl);
  assert(fd >= 0);
  int saved = dup(1);
  dup2(fd, 1);
  fflush(stderr);
  int saved_err = dup(2);
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0)
    dup2(devnull, 2);
  fn();
  fflush(stdout);
  fflush(stderr);
  dup2(saved, 1);
  close(saved);
  dup2(saved_err, 2);
  close(saved_err);
  if (devnull >= 0)
    close(devnull);
  lseek(fd, 0, SEEK_SET);
  ssize_t n = read(fd, cap, sizeof(cap) - 1);
  cap[n > 0 ? n : 0] = '\0';
  close(fd);
  unlink(tmpl);
}

/* A plausible randomized x86_64 _stext, and direct-map / vmalloc decoys that
 * live below the kernel-text window. */
#define STEXT 0xffffffff81234000UL
static const unsigned long DECOYS[] = {0xffff888000000000UL,
                                       0xffffc90000000000UL};

static void test_pins_stext_over_decoys(void) {
  unsigned long v[] = {DECOYS[0], DECOYS[1], STEXT};
  make_kcore(v, 3, 1);
  run_capture(kcore_run);
  assert(strstr(cap, "kernel_text:_stext pos=base conf=parsed "
                     "lo=0xffffffff81234000") != NULL);
}

static void test_ignores_nontext_segments(void) {
  make_kcore(DECOYS, 2, 1); /* nothing in the text window */
  run_capture(kcore_run);
  assert(strstr(cap, "kernel_text") == NULL);
}

static void test_lowest_text_window_vaddr(void) {
  unsigned long v[] = {0xffffffff82000000UL, STEXT}; /* both in window */
  make_kcore(v, 2, 1);
  run_capture(kcore_run);
  assert(strstr(cap, "lo=0xffffffff81234000") != NULL);
}

static void test_malformed_core_emits_nothing(void) {
  unsigned long v[] = {STEXT};
  make_kcore(v, 1, 0); /* bad magic */
  run_capture(kcore_run);
  assert(strstr(cap, "kernel_text") == NULL);
}

#if PHYS_OFFSET_EXACT
/* A plausible randomized x86_64 page_offset_base and two agreeing RAM segments:
 * page_offset_base = p_vaddr - p_paddr holds for both, so the base is pinned.
 */
#define DM_BASE 0xffff8b6d00000000UL

static void test_pins_directmap_base(void) {
  unsigned long v[] = {DM_BASE + 0x1000, DM_BASE + 0x100000000UL, STEXT};
  unsigned long p[] = {0x1000, 0x100000000UL, 0};
  make_kcore_pp(v, p, 3, 1);
  run_capture(kcore_run);
  assert(strstr(cap, "kernel_text:_stext pos=base conf=parsed "
                     "lo=0xffffffff81234000") != NULL);
  /* The exact left edge is bridged as the SF_VIRT_PAGE_OFFSET scalar, not a
   * REGION_DIRECTMAP base (which would only upper-bound page_offset_base). */
  assert(strstr(cap, "S virt_page_offset conf=parsed "
                     "value=0xffff8b6d00000000") != NULL);
}

/* RAM segments whose p_vaddr - p_paddr disagree (an unreliable p_paddr) must
 * not pin a base, though the text segment still resolves. */
static void test_directmap_conflict_rejected(void) {
  unsigned long v[] = {DM_BASE + 0x1000, DM_BASE + 0x100000000UL, STEXT};
  unsigned long p[] = {0x1000, 0x200000000UL, 0}; /* second disagrees */
  make_kcore_pp(v, p, 3, 1);
  run_capture(kcore_run);
  assert(strstr(cap, "kernel_text:_stext") != NULL);
  assert(strstr(cap, "virt_page_offset") == NULL);
}

/* A direct-map-window header with p_paddr 0 (vmalloc/vmemmap shape) carries no
 * physical base, so no direct-map base can be derived from it. */
static void test_directmap_zero_paddr_ignored(void) {
  unsigned long v[] = {DM_BASE, STEXT};
  unsigned long p[] = {0, 0};
  make_kcore_pp(v, p, 2, 1);
  run_capture(kcore_run);
  assert(strstr(cap, "virt_page_offset") == NULL);
}
#endif /* PHYS_OFFSET_EXACT */

int main(void) {
  char tmpl[] = "/tmp/kasld_kcore_rootXXXXXX";
  char *r = mkdtemp(tmpl);
  assert(r != NULL);
  snprintf(g_root, sizeof(g_root), "%s", r);
  setenv("KASLD_SYSROOT", g_root, 1);

  TEST_SUITE("test_kcore");
  BEGIN_CATEGORY("proc_kcore ELF program-header scan");
  RUN(test_pins_stext_over_decoys);
  RUN(test_ignores_nontext_segments);
  RUN(test_lowest_text_window_vaddr);
  RUN(test_malformed_core_emits_nothing);
#if PHYS_OFFSET_EXACT
  RUN(test_pins_directmap_base);
  RUN(test_directmap_conflict_rejected);
  RUN(test_directmap_zero_paddr_ignored);
#endif
  return TEST_DONE();
}

#else /* coupled host: proc_kcore's body compiles out */
#include "test_harness.h"
int main(void) {
  TEST_SUITE("test_kcore");
  return TEST_DONE();
}
#endif
