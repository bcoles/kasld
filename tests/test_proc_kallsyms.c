// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Unit tests for proc_kallsyms, driven end-to-end over a staged
// KASLD_SYSROOT /proc/kallsyms with the component's main renamed.
//
// Two behaviours are pinned, because both were broken by a mechanical
// conversion and neither had coverage to catch it:
//
//   1. The kptr_restrict probe. Every address reading as zero is the masked
//      case and must be reported as restricted; a symbol legitimately AT zero
//      must not be mistaken for a real address (several are).
//   2. Address width. A symbol address wider than this build's word must be
//      refused, not truncated — an fscanf("%lx") over a 64-bit kallsyms on a
//      32-bit build silently yields the low half, which looks exactly like a
//      valid image base and enters the evidence set at CONF_PARSED.
//
// Runs under tests/test-cross, which is where (2) is a genuine refusal rather
// than an ordinary parse, so the assertions are written against the build's
// own word size.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

int proc_kallsyms_main(void);
#define main proc_kallsyms_main
#include "../src/components/proc_kallsyms.c"
#undef main

#include "test_harness.h"

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_root[256];
static char cap[8192];
static int last_rc;

static void stage_kallsyms(const char *text) {
  char path[320];
  snprintf(path, sizeof(path), "%s/proc/kallsyms", g_root);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  assert(fd >= 0);
  size_t n = strlen(text);
  assert(write(fd, text, n) == (ssize_t)n);
  close(fd);
}

static void run_capture(void) {
  fflush(stdout);
  char tmpl[] = "/tmp/kasld_ks_capXXXXXX";
  int fd = mkstemp(tmpl);
  assert(fd >= 0);
  int saved = dup(1);
  dup2(fd, 1);
  fflush(stderr);
  int saved_err = dup(2);
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0)
    dup2(devnull, 2);

  last_rc = proc_kallsyms_main();

  fflush(stdout);
  fflush(stderr);
  dup2(saved, 1);
  close(saved);
  dup2(saved_err, 2);
  close(saved_err);
  if (devnull >= 0)
    close(devnull);
  lseek(fd, 0, SEEK_SET);
  ssize_t r = read(fd, cap, sizeof(cap) - 1);
  cap[r > 0 ? r : 0] = '\0';
  close(fd);
  unlink(tmpl);
}

/* kptr_restrict masks every address to zero. That is an access restriction,
 * not a missing source, and nothing may be emitted from it. */
static void test_masked_kallsyms_is_denied(void) {
  stage_kallsyms("0000000000000000 A irq_stack_union\n"
                 "0000000000000000 T _stext\n"
                 "0000000000000000 T _text\n"
                 "0000000000000000 T _etext\n");
  run_capture();
  assert(last_rc == KASLD_EXIT_NOPERM);
  assert(strstr(cap, "V kernel_image") == NULL);
  assert(strstr(cap, "V kernel_text") == NULL);
}

/* A readable table yields the image base at its full width. */
static void test_readable_kallsyms_emits_base(void) {
  char text[512];
  unsigned long base = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
  snprintf(text, sizeof(text), "%lx T _stext\n%lx T _text\n%lx T _etext\n",
           base, base, base + 0x100000);
  stage_kallsyms(text);
  run_capture();
  assert(last_rc != KASLD_EXIT_NOPERM);
  char want[64];
  snprintf(want, sizeof(want), "lo=%#lx", base);
  assert(strstr(cap, want) != NULL);
}

/* A 64-bit table read by a narrower build. The addresses cannot be
 * represented, so nothing may be emitted — least of all their low halves,
 * which are plausible kernel-text values in their own right. */
static void test_too_wide_addresses_are_not_truncated(void) {
  stage_kallsyms("ffffffff81a00000 T _stext\n"
                 "ffffffff81a00000 T _text\n"
                 "ffffffff83204c4b T _etext\n");
  run_capture();
  if (sizeof(kasld_addr_t) >= 8) {
    assert(strstr(cap, "lo=0xffffffff81a00000") != NULL);
  } else {
    /* The truncation this pins: the low half of _text. */
    assert(strstr(cap, "81a00000") == NULL);
    assert(strstr(cap, "V kernel_image") == NULL);
  }
}

/* The masked probe must not read a refusal as a mask: a too-wide address had
 * digits, so the table is readable and simply out of range for this build. */
static void test_too_wide_is_not_reported_as_restricted(void) {
  stage_kallsyms("ffffffff81a00000 T _stext\n"
                 "ffffffff81a00000 T _text\n");
  run_capture();
  if (sizeof(kasld_addr_t) < 8)
    assert(last_rc != KASLD_EXIT_NOPERM);
}

int main(void) {
  TEST_SUITE("proc_kallsyms (masked probe + address width)");
  snprintf(g_root, sizeof(g_root), "/tmp/kasld_ks_rootXXXXXX");
  assert(mkdtemp(g_root) != NULL);
  char sub[320];
  snprintf(sub, sizeof(sub), "%s/proc", g_root);
  assert(mkdir(sub, 0755) == 0);
  setenv("KASLD_SYSROOT", g_root, 1);

  BEGIN_CATEGORY("kptr_restrict probe");
  RUN(test_masked_kallsyms_is_denied);
  RUN(test_readable_kallsyms_emits_base);
  BEGIN_CATEGORY("address width");
  RUN(test_too_wide_addresses_are_not_truncated);
  RUN(test_too_wide_is_not_reported_as_restricted);

  snprintf(sub, sizeof(sub), "%s/proc/kallsyms", g_root);
  unlink(sub);
  snprintf(sub, sizeof(sub), "%s/proc", g_root);
  rmdir(sub);
  rmdir(g_root);
  return TEST_DONE();
}
