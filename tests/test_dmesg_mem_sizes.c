// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Parser test for dmesg_mem_sizes. The component is #included with its main
// renamed and driven over a staged KASLD_SYSROOT /var/log/dmesg.
//
// The behaviour under test is what makes the two bounds sound rather than
// merely plausible: the lower bound is emitted ONLY when all five section
// figures are present, since a partial sum bounds nothing; "reserved" is
// matched in full so "cma-reserved" cannot be mistaken for it; and a line whose
// reserved figure falls below the section total is treated as a misparse and
// yields neither bound, because the two would then contradict each other.
//
// The reference line is a real one, captured from a booted 4.19 arm64 kernel
// whose _text and _end were read from kallsyms in the same boot: the section
// total is 22428672 and the true footprint 22487040, so the bound holds with
// the head gap as its only slack.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

int dmesg_mem_sizes_main(int argc, char **argv);
#define main dmesg_mem_sizes_main
#include "../src/components/dmesg_mem_sizes.c"
#undef main

#include "test_harness.h"
#include "test_sysroot.h"

#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char cap[8192];

/* The real line, from a 4.19 arm64 boot. Sections total 21903K = 0x1563c00;
 * reserved is 58888K = 0x3982000. */
#define REAL_LINE                                                              \
  "Memory: 956920K/1048576K available (11132K kernel code, 1380K rwdata, "     \
  "4916K rodata, 4096K init, 379K bss, 58888K reserved, 32768K cma-reserved)\n"

static void stage_dmesg(const char *text) {
  th_sysroot_write("/var/log/dmesg", text);
}

static void run_capture(void) {
  fflush(stdout);
  char tmpl[] = "/tmp/kasld_ms_capXXXXXX";
  int fd = mkstemp(tmpl);
  assert(fd >= 0);
  int saved = dup(1);
  dup2(fd, 1);
  fflush(stderr);
  int saved_err = dup(2);
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0)
    dup2(devnull, 2);

  {
    char arg0[] = "dmesg_mem_sizes";
    char *av[] = {arg0, NULL};
    dmesg_mem_sizes_main(1, av);
  }

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

/* The reference line yields both bounds, at the values its figures state. */
static void test_real_line_both_bounds(void) {
  stage_dmesg(REAL_LINE);
  run_capture();
  assert(strstr(cap, "image_size_min conf=parsed value=0x1563c00") != NULL);
  assert(strstr(cap, "image_size_max conf=parsed value=0x3982000") != NULL);
}

/* A figure the component does not consume must not disturb the ones it does:
 * CONFIG_HIGHMEM appends a term the reference line does not carry. */
static void test_unknown_field_is_ignored(void) {
  stage_dmesg("Memory: 1K/2K available (11132K kernel code, 1380K rwdata, "
              "4916K rodata, 4096K init, 379K bss, 58888K reserved, "
              "0K cma-reserved, 4096K highmem)\n");
  run_capture();
  assert(strstr(cap, "image_size_min conf=parsed value=0x1563c00") != NULL);
  assert(strstr(cap, "image_size_max conf=parsed value=0x3982000") != NULL);
}

/* One section missing makes the sum a partial total, which bounds nothing. The
 * upper bound is independent and survives. */
static void test_partial_line_yields_no_lower_bound(void) {
  stage_dmesg("Memory: 1K/2K available (11132K kernel code, 1380K rwdata, "
              "4096K init, 379K bss, 58888K reserved)\n");
  run_capture();
  assert(strstr(cap, "image_size_min") == NULL);
  assert(strstr(cap, "image_size_max conf=parsed value=0x3982000") != NULL);
}

/* "cma-reserved" is a different quantity and must not be read as "reserved":
 * matching a suffix would take CMA's figure as the image's ceiling. */
static void test_cma_reserved_is_not_reserved(void) {
  stage_dmesg("Memory: 1K/2K available (11132K kernel code, 1380K rwdata, "
              "4916K rodata, 4096K init, 379K bss, 32768K cma-reserved)\n");
  run_capture();
  assert(strstr(cap, "image_size_min conf=parsed value=0x1563c00") != NULL);
  assert(strstr(cap, "image_size_max") == NULL);
}

/* Every page the image occupies is reserved when the line is printed, so a
 * reserved figure below the section total means the line was not what it was
 * taken for. Emitting the pair anyway would state a window whose ceiling is
 * under its floor. */
static void test_contradiction_yields_nothing(void) {
  stage_dmesg("Memory: 1K/2K available (11132K kernel code, 1380K rwdata, "
              "4916K rodata, 4096K init, 379K bss, 100K reserved)\n");
  run_capture();
  assert(strstr(cap, "image_size_min") == NULL);
  assert(strstr(cap, "image_size_max") == NULL);
}

/* A sum under the plausibility floor is a misparse, not a very small kernel. */
static void test_implausible_total_discarded(void) {
  stage_dmesg("Memory: 1K/2K available (1K kernel code, 1K rwdata, 1K rodata, "
              "1K init, 1K bss, 58888K reserved)\n");
  run_capture();
  assert(strstr(cap, "image_size_min") == NULL);
}

/* No such line: nothing claimed. */
static void test_absent_line(void) {
  stage_dmesg("[    0.000000] Linux version 4.19.325\n");
  run_capture();
  assert(strstr(cap, "image_size_min") == NULL);
  assert(strstr(cap, "image_size_max") == NULL);
}

int main(void) {
  th_sysroot_init("dmesg_mem_sizes");

  TEST_SUITE("test_dmesg_mem_sizes");
  BEGIN_CATEGORY("both bounds");
  RUN(test_real_line_both_bounds);
  RUN(test_unknown_field_is_ignored);
  BEGIN_CATEGORY("partial and contradictory lines");
  RUN(test_partial_line_yields_no_lower_bound);
  RUN(test_cma_reserved_is_not_reserved);
  RUN(test_contradiction_yields_nothing);
  RUN(test_implausible_total_discarded);
  RUN(test_absent_line);
  return TEST_DONE();
}
