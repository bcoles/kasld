/* This file is part of KASLD - https://github.com/bcoles/kasld
 *
 * test_component.h — driving a leak component from a test.
 *
 * A component test #includes the component with its main renamed, stages the
 * files it reads under KASLD_SYSROOT, calls that main, and asserts on the wire
 * lines it printed. The mechanics of the last part are the same every time and
 * are gathered here.
 *
 * Two of them are easy to get wrong, and both have been:
 *
 * stdout is the wire channel, so it has to be captured rather than watched —
 * and stderr silenced, since a component's diagnostics are chatty by design and
 * would otherwise bury the test output.
 *
 * A field assertion has to end at a non-hex character. Hex values nest, so
 * `strstr(cap, "hi=0xffffff")` is satisfied by `hi=0xffffffff`, and a negative
 * assertion written that way can never fail however wrong the component is.
 * th_cap_field_is() exists because that mistake was made three times before it
 * was noticed.
 *
 * Usage:
 *
 *     int foo_main(void);
 *     #define main foo_main
 *     #include "../src/components/foo.c"
 *     #undef main
 *     #include "test_harness.h"
 *     #include "test_sysroot.h"
 *     #include "test_component.h"
 *
 *     th_sysroot_write("/proc/foo", "...");
 *     int rc;
 *     TH_RUN_COMPONENT(rc, foo_main());
 *     assert(rc == 0);
 *     assert(th_cap_field_is("sample", expected));
 *
 * TH_RUN_COMPONENT is a macro rather than a function because component mains
 * differ: some take (void), some (int, char **).
 * ---
 * <bcoles@gmail.com>
 */
#ifndef KASLD_TEST_COMPONENT_H
#define KASLD_TEST_COMPONENT_H

#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The component's stdout from the last TH_RUN_COMPONENT. */
static char th_cap[8192];

static int th_cap_out_fd, th_cap_saved_out, th_cap_saved_err, th_cap_devnull;
static char th_cap_tmpl[] = "/tmp/kasld_component_capXXXXXX";

__attribute__((unused)) static void th_cap_begin(void) {
  fflush(stdout);
  strcpy(th_cap_tmpl, "/tmp/kasld_component_capXXXXXX");
  th_cap_out_fd = mkstemp(th_cap_tmpl);
  assert(th_cap_out_fd >= 0);
  th_cap_saved_out = dup(1);
  dup2(th_cap_out_fd, 1);
  fflush(stderr);
  th_cap_saved_err = dup(2);
  th_cap_devnull = open("/dev/null", O_WRONLY);
  if (th_cap_devnull >= 0)
    dup2(th_cap_devnull, 2);
}

__attribute__((unused)) static void th_cap_end(void) {
  fflush(stdout);
  fflush(stderr);
  dup2(th_cap_saved_out, 1);
  close(th_cap_saved_out);
  dup2(th_cap_saved_err, 2);
  close(th_cap_saved_err);
  if (th_cap_devnull >= 0)
    close(th_cap_devnull);
  lseek(th_cap_out_fd, 0, SEEK_SET);
  ssize_t r = read(th_cap_out_fd, th_cap, sizeof(th_cap) - 1);
  th_cap[r > 0 ? r : 0] = '\0';
  close(th_cap_out_fd);
  unlink(th_cap_tmpl);
}

/* Run a component main, capturing its stdout into th_cap and its exit status
 * into `rcvar`. */
#define TH_RUN_COMPONENT(rcvar, call)                                          \
  do {                                                                         \
    th_cap_begin();                                                            \
    (rcvar) = (call);                                                          \
    th_cap_end();                                                              \
  } while (0)

/* Whether the capture carries `<key>=0x<val>` as a WHOLE field — the match must
 * end at a non-hex character, or a shorter value is found inside a longer one
 * and the assertion is vacuous. */
__attribute__((unused)) static int th_cap_field_is(const char *key,
                                                   unsigned long val) {
  char want[80];
  snprintf(want, sizeof(want), "%s=0x%lx", key, val);
  size_t n = strlen(want);
  for (const char *p = th_cap; (p = strstr(p, want)) != NULL; p++)
    if (!isxdigit((unsigned char)p[n]))
      return 1;
  return 0;
}

/* How many times `needle` appears in the capture — for counting wire lines of
 * a given shape (`pos=extent`, a repeated sample). */
__attribute__((unused)) static int th_cap_count(const char *needle) {
  int n = 0;
  for (const char *p = th_cap; (p = strstr(p, needle)) != NULL; p++)
    n++;
  return n;
}

#endif /* KASLD_TEST_COMPONENT_H */
