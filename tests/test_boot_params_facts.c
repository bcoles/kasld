// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Parser unit test for boot_params_facts' setup-header handling. The component
// is #included with its main() renamed and driven over a staged KASLD_SYSROOT
// /sys/kernel/boot_params/data, with /boot/vmlinuz-<release> staged alongside
// where the fallback is under test.
//
// The case that matters: a boot_params the EFI stub synthesized carries no
// setup header. The stub zeroes a page and assigns a handful of fields, so
// every build-time field reads 0 and the "HdrS" magic is absent, while the
// KASLR flag two fields away is set because the stub randomized. Taking the
// relocatable_kernel zero at face value there states that the kernel cannot be
// relocated, on a machine that plainly was -- and the engine pins the base to
// the compile-time default on the strength of it.
//
// boot_params is x86-only (the component #errors elsewhere), so the body is
// gated to x86; on other hosts the suite is a trivial pass.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

#if defined(__x86_64__) || defined(__i386__) || defined(__amd64__)

/* Pull in the public API once, then neutralise the ELF-section macros so the
 * component's KASLD_EXPLAIN/KASLD_META do not emit colliding section arrays. */
#include "../src/include/kasld/api.h"
#undef KASLD_EXPLAIN
#undef KASLD_META
#define KASLD_EXPLAIN(t) extern char kasld_explain_unused[]
#define KASLD_META(t) extern char kasld_meta_unused[]

int bpfacts_main(void);
#define main bpfacts_main
#include "../src/components/boot_params_facts.c"
#undef main

#include "test_harness.h"
#include "test_sysroot.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TEST_RELEASE "6.11.0-25-generic"

static void put_le(unsigned char *p, unsigned long long v, int n) {
  for (int i = 0; i < n; i++)
    p[i] = (unsigned char)(v >> (8 * i));
}

/* A setup header as a boot loader copies it out of the image: the "HdrS" magic
 * at 0x202, a protocol version recent enough to carry every field read here,
 * and the build-time fields populated. */
static void hdr_copied(unsigned char *p, unsigned reloc) {
  memcpy(p + 0x202, "HdrS", 4);
  put_le(p + 0x206, 0x020f, 2); /* protocol 2.15 */
  put_le(p + 0x230, 0x200000, 4);
  p[0x234] = (unsigned char)reloc;
  put_le(p + 0x260, 0x4000000, 4);
}

static unsigned char zp[4096];
static void stage(void) {
  th_sysroot_write_n("/sys/kernel/boot_params/data", zp, sizeof(zp));
}

static char cap[16384];
static void run_capture(int (*fn)(void)) {
  fflush(stdout);
  char tmpl[] = "/tmp/kasld_bpfacts_capXXXXXX";
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

static int emits_kaslr_off(void) {
  return strstr(cap, "virt_kaslr_disabled") != NULL ||
         strstr(cap, "phys_kaslr_disabled") != NULL;
}

/* A header the EFI stub synthesized: no magic, every build-time field zero,
 * KASLR flag set because the stub randomized this boot. The relocatable zero
 * is an unwritten field, not an answer, and must not become a KASLR-off
 * signal -- the run it came from would otherwise report the compile-time base
 * as GUARANTEED while holding leaks that place the kernel elsewhere. */
static void test_synthesized_header_states_nothing_build_time(void) {
  memset(zp, 0, sizeof(zp));
  zp[0x211] = KASLD_BOOT_PARAMS_KASLR_FLAG;
  stage();
  run_capture(bpfacts_main);

  assert(strstr(cap, "kaslr_randomized conf=parsed value=0x1") != NULL);
  assert(!emits_kaslr_off());
  /* The same zeroes must not be read as an image size or a slot granularity. */
  assert(strstr(cap, "image_size_min") == NULL);
  assert(strstr(cap, "phys_kernel_align") == NULL);
}

/* The same synthesized header, with the image the fields really live in
 * readable beside it. The build-time answers come from there, and a
 * relocatable kernel yields no KASLR-off signal. This is the case the gate
 * exists to reach: staged so it collides with the sysfs zeroes rather than
 * passing on their absence. */
static void test_synthesized_header_defers_to_the_image(void) {
  memset(zp, 0, sizeof(zp));
  zp[0x211] = KASLD_BOOT_PARAMS_KASLR_FLAG;
  stage();

  unsigned char img[0x264];
  memset(img, 0, sizeof(img));
  hdr_copied(img, 1);
  th_sysroot_write_n("/boot/vmlinuz-" TEST_RELEASE, img, sizeof(img));
  setenv("KASLD_UNAME_RELEASE", TEST_RELEASE, 1);
  run_capture(bpfacts_main);
  unsetenv("KASLD_UNAME_RELEASE");
  th_sysroot_rm("/boot/vmlinuz-" TEST_RELEASE);

  assert(!emits_kaslr_off());
  assert(strstr(cap, "image_size_min conf=parsed value=0x4000000") != NULL);
  assert(strstr(cap, "phys_kernel_align conf=parsed value=0x200000") != NULL);
}

/* A header a boot loader really copied, from a kernel built without
 * CONFIG_RELOCATABLE. The inference is sound here and must survive: a kernel
 * that cannot be relocated cannot be randomized. */
static void test_copied_header_reports_non_relocatable(void) {
  memset(zp, 0, sizeof(zp));
  hdr_copied(zp, 0);
  stage();
  run_capture(bpfacts_main);

  assert(strstr(cap, "virt_kaslr_disabled conf=parsed value=0x1") != NULL);
  assert(strstr(cap, "phys_kaslr_disabled conf=parsed value=0x1") != NULL);
  assert(strstr(cap, "phys_kernel_align conf=parsed value=0x200000") != NULL);
}

/* A copied header from a relocatable kernel that the stub randomized: the
 * build-time fields are read, and nothing claims KASLR is off. The KASLR flag
 * is set so the runtime path is silent and this isolates the build-time one --
 * with it clear the component reports KASLR off from loadflags alone, which is
 * correct and is what test_copied_header_reports_non_relocatable covers. */
static void test_copied_header_relocatable_is_silent(void) {
  memset(zp, 0, sizeof(zp));
  hdr_copied(zp, 1);
  zp[0x211] = KASLD_BOOT_PARAMS_KASLR_FLAG;
  stage();
  run_capture(bpfacts_main);

  assert(!emits_kaslr_off());
  assert(strstr(cap, "image_size_max conf=parsed value=0x4000000") != NULL);
}

/* A header whose magic is present but whose protocol predates the fields:
 * 0x230, 0x234 and 0x260 are other fields' bytes at that version, so none of
 * them is read. */
static void test_old_protocol_reads_no_later_field(void) {
  memset(zp, 0, sizeof(zp));
  memcpy(zp + 0x202, "HdrS", 4);
  put_le(zp + 0x206, 0x0203, 2); /* predates kernel_alignment and the rest */
  zp[0x211] = KASLD_BOOT_PARAMS_KASLR_FLAG;
  put_le(zp + 0x230, 0x200000, 4);
  zp[0x234] = 0;
  put_le(zp + 0x260, 0x4000000, 4);
  stage();
  run_capture(bpfacts_main);

  assert(!emits_kaslr_off());
  assert(strstr(cap, "phys_kernel_align") == NULL);
  assert(strstr(cap, "image_size_min") == NULL);
}

int main(void) {
  th_sysroot_init("boot_params_facts");

  TEST_SUITE("test_boot_params_facts");
  BEGIN_CATEGORY("setup-header validity");
  RUN(test_synthesized_header_states_nothing_build_time);
  RUN(test_synthesized_header_defers_to_the_image);
  RUN(test_copied_header_reports_non_relocatable);
  RUN(test_copied_header_relocatable_is_silent);
  RUN(test_old_protocol_reads_no_later_field);
  return TEST_DONE();
}

#else /* non-x86 host: boot_params_facts is x86-only (the component #errors)   \
       */
#include "test_harness.h"
int main(void) {
  TEST_SUITE("test_boot_params_facts");
  return TEST_DONE();
}
#endif
