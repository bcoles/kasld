// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Block-parser tests for dmesg_backtrace. The component is #included with its
// main renamed and driven over a staged KASLD_SYSROOT /var/log/dmesg, so the
// whole ordered single pass runs — header-context tracking, CR3 attribution,
// and direct-map extraction — against hand-built oops dumps.
//
// The behaviour under test: the x86 CR3 page-table base is tagged by the
// faulting task's context. The idle task's CR3 is swapper_pg_dir (kernel .bss)
// -> REGION_KERNEL_BSS; any other task's CR3 is a process page table in DRAM
// -> REGION_RAM. The header is matched across every format the kernel has
// printed, each CR3 is attributed to its own dump, and a missing header
// degrades to the conservative REGION_RAM.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

int dmesg_backtrace_main(void);
#define main dmesg_backtrace_main
#include "../src/components/dmesg_backtrace.c"
#undef main

#include "test_harness.h"

#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_root[256];
static char cap[8192];

/* Write `text` as the sysroot's /var/log/dmesg (the source the component reads
 * under KASLD_SYSROOT). One root for the whole suite — kasld_sysroot() caches
 * the path, but the file content is re-read each run, so rewriting it per case
 * works. */
static void stage_dmesg(const char *text) {
  char path[320];
  snprintf(path, sizeof(path), "%s/var/log/dmesg", g_root);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  assert(fd >= 0);
  size_t n = strlen(text);
  assert(write(fd, text, n) == (ssize_t)n);
  close(fd);
}

/* Run the component, capturing its stdout (the wire channel) into `cap`;
 * the stderr diagnostics are silenced. */
static void run_capture(void) {
  fflush(stdout);
  char tmpl[] = "/tmp/kasld_bt_capXXXXXX";
  int fd = mkstemp(tmpl);
  assert(fd >= 0);
  int saved = dup(1);
  dup2(fd, 1);
  fflush(stderr);
  int saved_err = dup(2);
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0)
    dup2(devnull, 2);

  dmesg_backtrace_main();

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

/* The trigger case: a user-process (PID 633) WARNING. CR3 is the task PGD ->
 * REGION_RAM (not a false KERNEL_BSS); the RBX/RDI/R14 value is direct-map. */
static void test_user_cr3_is_ram_plus_directmap(void) {
  stage_dmesg(
      "kernel: CPU: 3 PID: 633 Comm: plymouthd Tainted: G OE 6.8.0-110\n"
      "kernel: RAX: ffff8d5ec9169ec0 RBX: ffff8d5ec397b000 RCX: 0\n"
      "kernel: CR2: 000079fac44400d0 CR3: 0000000253e3c000 CR4: 0\n");
  run_capture();
  assert(strstr(cap, "P ram:cr3") != NULL);
  assert(strstr(cap, "sample=0x253e3c000") != NULL);
  assert(strstr(cap, "kernel_bss") == NULL);
  /* The direct-map classification depends on the host's PAGE_OFFSET window
   * (the test binary is host-built); assert it only where the chosen value is
   * in range, so the test is not x86_64-host-specific. */
  if (in_directmap_range(0xffff8d5ec397b000UL)) {
    assert(strstr(cap, "V directmap") != NULL);
    assert(strstr(cap, "sample=0xffff8d5ec397b000") != NULL);
    /* A register value is only a heuristic direct-map witness (it may be a
     * non-pointer below the randomized page_offset_base); it must stay
     * sub-floor so it cannot forge a guaranteed page_offset ceiling. */
    assert(strstr(cap, "directmap pos=interior conf=heuristic") != NULL);
  }
}

/* Idle task (PID 0 / swapper): CR3 == swapper_pg_dir, in .bss. */
static void test_swapper_cr3_is_bss(void) {
  stage_dmesg("kernel: CPU: 0 PID: 0 Comm: swapper/0 Not tainted 6.8.0\n"
              "kernel: CR2: 0 CR3: 0000000041e0a000 CR4: 0\n");
  run_capture();
  assert(strstr(cap, "P kernel_bss:cr3") != NULL);
  assert(strstr(cap, "sample=0x41e0a000") != NULL);
}

/* v6.11+ header inserts a UID field before PID; token match must still work. */
static void test_uid_field_format_user(void) {
  stage_dmesg("kernel: CPU: 1 UID: 1000 PID: 990 Comm: firefox Tainted: G\n"
              "kernel: CR2: 0 CR3: 0000000288a14000 CR4: 0\n");
  run_capture();
  assert(strstr(cap, "P ram:cr3") != NULL);
  assert(strstr(cap, "sample=0x288a14000") != NULL);
}

/* Pre-~v3.9 lowercase "Pid: N, comm: name" header; idle task. */
static void test_ancient_lowercase_header_swapper(void) {
  stage_dmesg("kernel: Pid: 0, comm: swapper Not tainted 3.2.0\n"
              "kernel: CR2: 0 CR3: 0000000001c0b000 CR4: 0\n");
  run_capture();
  assert(strstr(cap, "P kernel_bss:cr3") != NULL);
  assert(strstr(cap, "sample=0x1c0b000") != NULL);
}

/* Two dumps in one log: the lower CR3 belongs to the user dump and must be
 * attributed to it (REGION_RAM), not to the earlier swapper dump. */
static void test_multi_dump_association(void) {
  stage_dmesg("kernel: CPU: 0 PID: 0 Comm: swapper/0 Not tainted\n"
              "kernel: CR3: 0000000099999000 CR4: 0\n"
              "kernel: CPU: 2 PID: 700 Comm: bash Tainted: G\n"
              "kernel: CR3: 0000000011111000 CR4: 0\n");
  run_capture();
  /* lowest CR3 (0x11111000) is the bash dump -> RAM */
  assert(strstr(cap, "P ram:cr3") != NULL);
  assert(strstr(cap, "sample=0x11111000") != NULL);
  assert(strstr(cap, "kernel_bss") == NULL);
}

/* A CR3 whose dump header was evicted from the ring buffer must not inherit a
 * stale context — it degrades to the conservative REGION_RAM. */
static void test_evicted_header_is_conservative(void) {
  stage_dmesg("kernel: RAX: ffff8d00 RBX: ffff8d01\n"
              "kernel: CR2: 0 CR3: 0000000042042000 CR4: 0\n");
  run_capture();
  assert(strstr(cap, "P ram:cr3") != NULL);
  assert(strstr(cap, "sample=0x42042000") != NULL);
  assert(strstr(cap, "kernel_bss") == NULL);
}

/* LoongArch prints raw pc/ra kernel-text registers; parse_loongarch_pc_ra reads
 * them positionally from the "pc <hex> ra <hex> tp <hex> sp <hex>" line. The
 * emit path is arch-gated to LoongArch, but the parser is host-independent. */
static void test_loongarch_pc_ra_parse(void) {
  unsigned long pc = 1, ra = 1;
  parse_loongarch_pc_ra("[ 1.234] kernel: pc 9000000012345678 "
                        "ra 9000000087654321 tp 9000000000abcdef "
                        "sp 9000000000fedcba",
                        &pc, &ra);
  assert(pc == 0x9000000012345678UL);
  assert(ra == 0x9000000087654321UL);

  /* No register line → both cleared. */
  pc = ra = 7;
  parse_loongarch_pc_ra("not a register dump line", &pc, &ra);
  assert(pc == 0 && ra == 0);
}

int main(void) {
  char tmpl[] = "/tmp/kasld_bt_rootXXXXXX";
  char *r = mkdtemp(tmpl);
  assert(r != NULL);
  snprintf(g_root, sizeof(g_root), "%s", r);
  char dir[300];
  snprintf(dir, sizeof(dir), "%s/var", g_root);
  mkdir(dir, 0755);
  snprintf(dir, sizeof(dir), "%s/var/log", g_root);
  mkdir(dir, 0755);
  setenv("KASLD_SYSROOT", g_root, 1);

  TEST_SUITE("test_dmesg_backtrace");
  BEGIN_CATEGORY("oops block parser + CR3 context tag");
  RUN(test_user_cr3_is_ram_plus_directmap);
  RUN(test_swapper_cr3_is_bss);
  RUN(test_uid_field_format_user);
  RUN(test_ancient_lowercase_header_swapper);
  RUN(test_multi_dump_association);
  RUN(test_evicted_header_is_conservative);
  RUN(test_loongarch_pc_ra_parse);
  return TEST_DONE();
}
