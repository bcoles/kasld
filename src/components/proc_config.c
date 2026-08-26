// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Parse /proc/config.gz for kernel configuration.
//
// Checks for CONFIG_RELOCATABLE, CONFIG_RANDOMIZE_BASE,
// and CONFIG_PAGE_OFFSET (32-bit vmsplit).
//
// Uses zlib for native gzip decompression when available (HAVE_ZLIB),
// otherwise spawns zcat with the open descriptor on its standard input.
//
// Detection component — leaks no randomized (KASLR) address.
//   Purpose: reads /proc/config.gz to determine whether
//   CONFIG_RANDOMIZE_BASE is set (KASLR compiled in) and what the
//   32-bit vmsplit (CONFIG_PAGE_OFFSET) is.
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
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include "include/kconfig.h"
#include "include/text_order.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#define PROC_CONFIG_GZ "/proc/config.gz"

KASLD_EXPLAIN(
    "Reads /proc/config.gz (requires CONFIG_IKCONFIG_PROC) to determine "
    "whether KASLR is compiled in (CONFIG_RANDOMIZE_BASE) and to extract "
    "layout-constraining config values: the 32-bit user/kernel split "
    "(CONFIG_PAGE_OFFSET), CONFIG_PHYSICAL_START, CONFIG_PHYSICAL_ALIGN, "
    "CONFIG_KASAN, kernel-text function ordering, and (on s390) "
    "CONFIG_KERNEL_IMAGE_BASE.");

KASLD_META("method:detection\n"
           "phase:inference\n"
           "discloses:virtual\n"
           "config:CONFIG_IKCONFIG_PROC\n");

/* The exit class the last open attempt implies; see kasld_exit_for_errno. */
static int proc_config_exit = KASLD_EXIT_UNAVAILABLE;

/* Decompress /proc/config.gz into a seekable FILE*.
 * Uses zlib where it is linked, otherwise spawns zcat.
 *
 * The file is opened ONCE and thereafter identified only by its descriptor,
 * never by name. That is what keeps the name out of the decompressor: zcat
 * reads standard input when given no file argument, so the child is handed the
 * descriptor and no path at all -- there is no command string, no argument
 * vector, and so nothing to quote. It also collapses the check and the use into
 * one syscall, where a separate access() would leave a window in which the name
 * could come to mean a different file. */
static FILE *open_proc_config(void) {
  FILE *fp;
  char buf[4096];

  kasld_info("checking %s ...", PROC_CONFIG_GZ);

  int fd = kasld_open(PROC_CONFIG_GZ, O_RDONLY);
  if (fd < 0) {
    /* Preserve WHY across the NULL return: a denied config is the target's
     * hardening, an absent one is how it was built. open() reports the same
     * EACCES/EPERM the exit classifier keys on. */
    proc_config_exit = kasld_exit_for_errno();
    kasld_err("Could not read %s", PROC_CONFIG_GZ);
    return NULL;
  }

#ifdef HAVE_ZLIB
  /* gzdopen takes ownership of fd: gzclose closes it, and on failure the
   * descriptor is closed below before the spawn path would have used it. */
  gzFile gz = gzdopen(fd, "rb");
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
    return NULL; /* tmpfile() failed; the descriptor went with gzclose */
  }
  close(fd);
  return NULL; /* zlib is linked, so there is no second decompressor to try */
#else

  /* No zlib (the static cross builds have none: no musl toolchain ships it, so
   * this is the only decompressor there). Spawn zcat directly rather than
   * through a shell -- popen would run /bin/sh, and a shell expands $( ) even
   * inside double quotes, so a resolved path containing one would execute.
   * zcat reads standard input with no file argument, so the child receives the
   * open descriptor and never the name.
   *
   * execvp, not execv: zcat is /bin/zcat on some systems and /usr/bin/zcat on
   * others, and busybox installs it wherever its links live. PATH belongs to
   * the user running kasld, which is the same trust the shell form already
   * assumed. */
  int pipefd[2];
  if (pipe(pipefd) != 0) {
    perror("[-] pipe");
    close(fd);
    return NULL;
  }

  pid_t pid = fork();
  if (pid < 0) {
    perror("[-] fork");
    close(pipefd[0]);
    close(pipefd[1]);
    close(fd);
    return NULL;
  }
  if (pid == 0) {
    if (dup2(fd, STDIN_FILENO) < 0 || dup2(pipefd[1], STDOUT_FILENO) < 0)
      _exit(127);
    close(pipefd[0]);
    close(pipefd[1]);
    close(fd);
    /* A modifiable array rather than a cast of the literal: execvp's argv is
     * char *const[], and casting away const on a string literal is the one
     * thing -Wcast-qual is looking for. */
    char zcat[] = "zcat";
    char *const argv[] = {zcat, NULL};
    execvp(zcat, argv);
    _exit(127); /* zcat absent; the empty output below reports it */
  }

  close(pipefd[1]);
  close(fd);
  FILE *proc = fdopen(pipefd[0], "r");
  if (!proc) {
    perror("[-] fdopen");
    close(pipefd[0]);
    waitpid(pid, NULL, 0);
    return NULL;
  }

  fp = tmpfile();
  if (!fp) {
    perror("[-] tmpfile");
    fclose(proc);
    waitpid(pid, NULL, 0);
    return NULL;
  }

  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), proc)) > 0)
    fwrite(buf, 1, n, fp);
  fclose(proc);

  /* Reap before judging the output. The empty-output test below stays the
   * arbiter -- a child that emitted a whole config and then exited non-zero
   * has still done the job -- but where there is nothing to show, the status
   * separates "zcat is not installed" (127 from the failed exec) from "the
   * file was not gzip". */
  int status = 0;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
    ;

  fseek(fp, 0, SEEK_END);
  if (ftell(fp) <= 0) {
    if (WIFEXITED(status) && WEXITSTATUS(status) == 127)
      kasld_err("zcat not found; cannot decompress %s", PROC_CONFIG_GZ);
    else
      kasld_err("Failed to decompress %s", PROC_CONFIG_GZ);
    fclose(fp);
    return NULL;
  }
  rewind(fp);

  return fp;
#endif
}

static int kaslr_disabled_from_config(FILE *fp) {
  if (kconfig_has_kaslr(fp))
    return 0;

  kasld_info(
      "Kernel appears to have been compiled without CONFIG_RANDOMIZE_BASE"
      " (KASLR not compiled in)");
  return 1;
}

int main(void) {
  FILE *fp = open_proc_config();
  if (!fp)
    return proc_config_exit;

#if PAGE_OFFSET_FROM_CONFIG
  /* Detect PAGE_OFFSET (32-bit vmsplit). CONFIG_PAGE_OFFSET equals the runtime
   * page_offset only on PAGE_OFFSET_FROM_CONFIG arches (x86_32, arm32, ppc32);
   * pinning Q_PAGE_OFFSET to it via page_offset_from_landmark's C_EQUALS would
   * exclude the truth on arches whose CONFIG_PAGE_OFFSET differs from the
   * running base.
   * (The properly gated scalar path is bootconfig_facts ->
   * page_offset_from_config.) */
  unsigned long virt_page_offset = get_kconfig_page_offset(fp);
  if (virt_page_offset) {
    kasld_info("CONFIG_PAGE_OFFSET: %#lx", virt_page_offset);
    kasld_result_base(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, virt_page_offset,
                      NULL, CONF_PARSED);
  }
#endif

  /* CONFIG_PHYSICAL_START (x86 LOAD_PHYSICAL_ADDR) — see boot_config.c. */
  unsigned long phys_start = get_kconfig_physical_start(fp);
  if (phys_start) {
    kasld_info("CONFIG_PHYSICAL_START: %#lx", phys_start);
    kasld_emit_scalar(SF_PHYSICAL_START, phys_start, CONF_PARSED);
  }

  /* CONFIG_PHYSICAL_ALIGN — KASLR slot granularity (x86). See boot_config.c.
   * Fallback for systems where /sys/kernel/boot_params/data is unreadable.  */
  unsigned long phys_align = get_kconfig_physical_align(fp);
  if (phys_align) {
    kasld_info("CONFIG_PHYSICAL_ALIGN: %#lx", phys_align);
    kasld_emit_scalar(SF_PHYS_KERNEL_ALIGN, phys_align, CONF_PARSED);
  }

  /* KASLR-off detection. CONFIG_RANDOMIZE_BASE=n in /proc/config.gz means
   * the kernel binary was built without KASLR support — both virtual and
   * physical placement use compile-time defaults. virt_kaslr_disabled_pin
   * and phys_kaslr_disabled_pin each gate by its arch macro
   * (KASLR_DISABLED_PINS_VIRT_TEXT / KASLR_DISABLED_PINS_PHYS) + window-
   * containment. */
  if (kaslr_disabled_from_config(fp)) {
    kasld_emit_scalar(SF_VIRT_KASLR_DISABLED, 1, CONF_PARSED);
    kasld_emit_scalar(SF_PHYS_KASLR_DISABLED, 1, CONF_PARSED);
  }

  /* CONFIG_KASAN=y forces the direct-map randomization off at runtime —
   * kaslr_memory_enabled() = kaslr_enabled() && !IS_ENABLED(CONFIG_KASAN) —
   * so page_offset / vmalloc / vmemmap stay at their compile-time defaults even
   * when CONFIG_RANDOMIZE_MEMORY=y. Consumed by directmap_kaslr_disabled_pin
   * (x86_64). The fact is arch-neutral; the rule gates on the arch. */
  if (is_kconfig_set(fp, "CONFIG_KASAN")) {
    kasld_info("CONFIG_KASAN=y");
    kasld_emit_scalar(SF_KASAN_ENABLED, 1, CONF_PARSED);
  }

  /* Kernel-text function ordering (canonical / static-reorder / FG-KASLR) —
   * gates whether a generic System.map can resolve symbols. See text_order.h.
   */
  emit_text_order_from_kconfig(fp, CONF_PARSED);

  /* s390 image-base layout discriminator. On an s390 config (CONFIG_S390=y),
   * the presence/absence of CONFIG_KERNEL_IMAGE_BASE distinguishes the modern
   * high separate-kernel-mapping layout (value > 0 → relocation floor) from the
   * pre-v6.8 identity-mapped layout (knob absent → kernel text in low RAM,
   * emitted as value 0). s390_image_base_from_config consumes this to recover a
   * tight image-base window without trusting version numbers. */
  if (is_kconfig_set(fp, "CONFIG_S390")) {
    unsigned long s390_image_base = get_kconfig_kernel_image_base(fp);
    kasld_info("CONFIG_KERNEL_IMAGE_BASE: %#lx%s", s390_image_base,
               s390_image_base ? "" : " (absent: identity-mapped layout)");
    kasld_emit_scalar(SF_VIRT_KERNEL_IMAGE_BASE, s390_image_base, CONF_PARSED);
  }

  fclose(fp);

  return 0;
}
