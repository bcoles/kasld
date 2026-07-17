// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Minimal PID-1 init for the live cross-architecture validation VMs
// (tests/vm/run). Arch-agnostic and statically cross-compiled per target.
//
// It boots as init, mounts the pseudo-filesystems, captures the kernel's
// ground truth (the real _text/_stext from kallsyms, with kptr_restrict
// lowered), then applies an optional restriction profile and runs the
// bundled `kasld` in verbose and JSON modes. tests/vm/run reads the
// resulting console log and checks the soundness invariant:
//
//     truth ∈ [virt_image_base_min, virt_image_base_max]
//
// The ground-truth dump is always captured first, as root with kptr=0, so
// the same boot yields the comparison baseline even for restricted runs.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <linux/reboot.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

static void write_file(const char *path, const char *val) {
  int fd = open(path, O_WRONLY);
  if (fd >= 0) {
    if (write(fd, val, strlen(val)) < 0) { /* best effort */
    }
    close(fd);
  }
}

static void dump_file(const char *path, const char *label) {
  int fd = open(path, O_RDONLY);
  printf("=== %s (%s) ===\n", label, path);
  if (fd < 0) {
    printf("  <absent or unreadable>\n\n");
    return;
  }
  char buf[4096];
  ssize_t n;
  while ((n = read(fd, buf, sizeof buf)) > 0)
    if (write(1, buf, (size_t)n) < 0)
      break;
  close(fd);
  printf("\n");
}

/* Print only the landmark kallsyms lines (the virtual text base etc.). This is
 * the ground truth tests/vm/run compares the inferred window against. */
static void dump_kallsyms_landmarks(void) {
  FILE *f = fopen("/proc/kallsyms", "r");
  printf("=== kallsyms landmarks (/proc/kallsyms) ===\n");
  if (!f) {
    printf("  <unreadable>\n\n");
    return;
  }
  char line[512];
  while (fgets(line, sizeof line, f)) {
    if (strstr(line, " _text\n") || strstr(line, " _stext\n") ||
        strstr(line, " _etext\n") || strstr(line, " _end\n"))
      fputs(line, stdout);
  }
  fclose(f);
  printf("\n");
}

/* Print only the /proc/iomem lines naming the kernel (physical text base). */
static void dump_iomem_kernel(void) {
  FILE *f = fopen("/proc/iomem", "r");
  printf("=== iomem kernel ranges (/proc/iomem) ===\n");
  if (!f) {
    printf("  <unreadable>\n\n");
    return;
  }
  char line[512];
  while (fgets(line, sizeof line, f))
    if (strstr(line, "Kernel code") || strstr(line, "Kernel data") ||
        strstr(line, "System RAM"))
      fputs(line, stdout);
  fclose(f);
  printf("\n");
}

/* ------------------------------------------------------------------------
 * Bundle capture (capture mode only).
 *
 * Emit the same /proc, /sys and /boot facts extra/collect gathers, framed on
 * the serial console so tests/vm/run can reconstruct a truth-bearing fixture
 * (real kallsyms + iomem — captured here as root with kptr_restrict=0) without
 * a shell or 9p in the guest. Each file is base64-encoded (binary-safe over
 * serial; the alphabet has no CR/NUL the harness strips):
 *
 *     KCAPv1 BEGIN <path>
 *     <base64 lines>
 *     KCAPv1 END <path> <nbytes>
 *
 * An absent/unreadable file emits nothing (the harness treats a missing frame
 * as absent, matching collect). /proc reports st_size 0, so the byte count is
 * carried on the END line (counted while streaming), not up front.
 * ------------------------------------------------------------------------ */
static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Encode n (1..3) input bytes to one base64 quantum, wrapping at 76 columns. */
static void b64_quantum(const unsigned char *in, int n, int *col) {
  unsigned char o[4];
  o[0] = (unsigned char)B64[in[0] >> 2];
  o[1] = (unsigned char)B64[((in[0] & 0x3) << 4) | (n > 1 ? in[1] >> 4 : 0)];
  o[2] =
      n > 1
          ? (unsigned char)B64[((in[1] & 0xf) << 2) | (n > 2 ? in[2] >> 6 : 0)]
          : (unsigned char)'=';
  o[3] = n > 2 ? (unsigned char)B64[in[2] & 0x3f] : (unsigned char)'=';
  fwrite(o, 1, 4, stdout);
  *col += 4;
  if (*col >= 76) {
    putchar('\n');
    *col = 0;
  }
}

static void capture_file(const char *path) {
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return; /* absent/unreadable: emit no frame */
  printf("KCAPv1 BEGIN %s\n", path);
  unsigned char buf[4096], carry[3];
  int cn = 0, col = 0;
  unsigned long total = 0;
  ssize_t r;
  while ((r = read(fd, buf, sizeof buf)) > 0) {
    total += (unsigned long)r;
    for (ssize_t i = 0; i < r; i++) {
      carry[cn++] = buf[i];
      if (cn == 3) {
        b64_quantum(carry, 3, &col);
        cn = 0;
      }
    }
  }
  if (cn > 0)
    b64_quantum(carry, cn, &col); /* final partial quantum, padded */
  if (col)
    putchar('\n');
  close(fd);
  printf("KCAPv1 END %s %lu\n", path, total);
  fflush(stdout);
}

/* Emit an in-memory buffer as a KCAPv1 frame (base64, byte-count on END). */
static void emit_frame(const char *path, const unsigned char *data,
                       unsigned long len) {
  printf("KCAPv1 BEGIN %s\n", path);
  int col = 0;
  unsigned long i = 0;
  for (; i + 3 <= len; i += 3)
    b64_quantum(data + i, 3, &col);
  if (i < len)
    b64_quantum(data + i, (int)(len - i), &col);
  if (col)
    putchar('\n');
  printf("KCAPv1 END %s %lu\n", path, len);
  fflush(stdout);
}

/* /proc/kallsyms is multi-MB (one line per symbol) but the offline analysis
 * reads only a handful of image-boundary landmarks (proc_kallsyms scans _text/
 * _stext/_etext; validate-bundle takes _text/_stext/_end as ground truth).
 * Capturing the full table would bloat the committed fixture and overrun the
 * serial link; emit only the landmark lines, which carry the same real
 * addresses (the truth). */
static int kallsyms_landmark(const char *sym) {
  static const char *const keep[] = {
      "_text",      "_stext",          "_etext",        "_sinittext",
      "_einittext", "_sdata",          "_edata",        "__bss_start",
      "__bss_stop", "__start_rodata",  "__end_rodata",  "__init_begin",
      "__init_end", "__per_cpu_start", "__per_cpu_end", "startup_64",
      "_end"};
  for (unsigned i = 0; i < sizeof keep / sizeof keep[0]; i++)
    if (strcmp(sym, keep[i]) == 0)
      return 1;
  return 0;
}

static void capture_kallsyms(void) {
  FILE *f = fopen("/proc/kallsyms", "r");
  if (!f)
    return;
  static unsigned char out[8192]; /* landmark subset: a few hundred bytes */
  unsigned long n = 0;
  char line[512];
  while (fgets(line, sizeof line, f)) {
    /* "ADDR TYPE SYMBOL [MODULE]\n" — isolate the 3rd field. */
    char *p = line;
    while (*p && *p != ' ')
      p++; /* addr */
    while (*p == ' ')
      p++;
    while (*p && *p != ' ')
      p++; /* type */
    while (*p == ' ')
      p++;
    char *sym = p;
    while (*p && *p != ' ' && *p != '\n')
      p++;
    char saved = *p;
    *p = '\0';
    int keep = kallsyms_landmark(sym);
    *p = saved;
    if (keep) {
      unsigned long ll = strlen(line);
      if (n + ll < sizeof out) {
        memcpy(out + n, line, ll);
        n += ll;
      }
    }
  }
  fclose(f);
  emit_frame("/proc/kallsyms", out, n);
}

/* Recurse a small kernel-exposed tree, capturing regular files (device-tree,
 * firmware/memmap). Bounded by the tree's own size. */
static void capture_tree(const char *dir) {
  DIR *d = opendir(dir);
  if (!d)
    return;
  struct dirent *e;
  while ((e = readdir(d))) {
    if (e->d_name[0] == '.' &&
        (e->d_name[1] == '\0' || (e->d_name[1] == '.' && e->d_name[2] == '\0')))
      continue;
    char p[1024];
    snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
    struct stat st;
    if (lstat(p, &st) != 0)
      continue;
    if (S_ISDIR(st.st_mode))
      capture_tree(p);
    else if (S_ISREG(st.st_mode))
      capture_file(p);
  }
  closedir(d);
}

/* Emit every fact the offline analysis reads, mirroring extra/collect's list.
 * Arch-generic: device-tree / firmware paths absent on a given arch emit
 * nothing. Runs as root with kptr_restrict=0, so kallsyms and iomem carry the
 * real ground truth the reconstructed fixture is validated against. */
static void capture_bundle(void) {
  struct utsname u;
  if (uname(&u) == 0) {
    printf("KCAPv1 META release %s\n", u.release);
    printf("KCAPv1 META machine %s\n", u.machine);
  }
  static const char *const files[] = {"/proc/meminfo",
                                      "/proc/cpuinfo",
                                      "/proc/zoneinfo",
                                      "/proc/cmdline",
                                      "/proc/iomem",
                                      "/proc/modules",
                                      "/proc/version",
                                      "/proc/sys/kernel/kptr_restrict",
                                      "/proc/sys/kernel/dmesg_restrict",
                                      "/proc/sys/kernel/perf_event_paranoid",
                                      "/proc/sys/kernel/randomize_va_space",
                                      "/sys/kernel/security/lockdown",
                                      "/sys/kernel/boot_params/data",
                                      "/sys/kernel/boot_params/setup_data",
                                      "/sys/kernel/notes",
                                      "/proc/config.gz"};
  for (unsigned i = 0; i < sizeof files / sizeof files[0]; i++)
    capture_file(files[i]);
  capture_kallsyms(); /* landmark lines only (see capture_kallsyms) */
  capture_tree("/sys/firmware/memmap");
  capture_tree("/proc/device-tree/chosen");
  capture_tree("/proc/device-tree/rtas");
  capture_tree("/sys/firmware/devicetree/base/chosen");
  capture_tree("/sys/firmware/devicetree/base/rtas");
  capture_file("/sys/firmware/fdt");
  printf("KCAPv1 DONE\n");
  fflush(stdout);
}

/* Run `path` and wait. If uid != 0 drop to that uid/gid first (gid before uid,
 * while still privileged) so the child runs fully unprivileged — the realistic
 * attacker identity. chdir to /tmp (the only world-writable mount). */
static void run_as(uid_t uid, const char *path, char *const argv[]) {
  printf("\n########## EXEC");
  if (uid)
    printf(" (uid=%d)", (int)uid);
  printf(" %s", path);
  for (int i = 1; argv[i]; i++)
    printf(" %s", argv[i]);
  printf(" ##########\n");
  fflush(stdout);
  pid_t pid = fork();
  if (pid == 0) {
    if (chdir("/tmp") != 0) { /* best effort */
    }
    if (uid != 0) {
      if (setgid((gid_t)uid) != 0) {
        printf("setgid(%d) failed\n", (int)uid);
        _exit(126);
      }
      if (setuid(uid) != 0) {
        printf("setuid(%d) failed\n", (int)uid);
        _exit(126);
      }
    }
    execv(path, argv);
    printf("execv(%s) failed\n", path);
    _exit(127);
  }
  int st;
  waitpid(pid, &st, 0);
  printf("########## %s exited rc=%d ##########\n", path, WEXITSTATUS(st));
  fflush(stdout);
}

int main(void) {
  mount("proc", "/proc", "proc", 0, "");
  mount("sysfs", "/sys", "sysfs", 0, "");
  mount("devtmpfs", "/dev", "devtmpfs", 0, "");
  mount("tmpfs", "/tmp", "tmpfs", 0, "");

  /* Stage the kernel image where kasld's kernel_image_facts expects it:
   * /boot/vmlinuz-<release>, keyed by uname -r. The initramfs carries the image
   * at /kernel-image; we cannot know the release until boot, so symlink it
   * here. Without this, the image-size facts (and the rules needing them)
   * cannot fire, since these VMs boot vmlinuz via -kernel with no /boot. */
  {
    struct utsname u;
    if (access("/kernel-image", F_OK) == 0 && uname(&u) == 0) {
      mkdir("/boot", 0755);
      char p[256];
      snprintf(p, sizeof p, "/boot/vmlinuz-%s", u.release);
      if (symlink("/kernel-image", p) != 0) { /* best effort */
      }
    }
  }

  /* Restriction profile (from cmdline tokens). The analysis phase always runs
   * unprivileged (uid 1000) — KASLD's threat model is an unprivileged local
   * attacker, so every scenario measures what such a user can leak, never what
   * root can. Scenarios differ only by the sysctl hardening applied:
   *   default   — uid 1000, kptr_restrict=0: permissive sysctls; an
   *               unprivileged user can still read kallsyms/iomem values.
   *   hidekptr  — uid 1000, kptr_restrict=2: no kallsyms; the pin must come
   * from inference (exercises the engine, not the kallsyms shortcut). hardened
   * — uid 1000, kptr_restrict=2, dmesg_restrict=1, perf_event_paranoid=3: the
   * realistic unprivileged-attacker floor, where only file-derived facts
   * survive. stock     — uid 1000 but leave every sysctl at its kernel default
   *               (kptr_restrict=0, dmesg_restrict=0, perf_event_paranoid=2):
   *               an unprivileged user on an out-of-the-box kernel, neither
   *               weakened nor hardened by us.
   * The root ground-truth capture above is the only privileged step. */
  int hidden = 0, hardened = 0, stock = 0, capture = 0;
  {
    int cf = open("/proc/cmdline", O_RDONLY);
    char cb[512];
    ssize_t cn;
    if (cf >= 0) {
      cn = read(cf, cb, sizeof cb - 1);
      if (cn > 0) {
        cb[cn] = 0;
        if (strstr(cb, "hidekptr"))
          hidden = 1;
        if (strstr(cb, "hardened"))
          hardened = 1;
        if (strstr(cb, "stock"))
          stock = 1;
        if (strstr(cb, "capture"))
          capture = 1;
      }
      close(cf);
    }
  }

  /* Always capture ground truth first, as root with kallsyms readable — even in
   * hidden/hardened runs (the comparison baseline comes from the same boot). */
  write_file("/proc/sys/kernel/kptr_restrict", "0\n");
  write_file("/proc/sys/kernel/perf_event_paranoid", "-1\n");

  printf(
      "\n\n==================== KASLD VM GROUND TRUTH ====================\n");
  dump_file("/proc/version", "version");
  dump_file("/proc/cmdline", "cmdline");
  dump_kallsyms_landmarks();
  dump_iomem_kernel();
  printf("=== presence probes ===\n");
  printf("/sys/firmware/efi: %d   /proc/device-tree: %d   "
         "/proc/device-tree/chosen/kaslr-seed: %d\n",
         access("/sys/firmware/efi", F_OK) == 0,
         access("/proc/device-tree", F_OK) == 0,
         access("/proc/device-tree/chosen/kaslr-seed", F_OK) == 0);
  fflush(stdout);

  /* Capture mode: emit the fact bundle (still root, kptr_restrict=0 → real
   * kallsyms/iomem truth) framed on serial for tests/vm/run to reconstruct a
   * fixture, then power off. No kasld run and no restriction profile — the
   * fixture is validated offline. */
  if (capture) {
    printf("\n==================== KASLD VM CAPTURE ====================\n");
    capture_bundle();
    printf("\n==================== KASLD VM DONE ====================\n");
    sync();
    sleep(1);
    reboot(LINUX_REBOOT_CMD_POWER_OFF);
    for (;;)
      pause();
    return 0;
  }

  /* Apply the requested restriction profile before running kasld. The analysis
   * always runs unprivileged; only the sysctl hardening varies. */
  uid_t uid = 1000;
  if (hardened) {
    write_file("/proc/sys/kernel/kptr_restrict", "2\n");
    write_file("/proc/sys/kernel/dmesg_restrict", "1\n");
    write_file("/proc/sys/kernel/perf_event_paranoid", "3\n");
    printf("=== profile: HARDENED — uid=1000, kptr_restrict=2, "
           "dmesg_restrict=1, perf_event_paranoid=3 (file-only floor) ===\n");
  } else if (hidden) {
    write_file("/proc/sys/kernel/kptr_restrict", "2\n");
    printf(
        "=== profile: hidden — uid=1000, kptr_restrict=2 (no kallsyms) ===\n");
  } else if (stock) {
    /* Kernel-default sysctls, nothing weakened or hardened by us: vanilla
     * defaults are kptr_restrict=0, dmesg_restrict=0, perf_event_paranoid=2.
     * Reset perf from the -1 used for the ground-truth dump; leave kptr and
     * dmesg at their defaults. */
    write_file("/proc/sys/kernel/perf_event_paranoid", "2\n");
    printf("=== profile: stock — uid=1000, kernel-default sysctls "
           "(kptr_restrict=0, dmesg_restrict=0, perf_event_paranoid=2) ===\n");
  } else {
    printf("=== profile: default — uid=1000, kptr_restrict=0 ===\n");
  }
  fflush(stdout);

  /* Run kasld in JSON mode only — tests/vm/run reads the window from the -j
   * output, and the ground-truth dump above supplies the comparison value. A
   * second verbose run would just double the work (every component re-spawned,
   * the live probes re-run) for output the check does not consume, which under
   * TCG emulation is the difference between finishing and timing out. */
  char *av_j[] = {"/kasld", "-j", NULL};
  run_as(uid, "/kasld", av_j);

  printf("\n==================== KASLD VM DONE ====================\n");
  sync();
  sleep(1);
  reboot(LINUX_REBOOT_CMD_POWER_OFF);
  for (;;)
    pause();
  return 0;
}
