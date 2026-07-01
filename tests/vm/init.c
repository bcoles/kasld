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

  /* Restriction profile (from cmdline tokens):
   *   default   — root, kptr_restrict=0: kasld can read everything.
   *   hidekptr  — root, kptr_restrict=2: no kallsyms; the pin must come from
   *               inference (exercises the engine, not the kallsyms shortcut).
   *   hardened  — drop to uid 1000 with kptr_restrict=2, dmesg_restrict=1,
   *               perf_event_paranoid=3: the realistic unprivileged-attacker
   *               floor, where only file-derived facts survive.
   *   stock     — drop to uid 1000 but leave every sysctl at its kernel default
   *               (kptr_restrict=0, dmesg_restrict=0, perf_event_paranoid=2):
   *               an unprivileged user on an out-of-the-box kernel, neither
   *               weakened nor hardened by us. */
  int hidden = 0, hardened = 0, stock = 0;
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

  /* Apply the requested restriction profile before running kasld. */
  uid_t uid = 0;
  if (hardened) {
    write_file("/proc/sys/kernel/kptr_restrict", "2\n");
    write_file("/proc/sys/kernel/dmesg_restrict", "1\n");
    write_file("/proc/sys/kernel/perf_event_paranoid", "3\n");
    uid = 1000;
    printf("=== profile: HARDENED — uid=1000, kptr_restrict=2, "
           "dmesg_restrict=1, perf_event_paranoid=3 (file-only floor) ===\n");
  } else if (hidden) {
    write_file("/proc/sys/kernel/kptr_restrict", "2\n");
    printf("=== profile: hidden — root, kptr_restrict=2 (no kallsyms) ===\n");
  } else if (stock) {
    /* Kernel-default sysctls, nothing weakened or hardened by us: vanilla
     * defaults are kptr_restrict=0, dmesg_restrict=0, perf_event_paranoid=2.
     * Reset perf from the -1 used for the ground-truth dump; leave kptr and
     * dmesg at their defaults. Run unprivileged. */
    write_file("/proc/sys/kernel/perf_event_paranoid", "2\n");
    uid = 1000;
    printf("=== profile: stock — uid=1000, kernel-default sysctls "
           "(kptr_restrict=0, dmesg_restrict=0, perf_event_paranoid=2) ===\n");
  } else {
    printf("=== profile: default — root, kptr_restrict=0 ===\n");
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
