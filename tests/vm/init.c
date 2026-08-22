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
#include <elf.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/reboot.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
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

/* Read the first line of `path` into buf (newline-stripped); empty on failure.
 * Used to capture the kernel's own booted sysctl values as facts. */
static void read_sysctl(const char *path, char *buf, size_t sz) {
  buf[0] = '\0';
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return;
  ssize_t n = read(fd, buf, sz - 1);
  close(fd);
  if (n <= 0) {
    buf[0] = '\0';
    return;
  }
  buf[n] = '\0';
  char *nl = strchr(buf, '\n');
  if (nl)
    *nl = '\0';
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
 * RANDOMIZE_MEMORY region ground truth (/proc/kcore).
 *
 * On x86_64 the direct map, vmalloc and vmemmap regions are randomized
 * independently of the text base (CONFIG_RANDOMIZE_MEMORY); their bases are the
 * kernel variables page_offset_base / vmalloc_base / vmemmap_base. Each
 * variable's *value* is the ground truth for the matching resolved window —
 * and, unlike the text base, it is not in kallsyms (kallsyms carries the
 * variable's address, not its content). It is read from /proc/kcore, a sparse
 * ELF core of kernel memory: only the ELF program headers plus one word per
 * region are read (a few KiB), never the multi-terabyte whole. Needs root +
 * kptr=0 + CONFIG_PROC_KCORE; a silent no-op otherwise (an arch without these
 * symbols, or no kcore), which the harness treats as "no region truth".
 * ------------------------------------------------------------------------ */
#if __SIZEOF_POINTER__ == 8
typedef Elf64_Ehdr kc_ehdr;
typedef Elf64_Phdr kc_phdr;
#else
typedef Elf32_Ehdr kc_ehdr;
typedef Elf32_Phdr kc_phdr;
#endif

/* Address of `sym` in /proc/kallsyms (root/kptr=0 → real values). 0 if absent.
 */
static unsigned long kallsyms_addr(const char *sym) {
  FILE *f = fopen("/proc/kallsyms", "r");
  if (!f)
    return 0;
  size_t slen = strlen(sym);
  unsigned long addr = 0;
  char line[512];
  while (fgets(line, sizeof line, f)) {
    /* "ADDR TYPE NAME [MODULE]\n" — compare the 3rd field to sym exactly. */
    char *p = line;
    while (*p && *p != ' ')
      p++;
    char *aend = p;
    while (*p == ' ')
      p++;
    while (*p && *p != ' ')
      p++; /* type */
    while (*p == ' ')
      p++;
    char *name = p;
    while (*p && *p != ' ' && *p != '\n')
      p++;
    if ((size_t)(p - name) == slen && strncmp(name, sym, slen) == 0) {
      *aend = '\0';
      addr = strtoul(line, NULL, 16);
      break;
    }
  }
  fclose(f);
  return addr;
}

/* Ground-truth offsets of the bpf_verifier_ksym leak targets (mirrors its
 * k_funcs[]), each relative to _text, so a VM boot can check the base the
 * offset table recovers against these real values. */
static void dump_bpf_kfunc_offsets(void) {
  static const char *const kf[] = {
      "schedule",     "do_exit",       "kfree",         "kmem_cache_alloc",
      "vfs_read",     "vfs_write",     "vfs_open",      "filp_close",
      "sock_recvmsg", "tcp_sendmsg",   "ip_rcv",        "capable",
      "commit_creds", "prepare_creds", "get_task_cred", "wake_up_process"};
  unsigned long t = kallsyms_addr("_text");
  printf("=== bpf k_func offsets (from _text=0x%lx) ===\n", t);
  for (unsigned i = 0; i < sizeof kf / sizeof kf[0]; i++) {
    unsigned long a = kallsyms_addr(kf[i]);
    printf("  %-18s 0x%lx off=0x%lx\n", kf[i], a, (a && t) ? a - t : 0UL);
  }
}

/* Read one native word at kernel virtual address `addr` from /proc/kcore by
 * walking the PT_LOAD program headers to the segment that covers it. Returns 1
 * and sets *out on success (only the headers + one word are read). */
static int kcore_read_word(unsigned long addr, unsigned long *out) {
  int fd = open("/proc/kcore", O_RDONLY);
  if (fd < 0)
    return 0;
  int ok = 0;
  kc_ehdr eh;
  if (pread(fd, &eh, sizeof eh, 0) == (ssize_t)sizeof eh &&
      memcmp(eh.e_ident, ELFMAG, SELFMAG) == 0) {
    for (unsigned i = 0; i < eh.e_phnum; i++) {
      kc_phdr ph;
      off_t poff = (off_t)eh.e_phoff + (off_t)i * eh.e_phentsize;
      if (pread(fd, &ph, sizeof ph, poff) != (ssize_t)sizeof ph)
        break;
      if (ph.p_type != PT_LOAD || ph.p_memsz == 0)
        continue;
      if (addr >= ph.p_vaddr && addr - ph.p_vaddr < ph.p_memsz) {
        off_t foff = (off_t)ph.p_offset + (off_t)(addr - ph.p_vaddr);
        unsigned long v;
        if (pread(fd, &v, sizeof v, foff) == (ssize_t)sizeof v) {
          *out = v;
          ok = 1;
        }
        break;
      }
    }
  }
  close(fd);
  return ok;
}

/* The RANDOMIZE_MEMORY region bases whose live soundness tests/vm/run gates. */
static const char *const region_syms[] = {"page_offset_base", "vmalloc_base",
                                          "vmemmap_base"};

/* Ground truth for the randomized region bases. One "region_truth <name> =
 * 0x<value>" line per region that resolves; nothing where kcore/the symbols are
 * absent. Emitted alongside the kallsyms/iomem truth so tests/vm/run can gate
 * each region's resolved window the same way it gates the text base. */
static void dump_region_kaslr_truth(void) {
  printf("=== region kaslr truth (/proc/kcore) ===\n");
  int any = 0;
  for (unsigned i = 0; i < sizeof region_syms / sizeof region_syms[0]; i++) {
    unsigned long addr = kallsyms_addr(region_syms[i]), val;
    if (addr && kcore_read_word(addr, &val)) {
      printf("region_truth %s = 0x%lx\n", region_syms[i], val);
      any = 1;
    }
  }
  if (!any)
    printf("  <none — not randomized on this arch, or kcore unreadable>\n");
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
  /* RANDOMIZE_MEMORY region truth: the resolved VALUES (a few bytes), read from
   * kcore here — never kcore itself, which is terabyte-sparse. Carried as a
   * small synthetic frame so a fixture can gate the region windows offline. */
  {
    unsigned char buf[256];
    int n = 0;
    for (unsigned i = 0; i < sizeof region_syms / sizeof region_syms[0]; i++) {
      unsigned long addr = kallsyms_addr(region_syms[i]), val;
      if (addr && kcore_read_word(addr, &val))
        n += snprintf((char *)buf + n, sizeof buf - (size_t)n,
                      "region_truth %s = 0x%lx\n", region_syms[i], val);
    }
    if (n > 0)
      emit_frame("/kcore-region-truth", buf, (unsigned long)n);
  }
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
      /* Drop ALL supplementary groups first (still privileged) so the child is
       * not in adm/kvm/video/etc. — a truly unprivileged identity. adm, for
       * one, would read /var/log/dmesg past dmesg_restrict. */
      if (setgroups(0, NULL) != 0) {
        printf("setgroups(0) failed\n");
        _exit(126);
      }
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

/* Load every module staged into /modules.
 *
 * A real system always has modules loaded; a cell with none leaves every
 * module-region component reading an empty /proc/modules and no per-module
 * sections under /sys/module, which is indistinguishable from a component that
 * does not work. The module region is also the only place several rules can
 * bound the text base from, so a cell without one silently under-tests them.
 *
 * finit_module() directly rather than modprobe: the initramfs carries no shell,
 * no depmod output and no module tree, and these are dependency-free drivers
 * staged as plain files. */
static void load_staged_modules(void) {
  DIR *d = opendir("/modules");
  struct dirent *e;
  int loaded = 0;

  if (!d)
    return;
  while ((e = readdir(d)) != NULL) {
    size_t n = strlen(e->d_name);
    char path[512];
    int fd;

    if (n < 4 || strcmp(e->d_name + n - 3, ".ko") != 0)
      continue;
    snprintf(path, sizeof(path), "/modules/%s", e->d_name);
    fd = open(path, O_RDONLY);
    if (fd < 0)
      continue;
    if (syscall(SYS_finit_module, fd, "", 0) == 0) {
      printf("[init] module loaded: %s\n", e->d_name);
      loaded++;
    } else {
      printf("[init] module FAILED: %s\n", e->d_name);
    }
    close(fd);
  }
  closedir(d);
  if (!loaded)
    printf("[init] no modules loaded -- module-region components have "
           "nothing to read\n");
}

int main(void) {
  mount("proc", "/proc", "proc", 0, "");
  mount("sysfs", "/sys", "sysfs", 0, "");
  mount("devtmpfs", "/dev", "devtmpfs", 0, "");
  mount("tmpfs", "/tmp", "tmpfs", 0, "");
  /* debugfs, the source for debugfs-based leak components. Mounts only where
   * CONFIG_DEBUG_FS is built in; the call fails harmlessly otherwise. */
  mount("debugfs", "/sys/kernel/debug", "debugfs", 0, "");

  /* Before anything reads /proc/modules or /sys/module. */
  load_staged_modules();

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
   * unprivileged (uid 1000, no supplementary groups) — KASLD's threat model is
   * an unprivileged local attacker with no group privileges. Every scenario is
   * a REALISTIC single-knob delta from the kernel's OWN booted sysctl defaults
   * (captured below; with this minimal initramfs no distro sysctl.d runs, so
   * those are the compile-time defaults — dmesg_restrict is per-.config,
   * perf/kptr the upstream runtime defaults): default     — booted
   * kptr/dmesg/perf. NB on modern kernels /proc/kallsyms is zeroed for an
   * unprivileged reader even at kptr_restrict=0: kallsyms_show_value() needs
   * perf_event_paranoid<=1 or CAP_SYSLOG. So the honest default does NOT hand
   * over the base via kallsyms. kptr-hidden (`hidekptr`)  — default +
   * kptr_restrict=2 (a distro raising it). perf-open   (`perfopen`)  — default
   * + perf_event_paranoid=0 (a dev/CI host permitting perf); perf<=1 ALSO
   * unlocks kallsyms, the realistic recovery path there, so kptr stays at its
   * booted default. dmesg-open  (`dmesgopen`) — default + dmesg_restrict=0
   * (dmesg log readable). hardened    (`hardened`)  — kptr=2, dmesg=1, perf=3:
   * the file-only floor. The root ground-truth capture (kptr temporarily 0) is
   * the only privileged step; every branch then sets kptr/perf explicitly
   * (default restores booted). `capture` mode (below) reconstructs a fixture
   * and never reaches this. */
  int hidden = 0, hardened = 0, perfopen = 0, dmesgopen = 0, bpfopen = 0,
      tracefsopen = 0, capture = 0;
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
        if (strstr(cb, "perfopen"))
          perfopen = 1;
        if (strstr(cb, "dmesgopen"))
          dmesgopen = 1;
        if (strstr(cb, "bpfopen"))
          bpfopen = 1;
        if (strstr(cb, "tracefsopen"))
          tracefsopen = 1;
        if (strstr(cb, "capture"))
          capture = 1;
      }
      close(cf);
    }
  }

  /* Capture the kernel's booted sysctl defaults as facts BEFORE modifying
   * anything, and log them per cell (the compile-time posture — never assumed).
   * kptr_restrict is upstream 0 and dmesg_restrict is per-.config (mainline 0,
   * distro kernels may compile 1). Empties (absent sysctl) fall back to
   * upstream defaults so the restore-writes below are always valid. */
  char b_kptr[16], b_perf[16], b_dmesg[16];
  read_sysctl("/proc/sys/kernel/kptr_restrict", b_kptr, sizeof b_kptr);
  read_sysctl("/proc/sys/kernel/perf_event_paranoid", b_perf, sizeof b_perf);
  read_sysctl("/proc/sys/kernel/dmesg_restrict", b_dmesg, sizeof b_dmesg);
  if (!b_kptr[0])
    strcpy(b_kptr, "0");
  if (!b_perf[0])
    strcpy(b_perf, "2");
  if (!b_dmesg[0])
    strcpy(b_dmesg, "0");
  printf("=== booted sysctls: kptr_restrict=%s perf_event_paranoid=%s "
         "dmesg_restrict=%s ===\n",
         b_kptr, b_perf, b_dmesg);

  /* Capture ground truth as root with kallsyms readable (needs kptr=0). perf is
   * opened only for the capture pass; the analysis profiles below each set
   * kptr/perf explicitly. */
  write_file("/proc/sys/kernel/kptr_restrict", "0\n");
  write_file("/proc/sys/kernel/perf_event_paranoid", "-1\n");

  printf(
      "\n\n==================== KASLD VM GROUND TRUTH ====================\n");
  dump_file("/proc/version", "version");
  dump_file("/proc/cmdline", "cmdline");
  dump_kallsyms_landmarks();
  dump_bpf_kfunc_offsets();
  dump_iomem_kernel();
  dump_region_kaslr_truth();
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
  /* unprivileged_bpf_disabled is left at its BOOTED value in every profile but
   * two: the kernel's own default is what an unprivileged attacker actually
   * faces (a distro built CONFIG_BPF_UNPRIV_DEFAULT_OFF boots it locked at 2).
   * hardened forces it off; the dedicated bpf-open profile forces it on to
   * exercise the bpf verifier-log leaks — the perf-open equivalent for a host
   * that permits unprivileged bpf(). */
  if (hardened) {
    write_file("/proc/sys/kernel/kptr_restrict", "2\n");
    write_file("/proc/sys/kernel/dmesg_restrict", "1\n");
    write_file("/proc/sys/kernel/perf_event_paranoid", "3\n");
    write_file("/proc/sys/kernel/unprivileged_bpf_disabled", "2\n");
    printf("=== profile: hardened — uid=1000, kptr_restrict=2, "
           "dmesg_restrict=1, perf_event_paranoid=3 (file-only floor) ===\n");
  } else if (perfopen) {
    /* default + perf relaxed (a host permitting unprivileged perf). perf<=1
     * also unlocks /proc/kallsyms (kallsyms_for_perf), the realistic recovery
     * path — so kptr stays at its booted default, not forced. */
    write_file("/proc/sys/kernel/kptr_restrict", b_kptr);
    write_file("/proc/sys/kernel/perf_event_paranoid", "0\n");
    printf("=== profile: perf-open — uid=1000, kptr_restrict=%s (booted), "
           "perf_event_paranoid=0, dmesg_restrict=%s (booted) ===\n",
           b_kptr, b_dmesg);
  } else if (dmesgopen) {
    /* default + dmesg log opened; kptr/perf stay at their booted defaults. */
    write_file("/proc/sys/kernel/kptr_restrict", b_kptr);
    write_file("/proc/sys/kernel/dmesg_restrict", "0\n");
    write_file("/proc/sys/kernel/perf_event_paranoid", b_perf);
    printf("=== profile: dmesg-open — uid=1000, kptr_restrict=%s (booted), "
           "dmesg_restrict=0, perf_event_paranoid=%s (booted) ===\n",
           b_kptr, b_perf);
  } else if (bpfopen) {
    /* default + unprivileged bpf() enabled (a host permitting it; only there do
     * the bpf verifier-log leaks fire). Other knobs stay at their booted
     * defaults. This root write re-enables bpf even where the kernel locked it
     * at 2 — an unprivileged attacker could not, so it models an
     * admin-permitted-bpf host, not a stock default. */
    write_file("/proc/sys/kernel/kptr_restrict", b_kptr);
    write_file("/proc/sys/kernel/perf_event_paranoid", b_perf);
    write_file("/proc/sys/kernel/unprivileged_bpf_disabled", "0\n");
    printf("=== profile: bpf-open — uid=1000, unprivileged_bpf_disabled=0, "
           "kptr_restrict=%s perf_event_paranoid=%s (booted) ===\n",
           b_kptr, b_perf);
  } else if (tracefsopen) {
    /* kallsyms hidden (kptr=2) but tracefs group-readable (mounted gid=1000
     * below): the tracefs address tables carry no kptr_restrict gate, so they
     * recover the text base where /proc/kallsyms is masked. The "tracing group"
     * vantage (Android AID_READTRACEFS). */
    write_file("/proc/sys/kernel/kptr_restrict", "2\n");
    write_file("/proc/sys/kernel/perf_event_paranoid", b_perf);
    printf("=== profile: tracefs-open — uid=1000, kptr_restrict=2, "
           "tracefs gid=1000 (dmesg_restrict=%s perf_event_paranoid=%s "
           "booted) ===\n",
           b_dmesg, b_perf);
  } else if (hidden) {
    write_file("/proc/sys/kernel/kptr_restrict", "2\n");
    write_file("/proc/sys/kernel/perf_event_paranoid", b_perf);
    printf("=== profile: kptr-hidden — uid=1000, kptr_restrict=2, "
           "dmesg_restrict=%s perf_event_paranoid=%s (booted) ===\n",
           b_dmesg, b_perf);
  } else {
    write_file("/proc/sys/kernel/kptr_restrict", b_kptr);
    write_file("/proc/sys/kernel/perf_event_paranoid", b_perf);
    printf("=== profile: default — uid=1000, kptr_restrict=%s "
           "dmesg_restrict=%s perf_event_paranoid=%s (all booted) ===\n",
           b_kptr, b_dmesg, b_perf);
  }
  fflush(stdout);

  /* tracefs-open vantage only: mount tracefs group-readable by the unprivileged
   * uid so the tracefs components (printk_formats,
   * available_filter_functions_addrs) read the address tables without root —
   * the "tracing group" (Android AID_READTRACEFS) scenario. Done as root here,
   * before run_as drops to uid 1000. gid=1000,mode=755 makes the tree
   * traversable and leaves the 0440 tables group-readable; a no-op on kernels
   * built without tracing (the mountpoint is absent). Other profiles never
   * mount it, so those components stay UNAVAILABLE there. */
  if (tracefsopen)
    mount("tracefs", "/sys/kernel/tracing", "tracefs", 0, "gid=1000,mode=755");

  /* Run kasld in JSON mode — tests/vm/run reads the window from the -j output,
   * and the ground-truth dump above supplies the comparison value. */
  char *av_j[] = {"/kasld", "-j", NULL};
  run_as(uid, "/kasld", av_j);

  /* Then once more for the human-readable readout and the address-space
   * diagram. --map, not --verbose: the layout rendering is the only thing this
   * second pass is for, and -v adds per-component narration and the explain
   * text on top of it. The components still re-run (there is no way to render
   * two formats from one pass), so this stays the cheapest form of the second
   * run — under TCG the per-component narration is what turns a slow boot into
   * a timed-out one. Every layout decision is otherwise only ever seen on
   * x86_64; this is what puts the map in front of a coupled 32-bit arch. */
  char *av_map[] = {"/kasld", "--map", "-q", NULL};
  run_as(uid, "/kasld", av_map);

  printf("\n==================== KASLD VM DONE ====================\n");
  sync();
  sleep(1);
  reboot(LINUX_REBOOT_CMD_POWER_OFF);
  for (;;)
    pause();
  return 0;
}
