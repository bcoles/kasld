// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Emit the kernel image size, read from the running kernel's /boot artefacts.
// The footprint is a two-ended interval; what each source proves decides which
// fact(s) it emits:
//   exact source (Image header / x86 bzImage / ELF / System.map / arm32 zImage
//     table / EFI zboot payload) — the exact in-memory footprint
//     (_end - _text); sound in both directions, so emits BOTH
//     SF_IMAGE_SIZE_MIN (ceiling) and SF_IMAGE_SIZE_MAX (floor).
//   lower-bound source (gzip ISIZE / compressed vmlinuz size) — below the
//     footprint (excludes BSS), so emits SF_IMAGE_SIZE_MIN only.
// x86 also supplies both facts from boot_params (boot_params_facts.c).
//
// An EFI zboot vmlinuz is a container, not a kernel image: the kernel inside it
// declares its own extent, so reading that needs the payload's first bytes and
// therefore a decompressor. Where none is available the container is sized by
// its file length instead, which is a looser lower bound and no upper bound at
// all -- the absence of a decompressor widens the window rather than changing
// what is claimed.
//
// Every reader here targets the same artefact family, so the component answers
// for one source and can say which of "denied" and "absent" applies when none
// of the formats matched.
// ---
// <bcoles@gmail.com>
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include "include/kasld/kernel_image.h"

#include <sys/wait.h>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

KASLD_EXPLAIN(
    "Reads the kernel image size from /boot (EFI/PE Image header, x86 "
    "bzImage setup header, ELF vmlinux, System.map, arm32 zImage table, "
    "EFI zboot payload header, or a gzip ISIZE trailer) and emits it as a "
    "scalar fact bounding the KASLR window. No privileges.");
KASLD_META("method:parsed\n"
           "phase:inference\n"
           "discloses:facts\n"
           "source:files\n");

/* Fill `buf` with exactly `n` bytes from `fd`, or return non-zero. A short
 * read would leave the tail holding whatever the caller's stack held, and the
 * header fields are then decided by it. */
static int read_exactly(int fd, void *buf, size_t n) {
  size_t off = 0;
  while (off < n) {
    ssize_t r = read(fd, (char *)buf + off, n - off);
    if (r < 0 && errno == EINTR)
      continue;
    if (r <= 0)
      return -1;
    off += (size_t)r;
  }
  return 0;
}

/* Read up to `n` bytes of the decompressed payload into `out`, starting from
 * the file offset `fd` is already positioned at. Takes ownership of `fd`.
 * Returns the number of bytes obtained, which may be short of `n`.
 *
 * Only a prefix is wanted, so the decompressor is stopped once it has produced
 * one rather than being left to expand the whole image. */
static size_t payload_prefix(int fd, uint8_t *out, size_t n) {
#ifdef HAVE_ZLIB
  /* gzdopen takes ownership of fd: gzclose closes it, and on failure the
   * descriptor is closed here before returning. */
  gzFile gz = gzdopen(fd, "rb");
  if (!gz) {
    close(fd);
    return 0;
  }
  size_t got = 0;
  while (got < n) {
    int r = gzread(gz, out + got, (unsigned)(n - got));
    if (r <= 0)
      break;
    got += (size_t)r;
  }
  gzclose(gz);
  return got;
#else
  /* No zlib (the static cross builds have none: no musl toolchain ships one).
   * Spawn zcat directly rather than through a shell -- popen would run /bin/sh,
   * which expands $( ) even inside double quotes -- and hand it the open
   * descriptor as standard input: zcat reads stdin when given no file argument,
   * so there is no command string and no path for the child to interpret.
   *
   * The descriptor is already positioned at the payload and the child inherits
   * that offset, which is what lets a stream beginning partway into a file be
   * decompressed without naming the file or copying the bytes. */
  int pipefd[2];
  if (pipe(pipefd) != 0) {
    close(fd);
    return 0;
  }

  pid_t pid = fork();
  if (pid < 0) {
    close(pipefd[0]);
    close(pipefd[1]);
    close(fd);
    return 0;
  }
  if (pid == 0) {
    if (dup2(fd, STDIN_FILENO) < 0 || dup2(pipefd[1], STDOUT_FILENO) < 0)
      _exit(127);
    close(pipefd[0]);
    close(pipefd[1]);
    close(fd);
    /* A modifiable array rather than a cast of the literal: execvp's argv is
     * char *const[], and casting away const on a string literal is what
     * -Wcast-qual looks for. */
    char zcat[] = "zcat";
    char *const argv[] = {zcat, NULL};
    execvp(zcat, argv);
    _exit(127); /* zcat absent; the empty read below reports it */
  }

  close(pipefd[1]);
  close(fd);

  size_t got = 0;
  while (got < n) {
    ssize_t r = read(pipefd[0], out + got, n - got);
    if (r < 0 && errno == EINTR)
      continue;
    if (r <= 0)
      break;
    got += (size_t)r;
  }
  close(pipefd[0]);
  /* Closing the read end ends the child the next time it writes; the bytes
   * already obtained are the answer, so its exit status is not consulted. */
  waitpid(pid, NULL, 0);
  return got;
#endif
}

/* The exact footprint declared by the kernel image inside an EFI zboot
 * container, or 0.
 *
 * Two independent encodings of the same number must agree: the container's
 * length word -- the padded payload length, which Makefile.zboot sets from the
 * payload's own declared size -- and that declared size, read from the
 * payload's first 64 bytes. Either can be wrong on its own: the length word is
 * read at an offset the header supplies, and the declared field comes out of a
 * decompressed prefix. The figure feeds an upper bound that the evidence layer
 * takes the minimum over, so one that is too small displaces the exact facts
 * instead of merely being loose. Disagreement is refused, not resolved.
 *
 * A payload whose compressor has no decoder here is left alone: the container
 * still yields its lower bound through kasld_image_size_from_gzip. */
static unsigned long zboot_exact_size(const char *release,
                                      enum kasld_image_bound *bound) {
  if (bound)
    *bound = KIMG_BOUND_NONE;

  static const char *const prefix[] = {"/boot/vmlinuz-", "/boot/Image-"};
  char path[256];

  for (size_t i = 0; i < sizeof(prefix) / sizeof(prefix[0]); i++) {
    snprintf(path, sizeof(path), "%s%s", prefix[i], release);

    /* Opened ONCE and identified by its descriptor from here on. The two
     * figures compared below are the whole point of this reader, and reading
     * them through two opens of the same name would let a file replaced in
     * between answer one each: an honest length word with a lying payload
     * passes a check made across both. fstat on the open descriptor sizes the
     * same file that is read, rather than whatever the name means next. */
    int fd = kasld_open(path, O_RDONLY);
    if (fd < 0)
      continue;

    uint8_t hdr[56];
    struct stat st;
    struct kasld_zboot z;
    if (fstat(fd, &st) != 0 || st.st_size <= 0 ||
        read_exactly(fd, hdr, sizeof(hdr)) != 0 ||
        !kasld_zboot_header(hdr, sizeof(hdr), (unsigned long)st.st_size, &z) ||
        !z.gzip) {
      close(fd);
      continue;
    }

    /* The container's own length word, at the offset the header named. */
    uint8_t tw[4];
    if (lseek(fd, (off_t)z.size_trailer, SEEK_SET) == (off_t)-1 ||
        read_exactly(fd, tw, sizeof(tw)) != 0) {
      close(fd);
      continue;
    }
    unsigned long trailer = (unsigned long)tw[0] | ((unsigned long)tw[1] << 8) |
                            ((unsigned long)tw[2] << 16) |
                            ((unsigned long)tw[3] << 24);

    if (lseek(fd, (off_t)z.payload_off, SEEK_SET) == (off_t)-1) {
      close(fd);
      continue;
    }

    uint8_t pre[64];
    size_t got =
        payload_prefix(fd, pre, sizeof(pre)); /* takes the descriptor */

    /* The prefix came out of a zboot container, which is built for arm64, riscv
     * and loongarch alone, so the offset-16 extent field is established for it:
     * no x86 image can reach that read by this path. */
    unsigned long declared = kasld_image_extent_from_prefix(pre, got, 1);
    if (declared && trailer && declared == trailer)
      return kasld_image_bounded(declared, KIMG_BOUND_EXACT, bound);
  }
  return 0;
}

/* Which of the two failure classes the /boot artefact is in, or 0 when it is
 * readable and simply parsed by nothing. The size readers swallow errno to keep
 * their own contract simple, so the question is asked again here, once, on the
 * path where it matters. */
static int boot_artefact_class(const char *release) {
  static const char *const prefix[] = {"/boot/vmlinuz-", "/boot/Image-",
                                       "/boot/System.map-"};
  char path[512];
  int denied = 0;
  for (size_t i = 0; i < sizeof(prefix) / sizeof(prefix[0]); i++) {
    snprintf(path, sizeof(path), "%s%s", prefix[i], release);
    FILE *f = kasld_fopen(path, "rb");
    if (f) {
      fclose(f);
      return 0;
    }
    if (errno == EACCES || errno == EPERM)
      denied = 1;
  }
  return denied ? KASLD_EXIT_NOPERM : KASLD_EXIT_UNAVAILABLE;
}

int main(void) {
  struct utsname uts;
  kasld_info("sizing the kernel image from the boot artefacts for this "
             "release ...");
  if (kasld_uname(&uts) != 0)
    return 0;
  const char *rel = uts.release;

  /* One ordered search for a statement about the footprint (_end - _text,
   * includes BSS), taking the first artefact that makes one. Which END each
   * source bounds is the source's own property and it reports it: the exact
   * footprint feeds both facts, a span resting on a partial symbol pair feeds
   * the ceiling's lower bound alone, and x86's init_size -- at or above the
   * footprint, never below -- feeds the image-base floor's upper bound alone.
   *
   * Offering a figure as the end it does not prove is worse than emitting
   * nothing: the evidence layer takes the MAX over lower bounds and the MIN
   * over upper bounds, so a wrong-sided figure displaces the exact facts
   * instead of widening the window. */
  enum kasld_image_bound b = KIMG_BOUND_NONE;
  unsigned long size = kasld_image_size_from_header(rel, &b);
  if (!size)
    size = kasld_image_size_from_bzimage(rel, &b);
  if (!size)
    size = kasld_image_size_from_elf(rel, &b);
  if (!size)
    size = kasld_image_size_from_sysmap(rel, &b);
  if (!size)
    size = zboot_exact_size(rel, &b);
  if (!size)
    size = kasld_image_size_from_zimage(rel, &b);

  int have_min = 0;
  if (size && (b == KIMG_BOUND_EXACT || b == KIMG_BOUND_LOWER)) {
    kasld_emit_scalar(SF_IMAGE_SIZE_MIN, size, CONF_PARSED);
    have_min = 1;
  }
  if (size && (b == KIMG_BOUND_EXACT || b == KIMG_BOUND_UPPER))
    kasld_emit_scalar(SF_IMAGE_SIZE_MAX, size, CONF_PARSED);

  /* A source that bounded only the floor side leaves the ceiling's lower bound
   * unstated, so the lower-bound readers are still consulted for it -- an x86
   * bzImage gets its upper bound from init_size and its lower bound from the
   * compressed file's own length. Prefer a whole-file gzip stream's ISIZE
   * (decompressed, tighter) over the raw vmlinuz size (compressed, looser);
   * both exclude BSS or under-count, so they bound the footprint from below but
   * never above. A zboot container whose payload could not be decompressed
   * arrives here too and takes the file size: its own length word is read only
   * where the payload's declared size can corroborate it. */
  if (!have_min) {
    enum kasld_image_bound lb_b = KIMG_BOUND_NONE;
    unsigned long lb = kasld_image_size_from_gzip(rel, &lb_b);
    if (!lb)
      lb = kasld_image_size_from_vmlinuz(rel, &lb_b);
    if (!lb)
      lb = kasld_image_size_from_stat(rel, &lb_b);
    if (lb && lb_b == KIMG_BOUND_LOWER) {
      kasld_emit_scalar(SF_IMAGE_SIZE_MIN, lb, CONF_PARSED);
      have_min = 1;
    }
  }

  if (size || have_min)
    return 0;

  /* Nothing answered. The artefact being present but unreadable is this host's
   * hardening; its being absent is how the host is laid out. Both arrive as the
   * same failed open, so classify rather than fall silent -- a run that emits
   * no size can then name the vantage. A readable artefact that no reader could
   * parse is neither, and stays 0. */
  return boot_artefact_class(rel);
}
