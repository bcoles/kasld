// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Emit the kernel image size, read from the running kernel's /boot artefacts.
// The footprint is a two-ended interval; what each source proves decides which
// fact(s) it emits:
//   exact source (Image header / x86 bzImage / ELF / System.map) — the exact
//     in-memory footprint (_end - _text); sound in both directions, so emits
//     BOTH SF_IMAGE_SIZE_MIN (ceiling) and SF_IMAGE_SIZE_MAX (floor).
//   lower-bound source (gzip ISIZE / compressed vmlinuz size) — below the
//     footprint (excludes BSS), so emits SF_IMAGE_SIZE_MIN only.
// x86 also supplies both facts from boot_params (boot_params_facts.c).
//
// Every reader here targets the same artefact family, so the component answers
// for one source and can say which of "denied" and "absent" applies when none
// of the formats matched.
// ---
// <bcoles@gmail.com>
#include "include/kasld/api.h"
#include "include/kasld/kernel_image.h"

KASLD_EXPLAIN(
    "Reads the kernel image size from /boot (EFI/PE Image header, x86 "
    "bzImage setup header, ELF vmlinux, System.map, or a gzip ISIZE "
    "trailer) and emits it as a scalar fact bounding the KASLR window. "
    "No privileges.");
KASLD_META("method:parsed\n"
           "phase:inference\n"
           "discloses:facts\n"
           "source:files\n");

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
  if (kasld_uname(&uts) != 0)
    return 0;
  const char *rel = uts.release;

  /* Exact footprint (_end - _text, includes BSS) from whichever artefact
   * exposes it. Exact → sound in both directions → emit MIN and MAX. */
  unsigned long exact = kasld_image_size_from_header(rel);
  if (!exact)
    exact = kasld_image_size_from_bzimage(rel);
  if (!exact)
    exact = kasld_image_size_from_elf(rel);
  if (!exact)
    exact = kasld_image_size_from_sysmap(rel);
  if (exact) {
    /* Exact footprint: a sound bound in BOTH directions, so it feeds the
     * ceiling (MIN) and the floor (MAX). */
    kasld_emit_scalar(SF_IMAGE_SIZE_MIN, exact, CONF_PARSED);
    kasld_emit_scalar(SF_IMAGE_SIZE_MAX, exact, CONF_PARSED);
    return 0;
  }

  /* No exact source: fall back to a lower bound (MIN, ceiling side) only.
   * Prefer a gzip stream's ISIZE (decompressed size, tighter) over the raw
   * vmlinuz file size (compressed, looser); both exclude BSS / under-count, so
   * they bound the footprint from below but never above (no MAX). */
  unsigned long lb = kasld_image_size_from_gzip(rel);
  if (!lb)
    lb = kasld_image_size_from_vmlinuz(rel);
  if (!lb)
    lb = kasld_image_size_from_stat(rel);
  if (lb) {
    kasld_emit_scalar(SF_IMAGE_SIZE_MIN, lb, CONF_PARSED);
    return 0;
  }

  /* Nothing answered. The artefact being present but unreadable is this host's
   * hardening; its being absent is how the host is laid out. Both arrive as the
   * same failed open, so classify rather than fall silent -- a run that emits
   * no size can then name the vantage. A readable artefact that no reader could
   * parse is neither, and stays 0. */
  return boot_artefact_class(rel);
}
