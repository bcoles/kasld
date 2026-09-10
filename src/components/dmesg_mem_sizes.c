// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Bound the kernel image size from the boot-time "Memory:" summary.
//
// mem_init_print_info() prints one line as the allocator comes up, naming the
// image's sections in KiB:
//
//   Memory: 956920K/1048576K available (11132K kernel code, 1380K rwdata,
//   4916K rodata, 4096K init, 379K bss, 58888K reserved, 32768K cma-reserved)
//
// It lives in mm/, not in arch code, so every architecture prints it, and the
// format has been byte-identical for the whole range of kernels in scope.
//
// LOWER BOUND — the sum of the five section figures. They are disjoint: the
// printer subtracts each nested region from its container before printing (init
// text out of kernel code, rodata out of both kernel code and rwdata), so
// nothing is counted twice. Together they span _stext.._end and miss only the
// _text.._stext head gap and whatever padding the linker inserted between
// sections, which is why the sum bounds the footprint from below rather than
// stating it. All five are required: a missing figure makes the sum a partial
// total, which bounds nothing.
//
// UPPER BOUND — the "reserved" figure, which is every present page the
// allocator did not receive. The image is reserved before the allocator starts
// and its init sections are not freed until much later in boot, long after this
// line is printed, so the whole image is inside that figure at the moment it is
// taken. Loose, since reserved also covers firmware, the initrd and any
// crashkernel, but it is an upper bound and the engine has few.
//
// Fields are matched by NAME, not by position: the parenthesised list is split
// on ", " and each token read as "<value>K <label>". A reordering upstream then
// costs nothing, and "reserved" cannot be confused with "cma-reserved" because
// the label must match in full.
//
// Leak primitive:
//   Data leaked:      kernel image section sizes (not an address)
//   Kernel subsystem: mm — mem_init_print_info()
//   Data structure:   the boot "Memory:" summary line
//   Address type:     none — sizes only
//   Method:           parsed (dmesg line)
//   Status:           informational; gated by dmesg_restrict
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/dmesg.h"
#include "include/kasld/api.h"
#include "include/kasld/cli.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

KASLD_EXPLAIN(
    "Parses the boot-time 'Memory: ... (NK kernel code, NK rwdata, ...)' line "
    "printed by mem_init_print_info() on every architecture. The section "
    "figures sum to a lower bound on the kernel image size and the 'reserved' "
    "figure is an upper bound, so one line bounds the footprint from both "
    "sides. Sizes only — the line discloses no address. Requires readable "
    "kernel logs (dmesg_restrict=0 or CAP_SYSLOG).");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "discloses:facts\n"
           "source:files\n"
           "sysctl:dmesg_restrict>=1\n");

/* A parsed "Memory:" line. `seen` is a bitmask over the five section fields, so
 * a partial line is rejected rather than summed. */
#define F_CODE (1u << 0)
#define F_RWDATA (1u << 1)
#define F_RODATA (1u << 2)
#define F_INIT (1u << 3)
#define F_BSS (1u << 4)
#define F_ALL_SECTIONS (F_CODE | F_RWDATA | F_RODATA | F_INIT | F_BSS)

struct mem_line {
  unsigned long sections_kib; /* running sum of the five section figures */
  unsigned long reserved_kib;
  unsigned seen;
  int have_reserved;
};

/* Smallest sum worth believing: a real kernel's sections run to megabytes, so
 * anything under this is a misparse rather than a very small kernel. */
#define MEM_SIZES_MIN_KIB 512UL

static const struct {
  const char *label;
  unsigned bit;
} k_fields[] = {
    {"kernel code", F_CODE}, {"rwdata", F_RWDATA}, {"rodata", F_RODATA},
    {"init", F_INIT},        {"bss", F_BSS},
};

/* One ", "-separated token, expected as "<value>K <label>". Unknown labels are
 * ignored: the line carries figures this component does not use (cma-reserved,
 * highmem) and may carry more later. */
static void take_token(struct mem_line *m, const char *tok) {
  char *end;
  unsigned long v;
  size_t i;

  while (*tok == ' ')
    tok++;
  v = strtoul(tok, &end, 10);
  if (end == tok || *end != 'K')
    return;
  end++;
  while (*end == ' ')
    end++;

  for (i = 0; i < sizeof(k_fields) / sizeof(k_fields[0]); i++) {
    if (strcmp(end, k_fields[i].label) != 0)
      continue;
    /* A repeated label would double the sum; take the first only. */
    if (m->seen & k_fields[i].bit)
      return;
    m->seen |= k_fields[i].bit;
    m->sections_kib += v;
    return;
  }
  if (strcmp(end, "reserved") == 0 && !m->have_reserved) {
    m->reserved_kib = v;
    m->have_reserved = 1;
  }
}

static int on_memory_line(const char *line, void *ctx) {
  struct mem_line *m = ctx;
  const char *open = strchr(line, '(');
  char buf[512];
  char *tok, *save;
  size_t n;

  if (!open || m->seen == F_ALL_SECTIONS)
    return 0;
  open++;
  n = strcspn(open, ")");
  if (n >= sizeof(buf))
    return 0;
  memcpy(buf, open, n);
  buf[n] = '\0';

  for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save))
    take_token(m, tok);
  return 0;
}

int main(int argc, char **argv) {
  struct mem_line m;
  unsigned long lo_bytes = 0, hi_bytes = 0;

  kasld_cli(argc, argv);
  memset(&m, 0, sizeof(m));

  kasld_info("searching the kernel log for the boot 'Memory:' summary ...");
  if (dmesg_search("Memory: ", on_memory_line, &m) < 0)
    return KASLD_EXIT_NOPERM;

  if (m.seen != F_ALL_SECTIONS && !m.have_reserved) {
    kasld_err("no 'Memory:' summary in the kernel log");
    return 0;
  }

  /* KiB to bytes, refusing a product that would wrap this build's word. */
  if (m.seen == F_ALL_SECTIONS && m.sections_kib >= MEM_SIZES_MIN_KIB &&
      m.sections_kib <= ULONG_MAX / 1024UL)
    lo_bytes = m.sections_kib * 1024UL;
  if (m.have_reserved && m.reserved_kib <= ULONG_MAX / 1024UL)
    hi_bytes = m.reserved_kib * 1024UL;

  /* Every page the image occupies is reserved at the moment this line is
   * printed, so the upper bound cannot fall below the lower one. If it does,
   * the line was not what it was taken for and neither figure is trustworthy —
   * a pair of claims that contradict each other is worse than none. */
  if (lo_bytes && hi_bytes && hi_bytes < lo_bytes) {
    kasld_err("'Memory:' reserved figure is below the section total; "
              "not emitting either");
    return 0;
  }

  if (lo_bytes)
    kasld_emit_scalar(SF_IMAGE_SIZE_MIN, lo_bytes, CONF_PARSED);
  if (hi_bytes)
    kasld_emit_scalar(SF_IMAGE_SIZE_MAX, hi_bytes, CONF_PARSED);
  if (!lo_bytes && !hi_bytes)
    kasld_err("'Memory:' summary carried no usable figure");
  return 0;
}
