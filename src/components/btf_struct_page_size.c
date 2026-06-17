// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Emit SF_STRUCT_PAGE_BYTES: the exact sizeof(struct page), parsed from the
// kernel's own BTF type information at /sys/kernel/btf/vmlinux.
//
// vmemmap holds one struct page per physical page frame, so vmemmap_size =
// max_pfn * sizeof(struct page). The s390/x86_64/arm64 vmemmap-sizing rules
// otherwise assume the common 64-byte struct page; this fact lets them use the
// exact value (CONFIG_WANT_PAGE_VIRTUAL and some debug/extension configs
// enlarge it), tightening their bounds and — on arm64 — hardening the VA_BITS
// discrimination threshold against misclassification.
//
// BTF layout: a fixed header, a type section (btf_type records, each optionally
// followed by kind-specific trailing data), and a string section. We scan for a
// BTF_KIND_STRUCT named "page" with a non-zero size. Native-endian only: the
// running kernel's BTF matches host byte order, so a magic mismatch (a blob in
// the opposite byte order) is treated as unavailable rather than parsed.
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kasld/cli.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

KASLD_EXPLAIN("Parses sizeof(struct page) from the kernel's BTF type info "
              "(/sys/kernel/btf/vmlinux) and emits it as a scalar fact; the "
              "vmemmap-sizing rules consume it, else assume 64 bytes.");
KASLD_META("method:parsed\n"
           "phase:inference\n");

#define BTF_MAGIC 0xeB9F
#define BTF_KIND_STRUCT 4

/* btf_type trailing bytes by kind (records that follow the 12-byte header).
 * Kinds with no trailing data return 0. */
static size_t btf_trailing(uint32_t kind, uint32_t vlen) {
  switch (kind) {
  case 1: /* INT        */
    return 4;
  case 3: /* ARRAY      */
    return 12;
  case 4: /* STRUCT     */
  case 5: /* UNION      */
    return (size_t)vlen * 12;
  case 6: /* ENUM       */
    return (size_t)vlen * 8;
  case 13: /* FUNC_PROTO */
    return (size_t)vlen * 8;
  case 14: /* VAR        */
    return 4;
  case 15: /* DATASEC    */
    return (size_t)vlen * 12;
  case 17: /* DECL_TAG   */
    return 4;
  case 19: /* ENUM64     */
    return (size_t)vlen * 12;
  default: /* PTR/FWD/CONST/TYPEDEF/FUNC/FLOAT/TYPE_TAG/... */
    return 0;
  }
}

/* Scan a BTF blob for `struct <name>` and return its size in bytes, or 0. */
static unsigned long btf_struct_size(const unsigned char *buf, size_t len,
                                     const char *name) {
  uint16_t magic;
  uint32_t hdr_len, type_off, type_len, str_off, str_len;
  if (len < 24)
    return 0;
  memcpy(&magic, buf, 2);
  if (magic != BTF_MAGIC)
    return 0; /* not native-endian BTF */
  memcpy(&hdr_len, buf + 4, 4);
  memcpy(&type_off, buf + 8, 4);
  memcpy(&type_len, buf + 12, 4);
  memcpy(&str_off, buf + 16, 4);
  memcpy(&str_len, buf + 20, 4);

  /* Sections are relative to the end of the header; bounds-check both. */
  if ((size_t)hdr_len > len)
    return 0;
  size_t tstart = (size_t)hdr_len + type_off;
  size_t sstart = (size_t)hdr_len + str_off;
  if (tstart > len || (size_t)type_len > len - tstart)
    return 0;
  if (sstart > len || (size_t)str_len > len - sstart)
    return 0;

  const unsigned char *types = buf + tstart;
  const char *strs = (const char *)buf + sstart;
  size_t off = 0;
  while (off + 12 <= type_len) {
    uint32_t name_off, info, size_or_type;
    memcpy(&name_off, types + off, 4);
    memcpy(&info, types + off + 4, 4);
    memcpy(&size_or_type, types + off + 8, 4);
    uint32_t kind = (info >> 24) & 0x1f;
    uint32_t vlen = info & 0xffff;
    size_t trail = btf_trailing(kind, vlen);

    if (kind == BTF_KIND_STRUCT && size_or_type != 0 && name_off < str_len) {
      const char *tn = strs + name_off;
      if (memchr(tn, '\0', str_len - name_off) && strcmp(tn, name) == 0)
        return size_or_type;
    }

    /* Advance past this record; stop on overrun (malformed/truncated). */
    if (trail > type_len - off - 12)
      break;
    off += 12 + trail;
  }
  return 0;
}

/* Read an entire (size-unreliable, e.g. sysfs) file into a malloc'd buffer. */
static unsigned char *read_all(FILE *f, size_t *out_len) {
  size_t cap = 1u << 20, len = 0;
  unsigned char *buf = malloc(cap);
  if (!buf)
    return NULL;
  for (;;) {
    if (len == cap) {
      if (cap >= (64u << 20))
        break; /* sanity cap — BTF is a few MB */
      unsigned char *nb = realloc(buf, cap * 2);
      if (!nb) {
        free(buf);
        return NULL;
      }
      buf = nb;
      cap *= 2;
    }
    size_t r = fread(buf + len, 1, cap - len, f);
    len += r;
    if (r == 0)
      break;
  }
  *out_len = len;
  return buf;
}

int main(int argc, char **argv) {
  kasld_cli(argc, argv);

  const char *path = "/sys/kernel/btf/vmlinux";
  FILE *f = kasld_fopen(path, "rb");
  if (!f) {
    kasld_err("%s unavailable (no CONFIG_DEBUG_INFO_BTF?)", path);
    return (errno == EACCES || errno == EPERM) ? KASLD_EXIT_NOPERM
                                               : KASLD_EXIT_UNAVAILABLE;
  }
  size_t len = 0;
  unsigned char *buf = read_all(f, &len);
  fclose(f);
  if (!buf)
    return KASLD_EXIT_UNAVAILABLE;

  unsigned long sz = btf_struct_size(buf, len, "page");
  free(buf);

  if (!sz) {
    kasld_err("struct page not found in BTF");
    return 0;
  }
  kasld_found("sizeof(struct page) = %lu bytes", sz);
  kasld_emit_scalar(SF_STRUCT_PAGE_BYTES, sz, CONF_PARSED);
  return 0;
}
