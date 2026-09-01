// This file is part of KASLD - https://github.com/bcoles/kasld
//
// What a component declares about itself: the reader for the ELF sections a
// component embeds in its own binary.
//
// Two halves, in the order they run. extract_elf_section() walks a component
// binary's section headers and returns one section's bytes, without executing
// it. parse_meta() splits a `.kasld_meta` section into the `key:value` pairs
// the component declared, in place, and meta_get()/meta_get_all() read them
// back.
//
// A leaf: it takes no lock, holds no state, and reads only the path it is
// handed, so a component's declaration is available to whoever asks for it
// wherever they ask -- before the component runs, while it runs, or after it
// has produced nothing at all.
//
// ---
// <bcoles@gmail.com>

#include "include/kasld/meta.h"

#include <elf.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *extract_elf_section(const char *path, const char *section_name) {
  /* Raw fopen(), NOT kasld_fopen(): `path` is the component's own binary, which
   * the orchestrator executes from its real location (execl below). It is a
   * runtime artifact, not a captured fact, so it must be read from the live
   * tree regardless of KASLD_SYSROOT — see sysroot.h on runtime-primitive
   * escapes. Under replay this would otherwise resolve into the captured tree
   * (where the binary does not exist), returning empty meta and silently
   * disabling every meta-driven hardening section. */
  FILE *f = fopen(path, "rb");
  if (!f)
    return NULL;

  unsigned char e_ident[EI_NIDENT];
  if (fread(e_ident, 1, EI_NIDENT, f) != EI_NIDENT)
    goto fail;
  if (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
      e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3)
    goto fail;

  int is64 = (e_ident[EI_CLASS] == ELFCLASS64);

  /* Read the ELF header fields used below: e_shoff, e_shentsize, e_shnum,
   * e_shstrndx. Seek past e_ident, already consumed. */
  uint64_t e_shoff;
  uint16_t e_shentsize, e_shnum, e_shstrndx;

  if (is64) {
    Elf64_Ehdr hdr;
    rewind(f);
    if (fread(&hdr, 1, sizeof(hdr), f) != sizeof(hdr))
      goto fail;
    e_shoff = hdr.e_shoff;
    e_shentsize = hdr.e_shentsize;
    e_shnum = hdr.e_shnum;
    e_shstrndx = hdr.e_shstrndx;
  } else {
    Elf32_Ehdr hdr;
    rewind(f);
    if (fread(&hdr, 1, sizeof(hdr), f) != sizeof(hdr))
      goto fail;
    e_shoff = hdr.e_shoff;
    e_shentsize = hdr.e_shentsize;
    e_shnum = hdr.e_shnum;
    e_shstrndx = hdr.e_shstrndx;
  }

  if (!e_shoff || !e_shnum || e_shstrndx >= e_shnum)
    goto fail;

  /* Read the section header string table (.shstrtab) to resolve names */
  uint64_t shstrtab_off, shstrtab_size;
  uint64_t shstrtab_hdr_off = e_shoff + (uint64_t)e_shstrndx * e_shentsize;
  if (is64) {
    Elf64_Shdr shdr;
    if (shstrtab_hdr_off > LONG_MAX ||
        fseek(f, (long)shstrtab_hdr_off, SEEK_SET))
      goto fail;
    if (fread(&shdr, 1, sizeof(shdr), f) != sizeof(shdr))
      goto fail;
    shstrtab_off = shdr.sh_offset;
    shstrtab_size = shdr.sh_size;
  } else {
    Elf32_Shdr shdr;
    if (shstrtab_hdr_off > LONG_MAX ||
        fseek(f, (long)shstrtab_hdr_off, SEEK_SET))
      goto fail;
    if (fread(&shdr, 1, sizeof(shdr), f) != sizeof(shdr))
      goto fail;
    shstrtab_off = shdr.sh_offset;
    shstrtab_size = shdr.sh_size;
  }

  if (shstrtab_size > 1024 * 1024) /* sanity limit: 1 MiB */
    goto fail;

  if (shstrtab_off > LONG_MAX)
    goto fail;

  char *strtab = malloc((size_t)shstrtab_size + 1);
  if (!strtab)
    goto fail;
  if (fseek(f, (long)shstrtab_off, SEEK_SET) ||
      fread(strtab, 1, (size_t)shstrtab_size, f) != (size_t)shstrtab_size) {
    free(strtab);
    goto fail;
  }
  strtab[shstrtab_size] = '\0';

  /* Scan section headers for the target section */
  char *result = NULL;

  for (uint16_t i = 0; i < e_shnum; i++) {
    uint64_t sh_offset, sh_size;
    uint32_t sh_name;

    uint64_t shdr_off = e_shoff + (uint64_t)i * e_shentsize;
    if (shdr_off > LONG_MAX || fseek(f, (long)shdr_off, SEEK_SET))
      break;

    if (is64) {
      Elf64_Shdr shdr;
      if (fread(&shdr, 1, sizeof(shdr), f) != sizeof(shdr))
        break;
      sh_name = shdr.sh_name;
      sh_offset = shdr.sh_offset;
      sh_size = shdr.sh_size;
    } else {
      Elf32_Shdr shdr;
      if (fread(&shdr, 1, sizeof(shdr), f) != sizeof(shdr))
        break;
      sh_name = shdr.sh_name;
      sh_offset = shdr.sh_offset;
      sh_size = shdr.sh_size;
    }

    if (sh_name >= shstrtab_size)
      continue;
    if (strcmp(strtab + sh_name, section_name) != 0)
      continue;

    /* Found it — read the section contents */
    if (sh_size == 0 || sh_size > 8192) /* sanity limit */
      break;
    if (sh_offset > LONG_MAX)
      break;
    result = malloc((size_t)sh_size + 1);
    if (!result)
      break;
    if (fseek(f, (long)sh_offset, SEEK_SET) ||
        fread(result, 1, (size_t)sh_size, f) != (size_t)sh_size) {
      free(result);
      result = NULL;
      break;
    }
    result[sh_size] = '\0';
    break;
  }

  free(strtab);
  fclose(f);
  return result;

fail:
  fclose(f);
  return NULL;
}

/* Split a component's .kasld_meta section into key/value pairs, IN PLACE.
 *
 * `raw` is the caller's own heap copy of the section and is modified: each key
 * and value is terminated where it ends, and the entries point into it. The
 * caller therefore keeps `raw` alive for as long as it reads the entries — the
 * log slot owns it for the run. Parsing in place rather than into fixed buffers
 * is what keeps a component's metadata costing its own ~90 bytes instead of a
 * key and value buffer per possible entry.
 *
 * A line without a colon, or with nothing before it, is skipped rather than
 * ending the parse: the section is generated by KASLD_META and a stray blank
 * or comment line should not truncate the keys after it. Returns the number of
 * lines that did not fit, so the caller can report the loss. */
int parse_meta(char *raw, struct component_meta *m) {
  m->num_entries = 0;
  if (!raw)
    return 0;

  int dropped = 0;
  char *p = raw;
  while (*p) {
    while (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t')
      p++;
    if (!*p)
      break;

    char *eol = strchr(p, '\n');
    char *next = eol ? eol + 1 : NULL;
    if (!eol)
      eol = p + strlen(p);

    char *colon = NULL;
    for (char *c = p; c < eol; c++)
      if (*c == ':') {
        colon = c;
        break;
      }

    if (colon && colon > p) {
      if (m->num_entries >= META_MAX_ENTRIES) {
        dropped++;
      } else {
        char *vstart = colon + 1;
        char *vend = eol;
        /* Terminate the key where the colon was, then trim the value's
         * surrounding whitespace by moving its start and terminating its end.
         * Both writes land inside `raw`, on bytes the pair no longer needs. */
        *colon = '\0';
        while (vstart < vend && (*vstart == ' ' || *vstart == '\t'))
          vstart++;
        while (vend > vstart &&
               (vend[-1] == ' ' || vend[-1] == '\t' || vend[-1] == '\r'))
          vend--;
        *vend = '\0';

        struct meta_entry *e = &m->entries[m->num_entries++];
        e->key = p;
        e->value = vstart;
      }
    }

    if (!next)
      break;
    p = next;
  }
  return dropped;
}

const char *meta_get(const struct component_meta *m, const char *key) {
  for (int i = 0; i < m->num_entries; i++) {
    if (strcmp(m->entries[i].key, key) == 0)
      return m->entries[i].value;
  }
  return NULL;
}

int meta_get_all(const struct component_meta *m, const char *key,
                 const char **values, int max_values) {
  int n = 0;
  for (int i = 0; i < m->num_entries; i++) {
    if (strcmp(m->entries[i].key, key) == 0 && n < max_values)
      values[n++] = m->entries[i].value;
  }
  return n;
}
