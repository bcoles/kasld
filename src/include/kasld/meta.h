// This file is part of KASLD - https://github.com/bcoles/kasld
//
// What a component declares about itself.
//
// A component embeds its own description in its binary, as ELF sections that
// nothing executes: `.kasld_meta` carries machine-readable `key:value` lines,
// `.kasld_explain` carries the technique's prose. Reading a section costs an
// open and a seek rather than a process, which is what lets every component be
// classified and scheduled before any of them runs, and lets the renderers
// report what a component declared whether or not it produced a result.
//
// Reading a section is not running the component, and this file keeps that
// line: it returns the bytes and the pairs they split into. What a key means --
// which phase a component belongs to, which sysctl gates it, whether it
// discloses -- is decided by the code that asked.
//
// Standalone by construction: an entry is a pair of pointers into the caller's
// own copy of the section, so nothing here needs the rest of the tree.

#ifndef KASLD_META_H
#define KASLD_META_H

/* Cap on `key:value` lines kept from one component's .kasld_meta section. The
 * busiest component in the tree declares 8. Overflow is reported through the
 * discard ledger rather than dropped quietly: a lost `phase:` reassigns a
 * component's scheduling and a lost mitigation key changes the hardening
 * report, so a component that outgrew this must not do so in silence. */
#define META_MAX_ENTRIES 16

/* One `key:value` pair, as pointers INTO the raw section the component's log
 * slot owns — not copies. parse_meta() terminates each field in place, so the
 * whole table costs two pointers per entry over the section itself (under 150
 * bytes for every component in the tree) instead of a fixed key and value
 * buffer per slot. Both stay valid for as long as that raw section does, which
 * is the lifetime of the log slot holding it, so a pointer handed out by
 * meta_get() is good for the run. */
struct meta_entry {
  const char *key;
  const char *value;
};

struct component_meta {
  struct meta_entry entries[META_MAX_ENTRIES];
  int num_entries;
};

/* Read a named section out of a component ELF binary without executing it.
 * Handles ELF32 and ELF64. Returns a malloc'd NUL-terminated string the caller
 * frees, or NULL when the section is absent, the file cannot be read, or the
 * section is empty or above the 8 KiB cap applied to every section read here.
 * Those outcomes are not distinguished: a component whose section outgrew the
 * cap presents exactly as one that declared nothing. */
char *extract_elf_section(const char *path, const char *section_name);

/* Split a raw .kasld_meta section into `key:value` entries, IN PLACE: `raw` is
 * modified, and must stay alive and unmoved for as long as any entry is read.
 * Returns the number of lines that did not fit, so the caller can report the
 * loss rather than let a component's metadata be truncated in silence. */
int parse_meta(char *raw, struct component_meta *m);

/* First value declared for `key`, or NULL. */
const char *meta_get(const struct component_meta *m, const char *key);

/* Every value declared for `key` — a key may repeat, as `sysctl` and `config`
 * do. Writes up to `max_values` of them and returns how many were written. */
int meta_get_all(const struct component_meta *m, const char *key,
                 const char **values, int max_values);

#endif /* KASLD_META_H */
