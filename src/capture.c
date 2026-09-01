// This file is part of KASLD - https://github.com/bcoles/kasld
//
// The captured evidence store: what components said, recorded verbatim.
//
// A component is a separate process that prints tagged lines on a pipe. This
// file reads one line at a time, validates it, and files it into the store its
// record kind belongs to -- `V`/`P` to results[], `S` to scalar_facts[], `C` to
// constraint_facts[]. The wire is the whole interface: nothing structured
// crosses from a component, which is what lets one be any executable in any
// language and lets a fuzzer drive these parsers with raw bytes.
//
// It records what a component said. It does not interpret what the value means:
// deciding that a KERNEL_TEXT base is _stext and normalising it to the image
// base needs the architecture's declared head gap, and that is analysis. The
// only judgement made here is whether a record is admissible at all --
// validated against the STATIC region table, never against the resolved runtime
// layout, which is not known this early and is checked later by
// result_in_bounds().
//
// A rejected record is reported through the discard ledger rather than dropped,
// because a component that ran and produced nothing and one whose output was
// refused are indistinguishable from the outside.
// ---
// <bcoles@gmail.com>

/* strtok_r and clock_gettime are POSIX, not C99; the wire parsers use the
 * reentrant tokenizer because component lines are parsed on worker threads. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "include/kasld/internal.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The three stores. Declared in kasld/capture.h; the engine bridge copies each
 * into the observation kind it corresponds to, and the renderers read them
 * directly to list the evidence a run gathered. */

struct result results[MAX_RESULTS];
int num_results;

/* Copied to OBS_SCALAR observations by the engine bridge; summarize_kaslr_state
 * and the renderers also read them directly. */
struct scalar_fact_record scalar_facts[MAX_SCALAR_FACTS];
int num_scalar_facts;

/* Copied to OBS_CONSTRAINT observations by the engine bridge, which a
 * passthrough rule folds into the meet as the named C_* constraint. */
struct constraint_fact_record constraint_facts[MAX_CONSTRAINT_FACTS];
int num_constraint_facts;

/* Look up region enum by wire name. Linear scan over region_info[] — a table
 * of a few dozen, negligible cost. Returns REGION_UNKNOWN on miss. */
static enum kasld_region region_from_wire(const char *s) {
  for (int i = 1; i < REGION__COUNT; i++) {
    if (region_info[i].wire_name && strcmp(region_info[i].wire_name, s) == 0)
      return (enum kasld_region)i;
  }
  return REGION_UNKNOWN;
}

static enum kasld_position pos_from_wire(const char *s) {
  if (strcmp(s, "base") == 0)
    return POS_BASE;
  if (strcmp(s, "top") == 0)
    return POS_TOP;
  if (strcmp(s, "interior") == 0)
    return POS_INTERIOR;
  if (strcmp(s, "extent") == 0)
    return POS_EXTENT;
  if (strcmp(s, "unknown") == 0)
    return POS_UNKNOWN;
  /* Unrecognized input also returns POS_UNKNOWN. The caller disambiguates
   * via `strcmp(val, "unknown") != 0` immediately after this call —
   * that guard must be kept co-located with any new call site. */
  return POS_UNKNOWN;
}

static enum kasld_confidence conf_from_wire(const char *s) {
  if (strcmp(s, "parsed") == 0)
    return CONF_PARSED;
  if (strcmp(s, "derived") == 0)
    return CONF_DERIVED;
  if (strcmp(s, "inferred") == 0)
    return CONF_INFERRED;
  if (strcmp(s, "heuristic") == 0)
    return CONF_HEURISTIC;
  if (strcmp(s, "timing") == 0)
    return CONF_TIMING;
  if (strcmp(s, "brute") == 0)
    return CONF_BRUTE;
  return CONF_UNKNOWN;
}

/* Map a method: meta value to its bit in struct result.method_set (0 if the
 * value is empty or unrecognized). Mirrors the closed set in enum kasld_method.
 */
static uint16_t method_bit(const char *s) {
  int m = -1;
  if (!s || !*s)
    return 0;
  if (strcmp(s, "parsed") == 0)
    m = KM_PARSED;
  else if (strcmp(s, "derived") == 0)
    m = KM_DERIVED;
  else if (strcmp(s, "inferred") == 0)
    m = KM_INFERRED;
  else if (strcmp(s, "heuristic") == 0)
    m = KM_HEURISTIC;
  else if (strcmp(s, "timing") == 0)
    m = KM_TIMING;
  else if (strcmp(s, "brute") == 0)
    m = KM_BRUTE;
  else if (strcmp(s, "detection") == 0)
    m = KM_DETECTION;
  return m < 0 ? 0u : (uint16_t)(1u << m);
}

/* Power-of-two test, allowing v=0 to mean "no constraint" but the caller
 * gates on v != 0 separately. */
static int is_pow2(unsigned long v) { return v && !(v & (v - 1)); }

static enum kasld_addr_type type_from_wire(char c) {
  switch (c) {
  case 'P':
    return KASLD_TYPE_PHYS;
  case 'V':
    return KASLD_TYPE_VIRT;
  default:
    return KASLD_TYPE_UNKNOWN;
  }
}

static int parse_hex(const char *s, unsigned long *out) {
  if (s[0] != '0' || (s[1] != 'x' && s[1] != 'X'))
    return 0;
  char *end;
  errno = 0;
  unsigned long v = strtoul(s, &end, 16);
  if (errno || *end != '\0')
    return 0;
  *out = v;
  return 1;
}

/* Is a free-text wire field made only of characters the protocol admits?
 *
 * `name`, `gate` and `msg` are the three fields a component fills with text of
 * its own choosing, and all three reach the operator's terminal — `gate` and
 * `msg` through the hardening report. A control byte among them is an escape
 * sequence: cursor movement and erase-line can redraw a finding as its
 * opposite in the very report meant to expose it.
 *
 * The admissible set is per field rather than global. `name` and `gate` are
 * identifiers, and every source that fills them is ASCII by its own
 * specification — kernel symbols are C identifiers, device-tree node names are
 * checked against a fixed set by dtc, ACPI signatures and OEM ids are ASCII by
 * the ACPI spec, a PCI BDF is hex with `:` and `.`. `msg` is quoted prose and
 * so admits the space as well.
 *
 * Bytes at or above 0x80 are excluded with the controls. Nothing that fills
 * these fields produces one, and admitting them would admit both the C1
 * controls — which a terminal in an 8-bit locale acts on, no ESC byte needed —
 * and confusable characters, neither of which a line-oriented ASCII protocol
 * has a reason to carry. Note the range cannot be split byte-wise: 0x80..0x9F
 * is also the UTF-8 continuation range, so banning C1 alone would corrupt any
 * multi-byte sequence, and permitting it would leave the controls intact. */
int wire_text_ok(const char *s, int allow_space) {
  for (; *s; s++) {
    unsigned char c = (unsigned char)*s;
    if (c >= 0x21 && c <= 0x7e)
      continue;
    if (allow_space && c == 0x20)
      continue;
    return 0;
  }
  return 1;
}

/* Split a "region[:name]" wire token into a resolved region + name_buf (sized
 * NAME_LEN). The split is on the FIRST `:` only — names may contain subsequent
 * colons (e.g. PCI BDF "0000:00:14.0"); region wire names are short
 * identifiers without ':' (the longest, "virt_page_offset" and
 * "efi_loader_image", are 16). Returns REGION_UNKNOWN on a malformed,
 * over-length, or unrecognized token. */
static enum kasld_region parse_region_field(const char *region_field,
                                            char *name_buf) {
  char region_str[32];
  name_buf[0] = '\0';
  const char *colon = strchr(region_field, ':');
  if (colon) {
    size_t rlen = (size_t)(colon - region_field);
    if (rlen >= sizeof(region_str)) /* over-length region = malformed line */
      return REGION_UNKNOWN;
    memcpy(region_str, region_field, rlen);
    region_str[rlen] = '\0';

    const char *name_src = colon + 1;
    size_t nlen = strlen(name_src);
    if (nlen >
        NAME_LEN - 1) /* over-length name rejects (no silent truncation) */
      return REGION_UNKNOWN;
    memcpy(name_buf, name_src, nlen);
    name_buf[nlen] = '\0';
    if (!wire_text_ok(name_buf, 0)) { /* control bytes reach the terminal */
      name_buf[0] = '\0';
      return REGION_UNKNOWN;
    }
  } else {
    size_t rlen = strlen(region_field);
    if (rlen >= sizeof(region_str))
      return REGION_UNKNOWN;
    memcpy(region_str, region_field, rlen);
    region_str[rlen] = '\0';
  }
  return region_from_wire(region_str);
}

/* Tokenise the key=value tail (everything after "<type> <region>[:<name>] ")
 * into *p, then apply sz→hi normalization plus cross-key and
 * pos-requires-field validation. Returns 1 if the tail is well-formed and
 * self-consistent, 0 to reject the line. */
/* Collected key/value fields from a tagged line's tail (pos= conf= lo= hi=
 * sz= sample= base_align=), after sz→hi normalization. Filled by
 * parse_result_tail(); consumed by the VAS check and the slot append. */
struct parsed_tail {
  int seen_pos, seen_conf, seen_lo, seen_hi, seen_sz, seen_sample;
  int seen_base_align;
  enum kasld_position pos;
  enum kasld_confidence conf;
  unsigned long lo, hi, sz, sample, base_align;
};

static int parse_result_tail(const char *tail_start, struct parsed_tail *p) {
  memset(p, 0, sizeof(*p));
  p->pos = POS_UNKNOWN;
  p->conf = CONF_UNKNOWN;

  char tail[MAX_LINE_LEN];
  size_t tl = strlen(tail_start);
  if (tl >= sizeof(tail))
    return 0;
  memcpy(tail, tail_start, tl + 1);
  /* Strip trailing newline. */
  if (tl > 0 && tail[tl - 1] == '\n')
    tail[tl - 1] = '\0';

  char *save = NULL;
  for (char *tok = strtok_r(tail, " \t", &save); tok;
       tok = strtok_r(NULL, " \t", &save)) {
    char *eq = strchr(tok, '=');
    if (!eq)
      return 0;
    *eq = '\0';
    const char *key = tok;
    const char *val = eq + 1;

    if (strcmp(key, "pos") == 0) {
      if (p->seen_pos)
        return 0;
      p->seen_pos = 1;
      p->pos = pos_from_wire(val);
      /* pos_from_wire returns POS_UNKNOWN for both unknown literal and
       * unrecognized — distinguish: only "unknown" string is valid here. */
      if (p->pos == POS_UNKNOWN && strcmp(val, "unknown") != 0)
        return 0;
    } else if (strcmp(key, "conf") == 0) {
      if (p->seen_conf)
        return 0;
      p->seen_conf = 1;
      p->conf = conf_from_wire(val);
      if (p->conf == CONF_UNKNOWN)
        return 0;
    } else if (strcmp(key, "lo") == 0) {
      if (p->seen_lo || !parse_hex(val, &p->lo))
        return 0;
      p->seen_lo = 1;
    } else if (strcmp(key, "hi") == 0) {
      if (p->seen_hi || p->seen_sz || !parse_hex(val, &p->hi))
        return 0;
      p->seen_hi = 1;
    } else if (strcmp(key, "sz") == 0) {
      if (p->seen_sz || p->seen_hi || !parse_hex(val, &p->sz))
        return 0;
      p->seen_sz = 1;
    } else if (strcmp(key, "sample") == 0) {
      if (p->seen_sample || !parse_hex(val, &p->sample))
        return 0;
      p->seen_sample = 1;
    } else if (strcmp(key, "base_align") == 0) {
      if (p->seen_base_align || !parse_hex(val, &p->base_align))
        return 0;
      if (!is_pow2(p->base_align))
        return 0;
      p->seen_base_align = 1;
    } else {
      /* Unknown key rejects the line (spec: no forward-compat silence). */
      return 0;
    }
  }

  /* Mandatory fields. */
  if (!p->seen_pos || !p->seen_conf)
    return 0;

  /* sz → hi normalization. */
  if (p->seen_sz) {
    /* sz requires lo — check before doing arithmetic on p->lo. */
    if (!p->seen_lo)
      return 0;
    /* hi = lo + sz - 1, rejecting an empty or wrapping extent in one step. */
    if (p->sz == 0 || kasld_add_ovf(p->lo, p->sz - 1, &p->hi))
      return 0;
    p->seen_hi = 1;
  }

  /* Cross-key constraints. */
  if (p->seen_lo && p->seen_hi && p->lo > p->hi)
    return 0;
  if (p->seen_sample) {
    if (p->seen_lo && p->sample < p->lo)
      return 0;
    if (p->seen_hi && p->sample > p->hi)
      return 0;
  }

  /* pos-requires-field. */
  switch (p->pos) {
  case POS_BASE:
    if (!p->seen_lo)
      return 0;
    break;
  case POS_TOP:
    if (!p->seen_hi)
      return 0;
    break;
  case POS_INTERIOR:
    if (!p->seen_sample)
      return 0;
    break;
  case POS_EXTENT:
    /* A covering member is a closed extent — both edges required. The value
     * lives in the gaps between extents, so a half-open extent is meaningless
     * to the map rules that consume it. */
    if (!p->seen_lo || !p->seen_hi)
      return 0;
    break;
  case POS_UNKNOWN:
    if (!p->seen_lo && !p->seen_hi && !p->seen_sample)
      return 0;
    break;
  }
  return 1;
}

/* Parse-time VAS validation against region_info[region].static_vas. Returns 1
 * if in-bounds (or the region is runtime-derived / has no static window), 0 to
 * reject. Layout-derived regions (derive_vas != NULL) are validated at runtime
 * via result_in_bounds instead. A rejection is surfaced under --verbose so a
 * developer porting a component to a new arch sees the drop (naming the
 * offending field) rather than a silent "ran but produced nothing". */
static int result_vas_ok(enum kasld_region region, const struct parsed_tail *p,
                         enum kasld_addr_type type, const char *name_buf,
                         int origin) {
  const struct region_info *ri = &region_info[region];
  if (ri->derive_vas != NULL ||
      (ri->static_vas.lo == 0 && ri->static_vas.hi == 0))
    return 1;

  unsigned long vlo = ri->static_vas.lo;
  unsigned long vhi = ri->static_vas.hi;
  const char *vas_field = NULL;
  unsigned long vas_val = 0;
  if (p->seen_lo && (p->lo < vlo || p->lo > vhi)) {
    vas_field = "lo";
    vas_val = p->lo;
  } else if (p->seen_hi && (p->hi < vlo || p->hi > vhi)) {
    vas_field = "hi";
    vas_val = p->hi;
  } else if (p->seen_sample && (p->sample < vlo || p->sample > vhi)) {
    vas_field = "sample";
    vas_val = p->sample;
  }
  if (!vas_field)
    return 1;

  if (verbose && !quiet)
    fprintf(stderr,
            "[parser] dropped %c %s%s%s: %s=%#lx out of VAS [%#lx, %#lx]"
            " (origin=%s)\n",
            kasld_type_wire(type), kasld_region_wire(region),
            name_buf[0] ? ":" : "", name_buf[0] ? name_buf : "", vas_field,
            vas_val, vlo, vhi,
            kasld_origin_name(origin)[0] ? kasld_origin_name(origin) : "?");
  kasld_discard_record(DISCARD_BOUNDS, kasld_origin_name(origin));
  return 0;
}

/* Claim a results[] slot and populate it from the validated line. Returns 1 on
 * success, 0 if the result table is full (warning emitted once). */
static int append_result(enum kasld_addr_type type, enum kasld_region region,
                         const char *name_buf, const struct parsed_tail *p,
                         const char *method, int origin) {
  kasld_result_lock();
  if (num_results >= MAX_RESULTS) {
    kasld_discard_record(DISCARD_CAPACITY, DSRC_RESULTS);
    static int warned;
    int first = !warned;
    warned = 1;
    kasld_result_unlock();
    /* Reported outside the lock: progress_note() takes output_mutex, and the
     * one-way result_mutex -> output_mutex order is what keeps the two from
     * ever forming a cycle. */
    if (first && !quiet)
      progress_note("[-] result limit (%d) reached, dropping further results",
                    MAX_RESULTS);
    return 0;
  }
  int idx = num_results++;
  kasld_result_unlock();

  struct result *r = &results[idx];
  result_init(r);
  r->type = type;
  r->region = region;
  if (name_buf[0]) {
    size_t nl = strlen(name_buf);
    if (nl > NAME_LEN - 1)
      nl = NAME_LEN - 1;
    memcpy(r->name, name_buf, nl);
    r->name[nl] = '\0';
  }
  r->pos = p->pos;
  r->conf = p->conf;
  if (p->seen_lo) {
    r->lo = p->lo;
    r->set_mask |= LO_SET;
  }
  if (p->seen_hi) {
    r->hi = p->hi;
    r->set_mask |= HI_SET;
  }
  if (p->seen_sample) {
    r->sample = p->sample;
    r->set_mask |= SAMPLE_SET;
  }
  if (p->seen_base_align) {
    r->base_align = p->base_align;
    r->set_mask |= BASE_ALIGN_SET;
  }
  /* Provenance: this is the first contributor. */
  origin_set_add(&r->origins, origin);
  r->method_set = method_bit(method);
  return 1;
}

/* Parse a new-format tagged line into a struct result and append it.
 *
 * Wire format:
 *   <type> <region>[:<name>] pos=<pos> conf=<conf> \
 *       [lo=<hex>] [hi=<hex>|sz=<hex>] [sample=<hex>] [base_align=<hex>]
 *
 * Pipeline: sscanf the positional prefix, then parse_region_field (region +
 * name), parse_result_tail (key/value tail + normalization + validation),
 * result_vas_ok (static-VAS bounds), append_result (slot claim + populate).
 *
 * Returns 1 on accept (record appended to results[]), 0 on reject.
 */
int capture_result(const char *line, const char *method, int origin) {
  /* Quick prefix filter. */
  if (line[0] != 'P' && line[0] != 'V')
    return 0;
  if (line[1] != ' ')
    return 0;

  /* region_field holds the "region[:name]" token. Sized to hold the
   * longest plausible name (NAME_LEN - 1) plus the longest region wire
   * string (~16) plus the separator. Width-restricted sscanf matches the
   * buffer size exactly. */
#define REGION_FIELD_CAP (NAME_LEN + 32)
  char type_ch;
  char region_field[REGION_FIELD_CAP];
  int prefix_consumed = 0;
  /* sscanf width must be strictly less than the buffer size — sscanf writes an
   * implicit terminator. The width is a literal (scanf cannot take a computed
   * one), so a _Static_assert locks it to the buffer: if NAME_LEN ever shrinks
   * enough to make REGION_FIELD_CAP <= 80, the build fails here rather than
   * silently overflowing region_field on component-controlled input. */
  /* __extension__ silences -Wpedantic: _Static_assert is a C11 keyword gcc
   * accepts as an extension on the -std=c99 build path. */
  __extension__ _Static_assert(REGION_FIELD_CAP > 79,
                               "sscanf width 79 must stay < REGION_FIELD_CAP");
  if (sscanf(line, "%c %79s %n", &type_ch, region_field, &prefix_consumed) <
          2 ||
      prefix_consumed == 0)
    return 0;
#undef REGION_FIELD_CAP

  enum kasld_addr_type type = type_from_wire(type_ch);
  if (type == KASLD_TYPE_UNKNOWN)
    goto reject;

  char name_buf[NAME_LEN];
  enum kasld_region region = parse_region_field(region_field, name_buf);
  if (region == REGION_UNKNOWN)
    goto reject;

  struct parsed_tail p;
  if (!parse_result_tail(line + prefix_consumed, &p))
    goto reject;

  /* The two below reject for reasons of their own and record them, so they do
   * not fall through to the parse label. */
  if (!result_vas_ok(region, &p, type, name_buf, origin))
    return 0;

  return append_result(type, region, name_buf, &p, method, origin);

  /* Past the prefix filter the line CLAIMED to be a record, so a rejection here
   * is a component reporting something this build does not accept, and the
   * record it carried never reaches the engine. Recorded at the point of
   * decision rather than inferred by the caller: inference would have to ask
   * whether anything else recorded meanwhile, which is not a question with a
   * stable answer while worker threads share the ledger. */
reject:
  kasld_discard_record(DISCARD_PARSE, kasld_origin_name(origin));
  return 0;
}

/* Parse one `S <fact> conf=<c> value=0x<hex>` scalar-fact wire record into
 * scalar_facts[]. Returns 1 on capture, 0 on reject (unknown fact, bad conf or
 * value). Sibling of capture_result(); same validate-or-reject discipline. */
int capture_scalar(const char *line, int origin) {
  /* Not an `S` record at all — prose off the shared pipe. Not a rejection, and
   * deliberately ahead of the reject label below. */
  if (line[0] != 'S' || line[1] != ' ')
    return 0;
  char name[32], conf_str[16], val_str[40];
  if (sscanf(line, "S %31s conf=%15s value=%39s", name, conf_str, val_str) != 3)
    goto reject;
  enum kasld_scalar_fact f = kasld_scalar_fact_from_wire(name);
  if (f == SF_NONE)
    goto reject;
  enum kasld_confidence c = conf_from_wire(conf_str);
  if (c == CONF_UNKNOWN)
    goto reject;
  unsigned long v;
  if (!parse_hex(val_str, &v))
    goto reject;
  /* Cap check + slot reservation under the same lock as capture_result —
   * the inference worker pool can call this from any thread, so a naked
   * num_scalar_facts++ is racy. Once the slot is reserved, this thread is
   * the only writer of that slot, so the field assignments below run
   * outside the lock. */
  kasld_result_lock();
  if (num_scalar_facts >= MAX_SCALAR_FACTS) {
    kasld_discard_record(DISCARD_CAPACITY, DSRC_SCALARS);
    kasld_result_unlock();
    return 0;
  }
  int idx = num_scalar_facts++;
  kasld_result_unlock();
  struct scalar_fact_record *s = &scalar_facts[idx];
  s->fact = f;
  s->value = v;
  s->conf = c;
  s->origin = origin;
  return 1;

  /* Same discipline as capture_result, and in the same place: past the prefix
   * filter the component meant to report a fact, and this build did not accept
   * it. The full-table path above records its own reason and returns without
   * reaching here. */
reject:
  kasld_discard_record(DISCARD_PARSE, kasld_origin_name(origin));
  return 0;
}

/* Parse one `C <quantity> <op> conf=<c> value=0x<hex>` record into
 * constraint_facts[]. Returns 1 on capture, 0 on reject (unknown quantity,
 * unsupported/unknown op, bad conf or value, full table). Mirrors
 * capture_scalar; the channel carries inequality bounds only (>=, <=). */
int capture_constraint(const char *line, int origin) {
  if (line[0] != 'C' || line[1] != ' ')
    return 0;
  char qname[32], opname[16], conf_str[16], val_str[40];
  if (sscanf(line, "C %31s %15s conf=%15s value=%39s", qname, opname, conf_str,
             val_str) != 4)
    goto reject;
  enum kasld_quantity q = kasld_quantity_from_wire(qname);
  if (q >= Q__COUNT)
    goto reject;
  enum constraint_op op;
  if (!kasld_constraint_op_from_wire(opname, &op))
    goto reject;
  /* Whitelist the inequality-bound ops (matches kasld_emit_constraint); an
   * exact or value2-carrying op reaching here is not carried on this channel.
   */
  if (op != C_LOWER_BOUND && op != C_UPPER_BOUND)
    goto reject;
  enum kasld_confidence c = conf_from_wire(conf_str);
  if (c == CONF_UNKNOWN)
    goto reject;
  unsigned long v;
  if (!parse_hex(val_str, &v))
    goto reject;
  /* Same lock discipline as capture_scalar. */
  kasld_result_lock();
  if (num_constraint_facts >= MAX_CONSTRAINT_FACTS) {
    kasld_discard_record(DISCARD_CAPACITY, DSRC_CONSTRAINT_FACTS);
    kasld_result_unlock();
    return 0;
  }
  int idx = num_constraint_facts++;
  kasld_result_unlock();
  struct constraint_fact_record *cf = &constraint_facts[idx];
  cf->q = q;
  cf->op = op;
  cf->value = v;
  cf->conf = c;
  cf->origin = origin;
  return 1;

reject:
  kasld_discard_record(DISCARD_PARSE, kasld_origin_name(origin));
  return 0;
}
/* ---------------------------------------------------------------------------
 * The store's normal form.
 *
 * Components report the same fact more than once, and they finish in whatever
 * order the worker pool gives them. This pass sorts the store into a canonical
 * content order and collapses records that describe the same (type, region,
 * name), so what survives is a function of the record SET rather than of
 * arrival. Nothing is inferred here: no value is computed, no meaning is
 * assigned -- a duplicate is folded into the record it duplicates, and that is
 * all. Deciding what the surviving records MEAN happens later, and elsewhere.
 * ------------------------------------------------------------------------- */

int conf_weight(enum kasld_confidence c) {
  switch (c) {
  case CONF_PARSED:
    return 6;
  case CONF_DERIVED:
    return 5;
  case CONF_INFERRED:
    return 4;
  case CONF_HEURISTIC:
    return 3;
  case CONF_TIMING:
    return 2;
  case CONF_BRUTE:
    return 1;
  default:
    return 0;
  }
}

/* Dedup key is origin only — same origin with a different method means
 * the second method is silently dropped. This is intentional: the method
 * field is an attribute of the contribution, not a discriminator for
 * identity. Two contributions from the same component are one provenance
 * entry regardless of method. */
static void merge_into(struct result *a, const struct result *b,
                       int *sample_owner_w) {
  if (HAS_LO(b)) {
    if (!HAS_LO(a) || b->lo > a->lo)
      a->lo = b->lo;
    a->set_mask |= LO_SET;
  }
  if (HAS_HI(b)) {
    if (!HAS_HI(a) || b->hi < a->hi)
      a->hi = b->hi;
    a->set_mask |= HI_SET;
  }
  if (HAS_SAMPLE(b)) {
    int wb = conf_weight(b->conf);
    if (!HAS_SAMPLE(a) || wb > *sample_owner_w) {
      a->sample = b->sample;
      a->set_mask |= SAMPLE_SET;
      *sample_owner_w = wb;
      /* pos follows the surviving sample owner unless a stronger claim
       * (POS_BASE: lo IS the base) is already on the record from another
       * contributor. POS_BASE > POS_INTERIOR; the merged record represents
       * the strongest mutually consistent pos claim across contributors. */
      if (a->pos != POS_BASE)
        a->pos = b->pos;
    }
  }
  /* Promote pos to POS_BASE when any contributor carries that claim. The
   * lo/hi/sample fields are merged independently above; this only updates
   * the categorical pos tag so downstream rules that gate on it (notably
   * text_pin_from_observation) fire on the merged record. */
  if (b->pos == POS_BASE && a->pos != POS_BASE)
    a->pos = POS_BASE;
  if (HAS_BASE_ALIGN(b)) {
    if (!HAS_BASE_ALIGN(a) || b->base_align > a->base_align)
      a->base_align = b->base_align;
    a->set_mask |= BASE_ALIGN_SET;
  }
  if (conf_weight(b->conf) > conf_weight(a->conf))
    a->conf = b->conf;
  a->method_set |= b->method_set;
  /* Contributors are a set of component slots, so the union is a word-wise OR:
   * membership is idempotent and no de-duplication pass is needed. */
  origin_set_union(&a->origins, &b->origins);
}

static int merge_consistent(const struct result *a) {
  if (HAS_LO(a) && HAS_HI(a) && a->lo > a->hi)
    return 0;
  return 1;
}

/* Sample-conflict predicate: two contributors both carry HAS_SAMPLE but
 * point at different addresses. Spec rationale: same-(type, region, name)
 * with differing samples almost always means different instances (e.g. two
 * distinct swiotlb buffers, two initrd-witness pointers from different
 * subsystems) — silently collapsing them would lose data. Treated the same
 * as a bound conflict: keep both records separate. Records without a sample
 * pair are always sample-compatible. */
static int samples_conflict(const struct result *a, const struct result *b) {
  if (!HAS_SAMPLE(a) || !HAS_SAMPLE(b))
    return 0;
  return a->sample != b->sample;
}

/* LO-only-point conflict: two contributors are each POS_BASE-style point
 * witnesses (LO set, HI not set) disagreeing on the address. Same rationale
 * as samples_conflict — these are independent observations of distinct
 * points, not refinements of a single range. Without this guard,
 * merge_into's `max(lo)` semantics (which makes sense for intersecting
 * extents) silently discards the lower witness, losing data. Exposed in
 * the wild on ppc64-no-KASLR where two components legitimately emit
 * different base witnesses for the direct map (sysfs_devicetree_memory at
 * PAGE_OFFSET vs sysfs_memory_blocks at PAGE_OFFSET + DRAM_base). */
static int lo_only_conflict(const struct result *a, const struct result *b) {
  int a_point = HAS_LO(a) && !HAS_HI(a);
  int b_point = HAS_LO(b) && !HAS_HI(b);
  if (!a_point || !b_point)
    return 0;
  return a->lo != b->lo;
}

/* Sample-vs-LO clamp conflict: merging would force clamp_sample() to shift
 * an existing sample to satisfy a contributor's lo (sample below it) or hi
 * (sample above it). The clamp silently rewrites the sample address — the
 * source observation's true address is then lost from the merged record
 * AND reattributed to whichever component contributed the conflicting
 * bound. Symmetric in (acc, b) by inspection. */
static int sample_bound_clamp_conflict(const struct result *a,
                                       const struct result *b) {
  if (HAS_SAMPLE(a) && HAS_LO(b) && a->sample < b->lo)
    return 1;
  if (HAS_SAMPLE(a) && HAS_HI(b) && a->sample > b->hi)
    return 1;
  if (HAS_SAMPLE(b) && HAS_LO(a) && b->sample < a->lo)
    return 1;
  if (HAS_SAMPLE(b) && HAS_HI(a) && b->sample > a->hi)
    return 1;
  return 0;
}

/* Cross-tier edge conflict: the WEAKER contributor would supply an edge that
 * survives the intersection.
 *
 * merge_into takes the tightest edge from any contributor and the strongest
 * confidence across all of them, and nothing requires those to be the same
 * contributor. A merged record carries ONE confidence, so a weaker record's
 * tighter edge is published at the stronger record's tier — and the engine's
 * sound floor then admits a bound nothing proved at that tier. The measured
 * edge it displaced is gone from the record entirely.
 *
 * Agreement is not a conflict. A weaker record holding the SAME value moves no
 * edge, which is the corroboration this merge exists for; those still collapse,
 * so the consensus-source counting downstream is unaffected.
 *
 * Refusing costs nothing: both records reach the engine, each carrying its own
 * confidence, and the two resolutions separate them without further help — the
 * guaranteed run is floored above the weaker constraint and never sees it,
 * while the likely run applies both and keeps the tighter claim.
 *
 * Symmetric in (a, b): weak and strong are chosen by confidence, never by which
 * record happens to be the accumulator, so the canonical sort's choice of
 * anchor cannot change the outcome.
 *
 * EDGES ONLY, and the limit is deliberate. merge_into refuses to let a weaker
 * contributor displace a sample another already holds, but adopts one freely
 * where the accumulator holds none, so a weak sample can still reach a record
 * that publishes it at a stronger tier. Extending this predicate to cover that
 * also refuses the merge a weak interior sample makes into a strong extent,
 * which is a refinement worth keeping and is the shape
 * test_merge_sample_inside_extent_collapses pins down. The asymmetry is
 * defensible because only the EDGES become bounds: the merged record keeps the
 * strong contributor's pos, so the sample is carried rather than read as the
 * anchor. Revisit if a consumer is found that turns a sample into a bound at
 * the record's confidence. */
static int conf_edge_conflict(const struct result *a, const struct result *b) {
  int wa = conf_weight(a->conf);
  int wb = conf_weight(b->conf);
  if (wa == wb)
    return 0;
  const struct result *weak = (wa < wb) ? a : b;
  const struct result *strong = (wa < wb) ? b : a;
  if (HAS_LO(weak) && (!HAS_LO(strong) || weak->lo > strong->lo))
    return 1;
  if (HAS_HI(weak) && (!HAS_HI(strong) || weak->hi < strong->hi))
    return 1;
  return 0;
}

static void clamp_sample(struct result *a) {
  if (HAS_SAMPLE(a)) {
    if (HAS_LO(a) && a->sample < a->lo)
      a->sample = a->lo;
    if (HAS_HI(a) && a->sample > a->hi)
      a->sample = a->hi;
  }
  if (a->pos == POS_UNKNOWN) {
    if (HAS_LO(a))
      a->pos = POS_BASE;
    else if (HAS_HI(a))
      a->pos = POS_TOP;
  }
}

/* Total order over a record's own content, for the canonical sort below.
 * Compares only value fields — never provenance or array position — so two
 * records that tie here are identical as evidence, and no refusal predicate can
 * reject their merge. Their relative order is therefore immaterial, which is
 * what lets an unstable qsort produce a stable result. Addresses compare by
 * relation rather than subtraction: they are unsigned long and a difference
 * would wrap. */
static int result_canonical_cmp(const void *va, const void *vb) {
  const struct result *a = (const struct result *)va;
  const struct result *b = (const struct result *)vb;
  if (a->type != b->type)
    return (int)a->type - (int)b->type;
  if (a->region != b->region)
    return (int)a->region - (int)b->region;
  int n = strncmp(a->name, b->name, NAME_LEN);
  if (n != 0)
    return n;
  if (a->pos != b->pos)
    return (int)a->pos - (int)b->pos;
  if (a->conf != b->conf)
    return (int)a->conf - (int)b->conf;
  if (a->set_mask != b->set_mask)
    return a->set_mask < b->set_mask ? -1 : 1;
  if (a->lo != b->lo)
    return a->lo < b->lo ? -1 : 1;
  if (a->hi != b->hi)
    return a->hi < b->hi ? -1 : 1;
  if (a->sample != b->sample)
    return a->sample < b->sample ? -1 : 1;
  if (a->base_align != b->base_align)
    return a->base_align < b->base_align ? -1 : 1;
  return 0;
}

/* Collapse same-(type, region, name) records into one. Called by run_phase()
 * once after every component in the phase has finished, so compute_kaslr_info()
 * — and the engine evidence built from results[] — see deduplicated records.
 * The engine itself runs later, in emit_summary(); nothing infers here.
 *
 * ORDER-INDEPENDENT: results[] arrives in component completion order, which
 * under the worker pool varies between runs. The pass opens by sorting into a
 * canonical content order, so both the grouping and the surviving records are a
 * function of the record SET alone. That matters beyond presentation: the
 * refusal predicates are not transitive (a record carrying no sample is
 * sample-compatible with every other), so which contributor anchors a group can
 * decide which later candidates join it. Sorting fixes the anchor by content
 * instead of by arrival. It also makes every consumer that walks results[] in
 * index order — the JSON and markdown record lists, the text evidence rows, the
 * covering order handed to the engine — reproducible across runs.
 *
 * IDEMPOTENT: safe to call repeatedly. The merge collapses (type, region, name)
 * groups by keeping the highest-confidence record's sample/pos and taking the
 * narrowest interval intersection; calling it again on the already-merged set
 * is a no-op (every potential merge has already been applied). The compaction
 * below preserves relative order, so the array stays sorted and the second
 * call's sort is a no-op too. Test code (and the per-phase wiring in run_phase)
 * relies on this — a future edit that introduced cross-call state would break
 * both. */
void merge_results(void) {
  if (num_results > 1)
    qsort(results, (size_t)num_results, sizeof(results[0]),
          result_canonical_cmp);

  int alive[MAX_RESULTS];
  for (int i = 0; i < num_results; i++)
    alive[i] = 1;

  for (int i = 0; i < num_results; i++) {
    if (!alive[i])
      continue;
    /* Covering members (pos=extent) bypass the merge: they belong to a
     * complete, single-source map whose value lives in the gaps between
     * extents (see struct covering). Collapsing them by (type, region, name)
     * would mix two sources' maps or melt adjacent extents of one map,
     * destroying the gaps the map rules depend on. They are routed to the
     * engine's coverings[] at evidence build; here they pass through untouched
     * as neither anchor nor candidate. */
    if (results[i].pos == POS_EXTENT)
      continue;
    int merged_any = 0;
    struct result acc = results[i];
    int sample_owner_w =
        HAS_SAMPLE(&results[i]) ? conf_weight(results[i].conf) : -1;
    int contribs[MAX_RESULTS];
    int n_contribs = 0;
    contribs[n_contribs++] = i;

    for (int j = i + 1; j < num_results; j++) {
      if (!alive[j])
        continue;
      const struct result *b = &results[j];
      if (b->pos == POS_EXTENT)
        continue; /* covering members never merge — see the anchor guard */
      if (b->type != acc.type || b->region != acc.region)
        continue;
      if (strncmp(b->name, acc.name, NAME_LEN) != 0)
        continue;
      /* Independent-witness gates: different samples / LO-only points /
       * sample-vs-bound combinations for the same merge key are almost
       * certainly different instances (two swiotlb buffers, two initrd
       * witnesses, two base witnesses on a coupled arch) — silently
       * collapsing them would lose data. Keep both records. */
      if (samples_conflict(&acc, b))
        continue;
      if (lo_only_conflict(&acc, b))
        continue;
      if (sample_bound_clamp_conflict(&acc, b))
        continue;
      if (conf_edge_conflict(&acc, b))
        continue;
      struct result trial = acc;
      int trial_w = sample_owner_w;
      merge_into(&trial, b, &trial_w);
      if (!merge_consistent(&trial))
        continue;
      acc = trial;
      sample_owner_w = trial_w;
      contribs[n_contribs++] = j;
      merged_any = 1;
    }

    if (!merged_any)
      continue;

    clamp_sample(&acc);
    results[i] = acc;
    for (int k = 1; k < n_contribs; k++)
      alive[contribs[k]] = 0;
  }

  int w = 0;
  for (int i = 0; i < num_results; i++) {
    if (!alive[i])
      continue;
    if (w != i)
      results[w] = results[i];
    w++;
  }
  num_results = w;
}