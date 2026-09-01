// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: s390 KASLR granularity is THREAD_SIZE, which the config settles.
//
// The s390 boot code places the kernel with round_down(..., THREAD_SIZE) and
// says so of the result: "__kaslr_offset, which is THREAD_SIZE aligned"
// (arch/s390/boot/startup.c). THREAD_SIZE is PAGE_SIZE << THREAD_SIZE_ORDER,
// and s390 fixes PAGE_SIZE at 4 KiB -- arch/s390/Kconfig selects
// HAVE_PAGE_SIZE_4KB and offers no other size -- so the granularity is decided
// entirely by that order: 2 ordinarily, 4 under CONFIG_KASAN or CONFIG_KMSAN
// (arch/s390/include/asm/thread_info.h). 16 KiB or 64 KiB, nothing else.
//
// Which of the two is therefore a question a readable kernel config answers
// outright, and answers for both axes. The arch baseline claims the smaller as
// a floor, because that is all it can claim without seeing the config; this
// states the value once the config has been seen:
//
//   either set   -> 64 KiB. Four times coarser than the baseline, so this
//                   NARROWS: the same window holds a quarter as many
//                   placements. Sound because the offset really is a multiple
//                   of 64 KiB there.
//   both clear   -> 16 KiB, which is the baseline's own value -- so nothing
//                   moves except that the count stops being a ceiling.
//
// Both facts must be present. Their absence is not a negative: a config that
// could not be read states neither, and assuming the ordinary case there would
// put a guess where the baseline already has a sound floor. The two are
// mutually exclusive in Kconfig (KMSAN depends on !KASAN), so no run should see
// both set; if one did, the coarser answer is the same either way.
//
// Capped at the weaker of the two facts' confidence, so an unkeyed /boot config
// -- already demoted where it is read -- shapes the likely window only.
//
// s390 only; inert elsewhere.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

int rule_s390_thread_size_align(const struct evidence_set *ev,
                                const struct estimate *est,
                                struct constraint *out, int out_max) {
  (void)est;
#if defined(__s390x__) || defined(__s390__)
  int have_kasan = 0, have_kmsan = 0, kasan = 0, kmsan = 0;
  enum kasld_confidence kasan_conf = CONF_UNKNOWN, kmsan_conf = CONF_UNKNOWN;
  uint32_t src = 0;
  int n = 0;

  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR)
      continue;
    /* Strongest wins, not first seen: /proc/config.gz and a release-keyed
     * /boot/config can both answer, and taking whichever the evidence set
     * happened to order first would let a weaker source decide the value and
     * cap the constraint under it. */
    if (o->scalar_fact == SF_KASAN_ENABLED &&
        (!have_kasan || o->conf > kasan_conf)) {
      have_kasan = 1;
      kasan_conf = o->conf;
      kasan = o->scalar_value != 0;
      src = o->id;
    } else if (o->scalar_fact == SF_KMSAN_ENABLED &&
               (!have_kmsan || o->conf > kmsan_conf)) {
      have_kmsan = 1;
      kmsan_conf = o->conf;
      kmsan = o->scalar_value != 0;
    }
  }
  if (!have_kasan || !have_kmsan)
    return 0;
  /* The pair is only as trustworthy as its weaker half. */
  const enum kasld_confidence conf =
      kasan_conf < kmsan_conf ? kasan_conf : kmsan_conf;

  /* PAGE_SIZE << 2, or << 4 where the instrumented stacks are built in. */
  const unsigned long thread_size = (kasan || kmsan) ? 0x10000ul : 0x4000ul;

  const enum kasld_quantity qs[] = {Q_VIRT_KASLR_ALIGN, Q_PHYS_KASLR_ALIGN};
  for (size_t i = 0; i < sizeof(qs) / sizeof(qs[0]) && n < out_max; i++) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = qs[i];
    c->op = C_EQUALS;
    c->value = thread_size;
    c->conf = conf;
    c->derived_from[0] = src;
    c->lineage_count = src ? 1 : 0;
    snprintf(c->origin, ORIGIN_LEN, "s390_thread_size_align");
  }
  return n;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
