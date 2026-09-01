// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: KASLR slot granularity from x86 CONFIG_PHYSICAL_ALIGN.
//
// CONFIG_PHYSICAL_ALIGN is the actual physical KASLR slot granularity — a
// Kconfig range rather than a constant, and a different range on each x86
// target (arch/x86/Kconfig). When it exceeds the arch default the slot count is
// proportionally smaller, so raise both
// Q_VIRT_KASLR_ALIGN and Q_PHYS_KASLR_ALIGN (physical and virtual offsets are
// locked on x86-64).
//
// Reads SF_PHYS_KERNEL_ALIGN, emitted by either source:
//   - boot_params_facts.c — /sys/kernel/boot_params/data hdr.kernel_alignment
//     (the kernel's runtime echo of CONFIG_PHYSICAL_ALIGN; canonical).
//   - boot_config.c / proc_config.c — CONFIG_PHYSICAL_ALIGN= line from
//     /boot/config-$REL or /proc/config.gz (fallback when boot_params is
//     unreadable, e.g. minimal containers).
// Both sources emit CONF_PARSED; the engine's strongest-wins resolver
// dedupes when both fire.
//
// C_EQUALS, not a floor: CONFIG_PHYSICAL_ALIGN is the slot granularity itself.
// The boot stub steps both slot arrays by exactly that constant -- the physical
// one when it walks the usable memory regions, and the virtual one when it
// picks a displacement within the image window -- so no placement lies off that
// grid and none between two of its multiples. Stating it closes the alignment
// from above as well as below, which is what lets a count over the resulting
// grain be the size of the set the kernel drew from rather than a ceiling over
// it. A value below the arch baseline still cannot lower the floor; the
// axiomatic kaslr_align_arch_default constraint dominates it.
//
// The claim rests on the value describing the running kernel. Both readable
// sources are the target's own configuration -- the kernel's copy of the
// constant, or its config -- and an unkeyed /boot/config, which is not bound to
// the running kernel, is already demoted below the sound floor where it is
// read, so it cannot reach this.
//
// One caveat on the boot_params copy, which the image copy does not share: the
// field is documented read/modify, and from protocol 2.10 a loader may LOWER it
// toward min_alignment to permit a lesser alignment. The randomizer steps by
// CONFIG_PHYSICAL_ALIGN regardless, so a lowered value only understates the
// granularity -- more placements counted, less snapping -- and is then a floor
// wearing the label of a value.
//
// How much room that leaves is not the same on the two x86 targets, and the
// difference is the size of the mislabel rather than of the risk.
// MIN_KERNEL_ALIGN_LG2 is PMD_SHIFT on x86_64 (asm/boot.h) -- 2 MiB, which is
// the architectural grid itself, so there is nowhere to lower to. On x86_32 it
// is PAGE_SHIFT + THREAD_SIZE_ORDER, and THREAD_SIZE_ORDER is 1
// (page_32_types.h), giving 8 KiB against a 2 MiB default: 256 steps of room.
//
// A RAISED field is the direction nothing here detects. The drop below refuses
// values under the architecture's minimum, which is the harmless case -- as a
// floor such a value was dominated anyway. A value over the minimum passes
// untouched, and since this states a value rather than a bound it would close
// the alignment onto a grid coarser than the one the kernel used, which
// image_base_grid_align then snaps a window onto. The boot protocol sanctions
// modification downward only and no in-tree loader raises the field, so this
// takes an out-of-spec loader; it is recorded because the code cannot tell.
//
// A value below the architecture's own minimum is dropped rather than emitted.
// The Kconfig range starts at that minimum, so a smaller reading describes no
// kernel this architecture can build and is bad data. As a floor such a value
// was harmless -- the axiomatic baseline simply dominated it -- but a stated
// granularity beneath the baseline contradicts it instead, and the resolver
// would have to discard one of the two. The architecture's minimum is not the
// one to discard. A sanity check gates emission before that comparison: a
// power of two within the range the architecture's own Kconfig admits.
//
// x86 only (boot_params is x86-specific; CONFIG_PHYSICAL_ALIGN is an x86
// Kconfig knob); inert elsewhere.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

int rule_boot_params_kaslr_align(const struct evidence_set *ev,
                                 const struct estimate *est,
                                 struct constraint *out, int out_max) {
  (void)est;
#if defined(__x86_64__) || defined(__i386__)
  unsigned long align = 0;
  uint32_t src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (o->valid && o->value_kind == OBS_SCALAR &&
        o->scalar_fact == SF_PHYS_KERNEL_ALIGN) {
      align = o->scalar_value;
      src = o->id;
      break;
    }
  }

  /* Sanity: a non-zero power of two no coarser than the widest alignment the
   * architecture admits. Both x86 targets range CONFIG_PHYSICAL_ALIGN up to
   * 0x1000000 (arch/x86/Kconfig), so a larger figure describes no kernel either
   * can build. This bounds a field that arrived wrong; it does not detect one
   * raised within the range, which nothing here can. */
  if (align == 0 || (align & (align - 1)) != 0 || align < 4096ul ||
      align > 0x1000000ul)
    return 0;

  int n = 0;
  const enum kasld_quantity qs[] = {Q_VIRT_KASLR_ALIGN, Q_PHYS_KASLR_ALIGN};
  const unsigned long mins[] = {(unsigned long)KASLR_VIRT_ALIGN,
                                (unsigned long)KASLR_PHYS_ALIGN};
  for (size_t i = 0; i < sizeof(qs) / sizeof(qs[0]) && n < out_max; i++) {
    struct constraint *c;
    if (align < mins[i])
      continue;
    c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = qs[i];
    c->op = C_EQUALS;
    c->value = align;
    c->conf = CONF_PARSED;
    c->derived_from[0] = src;
    c->lineage_count = src ? 1 : 0;
    snprintf(c->origin, ORIGIN_LEN, "boot_params_kaslr_align");
  }
  return n;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
