// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Expected kernel address space values for supported architectures, plus the
// shared component API: result emission helpers, region enum, KASLD_EXPLAIN,
// KASLD_META.
//
// Each architecture header (arch/*.h) defines kernel address-space constants
// used throughout kasld; see any arch/*.h for the set, and the #error guards
// below for the symbols every arch must supply.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_API_H
#define KASLD_API_H

/* The 4 KiB granule the kernel's own layout arithmetic is written in: the unit
 * behind expressions lifted from kernel source, such as x86_64's module
 * randomization span of `1024 * PAGE_SIZE`. It is a fixed number that stays 4
 * KiB whatever the analysed machine runs.
 *
 * It is NOT the target's page size, and must never stand in for one. Four of
 * the eight supported architecture families admit several page sizes -- arm64
 * and loongarch64 4/16/64 KiB, mips 4/8/16/32/64 KiB, powerpc 4/16/64/256 KiB
 * -- so on those a page-frame number converted with this constant is wrong by
 * up to 64x. Where the target's page size is genuinely needed, it comes from
 * the SF_PAGE_SIZE observation at runtime; pfn_to_phys() below exists only on
 * the architectures where the two coincide, so a conversion that needs the
 * runtime value cannot reach this constant by accident.
 *
 * Deliberately not spelled PAGE_SIZE: that name belongs to the C library on
 * some targets (musl defines it under _GNU_SOURCE wherever the ABI fixes a
 * page size), and a macro named for a machine property invites exactly the
 * substitution the paragraph above forbids. */
#define KASLD_LAYOUT_GRANULE 0x1000ul
#define KB 0x400ul
#define MB 0x100000ul
#define GB 0x40000000ul
#define TB 0x10000000000ul
#define PB 0x4000000000000ul

/* =========================================================================
 * kasld_addr_t — the kernel-address value domain.
 *
 * CONTRACT: kasld is built for, and run on, its target architecture (a cross
 * compiler may produce the binary, but it executes on the target's kernel).
 * So the build word == the target kernel word, and a kernel address is exactly
 * `unsigned long`. kasld_addr_t names that domain: use it for stored addresses
 * (result/observation lo/hi/sample/base_align, ...) so the intent is explicit
 * and the type lives in one place.
 *
 * Two things deliberately do NOT use kasld_addr_t:
 *   - values that are arch-INDEPENDENT and may exceed any word (plausibility
 *     ceilings such as 1<<50, slot math): those are `unsigned long long`, and
 *     are consumed by `unsigned long long`-parameter helpers (kasld_addr_in_*)
 *     so a wide bound is never silently truncated to the word; and
 *   - real machine pointers / syscall operands at the hardware boundary, which
 *     are the platform's `unsigned long`/`uintptr_t`/`void *` by definition.
 * ========================================================================= */
typedef unsigned long kasld_addr_t;

/* Overflow-checked unsigned word arithmetic. Returns 1 if a (+|*) b overflows
 * the word — the wrapped result is still written to *out — and 0 otherwise.
 * Prefer these to hand-rolling a `b > ULONG_MAX - a` pre-check: they compute
 * and check in one step and can't be got subtly wrong. Uses the compiler
 * builtin where available; the fallback is the standard wrap test. */
#if defined(__GNUC__) || defined(__clang__)
static inline int kasld_add_ovf(unsigned long a, unsigned long b,
                                unsigned long *out) {
  return __builtin_add_overflow(a, b, out);
}
static inline int kasld_mul_ovf(unsigned long a, unsigned long b,
                                unsigned long *out) {
  return __builtin_mul_overflow(a, b, out);
}
#else
static inline int kasld_add_ovf(unsigned long a, unsigned long b,
                                unsigned long *out) {
  *out = a + b;
  return *out < a;
}
static inline int kasld_mul_ovf(unsigned long a, unsigned long b,
                                unsigned long *out) {
  *out = a * b;
  return a != 0 && *out / a != b;
}
#endif

/* =========================================================================
 * Arch-header contract: every per-arch header (arch/...) below defines these.
 *
 * Virtual address space layout:
 * - PAGE_OFFSET:              Start of the kernel direct-mapping (linear map).
 * - KERNEL_VIRT_VAS_START:    Lowest plausible kernel virtual address (floor).
 *                             Often equals PAGE_OFFSET, but may be lower on
 *                             arches with configurable vmsplit to cover all
 *                             configs (e.g. 0x40000000 on 32-bit x86/arm).
 * - KERNEL_VIRT_VAS_END:      End of kernel virtual address space.
 * - KERNEL_VIRT_TEXT_MIN:     Minimum plausible kernel text virtual address.
 * - KERNEL_VIRT_TEXT_MAX:     Maximum plausible kernel text virtual address.
 * - MODULES_START / _END:     Kernel module virtual address range.
 *
 *   CONTRACT: MODULES_START/END is the *validation UNION* across all in-scope
 *   kernel versions, not the snapshot of one. Narrower runtime windows are
 *   anchored from /proc/modules / /sys/module observations
 *   (engine_sync_authoritative); the static window must not exclude any
 *   address a real kernel might assign to a module -- silently rejecting
 *   legitimate module leaks is the failure mode this guards against. A
 *   wider-than-truth window admits some non-module addresses (cosmetic where
 *   the band is not used to bound text); a narrower-than-truth window drops
 *   real data. Where the module region MOVES WITH KASLR the union must cover
 *   the relocatable range; a static band describes the region only when KASLR
 *   is off. Widening far enough to do that can leave range-classification
 *   vacuous on an arch -- that is the correct trade, and it is contained by
 *   the REGION_MODULE / REGION_MODULE_BAND provenance split (see the region
 *   table), never by narrowing the union back.
 *
 * - MODULES_RELATIVE_TO_TEXT: 1 if the module region shifts with KASLR text.
 * - IMAGE_ALIGN:              Kernel text address alignment.
 * - IMAGE_BASE_OFFSET:       the gap from the image's PLACEMENT ADDRESS to
 * _text -- from the linear-map base on a coupled arch, from the load address on
 * s390 -- so `placement + IMAGE_BASE_OFFSET` is where _text lands. It is what a
 * rule adds when projecting a base it knows onto the text base. NOT the _stext
 * head gap (see STEXT_OFFSET), and NOT _text's alignment residue: the two
 * coincide on most arches but diverge wherever the gap is a whole multiple of
 * the KASLR granule, where the residue is 0 and this constant is not --
 * 0x100000 vs 0 on s390, 0x200000 vs 0 on loongarch64. Code that wants the
 * residue must take `KERNEL_VIRT_TEXT_DEFAULT & (align - 1)`, which is what
 * kasld_floor_aligned_suboffset() does; using IMAGE_BASE_OFFSET there would
 * floor a whole granule too high on those two arches and could exclude the
 * truth.
 * - STEXT_OFFSET:             Head gap _stext - _text (0 unless a fixed header
 *                             precedes _stext, e.g. arm64 0x10000); see its
 *                             definition below — a fallback, resolved at
 * runtime from the real _text symbol where possible.
 * - KERNEL_VIRT_TEXT_DEFAULT: Default image base (_text) virtual address (no
 * KASLR).
 *
 * Physical addresses:
 * - PHYS_OFFSET:              Physical RAM base address.
 * - KERNEL_PHYS_MIN / _MAX:   Min/max plausible kernel physical load address.
 *
 * KASLR and address derivation:
 * - KASLR_SUPPORTED:          1 if the arch has mainline KASLR.
 * - DIRECTMAP_STATIC:         1 if PAGE_OFFSET and PHYS_OFFSET do not move at
 *                             runtime (the linear-map base is fixed once
 * booted). This governs whether a direct-map base reconstructed from a leak may
 * be PINNED to one value (PAGE_OFFSET_FIXED) rather than kept a window. 0 if
 * either offset shifts at boot (KASLR randomization or runtime patching), where
 * such a reconstruction must stay a window. It does NOT gate the compile-time
 * projection macros phys_to_directmap_virt / directmap_virt_to_phys: those
 * substitute this build's PAGE_OFFSET, which is sound only where this build
 * KNOWS the target's base (PAGE_OFFSET_KNOWN_AT_BUILD), a stricter condition.
 *                             The VMSPLIT arches are DIRECTMAP_STATIC=1 yet
 *                             KNOWN_AT_BUILD=0 -- the base is a runtime
 * constant but this build cannot know which split the target chose -- so the
 * macros are undefined there.
 * - PHYS_OFFSET_EXACT:        1 if PHYS_OFFSET is the true runtime physical
 * base of the linear map, so page_offset_base = directmap_va -
 * __pa(directmap_va) + PHYS_OFFSET is exact. 0 (the default) if PHYS_OFFSET is
 * a placeholder or assumption -- e.g. arm64 randomizes memstart_addr and
 * riscv's RAM base is board-dependent, so that identity would recover a wrong
 * base. Narrower than DIRECTMAP_STATIC, which also requires a static
 * PAGE_OFFSET (x86_64 randomizes page_offset_base yet keeps PHYS_OFFSET exactly
 * 0).
 * - TEXT_TRACKS_DIRECTMAP:    1 if kernel text sits at a fixed offset within
 * the linear map (text moves with the directmap; KASLR cannot slide them
 * independently). 0 if text relocates independently -- phys-DRAM ceilings /
 *                             floors then do not propagate to virtual text
 *                             bounds.
 * - directmap_virt_to_phys(): Convert a directmap virtual to its physical page.
 *                             Gated by PAGE_OFFSET_KNOWN_AT_BUILD, like
 *                             phys_to_directmap_virt; sound only when the input
 *                             is a directmap address.
 *
 * These are deliberately WIDE: each range is the union across all in-scope
 * kernel versions / configs (vmsplit, non-KASLR defaults, old kernels), so a
 * real leak is never wrongly rejected; the engine narrows from observations.
 * They are a validation contract, not per-system defaults to hand-tune.
 *
 * Two tiers of virtual-text ranges exist:
 *   KERNEL_VIRT_TEXT_MIN/MAX -- the validation range: any leaked virtual text
 *     address in [MIN, MAX] is plausible on this arch (wide enough to cover all
 *     vmsplit configs, non-KASLR defaults, old kernels). Accepts/rejects leaks.
 *   KASLR_VIRT_TEXT_MIN/MAX  -- the randomization window: the narrower range
 * the KASLR mechanism actually selects from at boot. Drives slot count /
 * entropy bits. KASLR_VIRT_ALIGN is the slot granularity. On most arches the
 * two ranges coincide and KASLR_VIRT_ALIGN == IMAGE_ALIGN (the defaults below
 * alias them); arch headers override when they differ, e.g. x86_64: KERNEL_TEXT
 * [0xffffffff80000000, 0xffffffffc0000000] (1 GiB); KASLR_TEXT  [MIN + 16 MiB,
 * ...]; KASLR_VIRT_ALIGN = 2 MiB. arm64:  KERNEL_TEXT ~128 TiB; KASLR_TEXT ~64
 * TiB; KASLR_VIRT_ALIGN 64 KiB (== IMAGE_ALIGN).
 * ========================================================================= */

/* LINEAR_MAP_ANCHOR — WHERE the linear map's physical anchor comes from.
 *
 * The linear map sends one physical address to virtual PAGE_OFFSET. Call it the
 * anchor. A rule that pairs a direct-map virtual with a physical reconstructs
 * the base as (virt - phys + anchor), so the anchor is the whole content of the
 * derivation — get it wrong and the base is wrong by the same amount, silently,
 * with nothing in the arithmetic to notice. The anchor is not a number this
 * binary can carry (on most arches the kernel decides it at boot), so the axis
 * names its SOURCE:
 *
 *   LM_ANCHOR_PHYS_OFFSET — the compile-time PHYS_OFFSET IS the anchor. These
 *     are the kernels that map physical 0 at the linear-map base, so the
 *     constant is right by construction rather than by luck.
 *   LM_ANCHOR_DRAM_BASE — the kernel sets the anchor FROM the base of DRAM
 *     while booting, so the lowest observed physical RAM base names it. The
 *     value is a runtime discovery; only evidence supplies it.
 *   LM_ANCHOR_UNKNOWABLE — the kernel places the anchor at neither, displaced
 *     by an amount no unprivileged observation recovers. A rule must DECLINE;
 *     there is no sound one-sided bound to fall back on either, because the
 *     displacement has no fixed direction.
 *
 * Declared by every arch header, because there is no defensible default: a
 * missing answer would silently become "PHYS_OFFSET" and reintroduce exactly
 * the substitution this axis exists to prevent.
 *
 * This is a THIRD axis, not a restatement of the two above it. DIRECTMAP_STATIC
 * asks whether the base moves at runtime and TEXT_TRACKS_DIRECTMAP whether text
 * rides inside the map; both were used as proxies for this question and neither
 * answers it. arm64 is the counterexample that separates all three: text is
 * randomized independently of the map (TEXT_TRACKS_DIRECTMAP=0), the base does
 * move (DIRECTMAP_STATIC=0), and the anchor is UNKNOWABLE — memstart_addr is
 * rounded down to ARM64_MEMSTART_ALIGN, re-based to (end of DRAM - linear
 * region size) when memory overflows the map, decremented by the whole
 * 52-to-48 PAGE_OFFSET difference on a 52-bit build running without 52-bit
 * hardware, and on older kernels moved down again by a random multiple of the
 * alignment. Every one of those displacements is itself large-page aligned, so
 * an alignment sanity check does not catch them.
 *
 * Each arch header cites the kernel code its answer comes from. */
/* MODULES_ANCHOR — what the module band's position is fixed to.
 *
 * Four alternatives, and they are alternatives: a band is anchored to exactly
 * one thing. Encoding that as independent booleans meant the illegal
 * combinations had to be excluded by hand, and api.h grew a pairwise #error for
 * each pair anyone thought of — "cannot follow both PAGE_OFFSET and the text
 * base", "cannot be both text-bracketing and text-relative". Those checks were
 * the encoding admitting it was wrong: n placements need n(n-1)/2 checks to
 * stay exclusive, and the (n+1)th is added by someone who writes one boolean
 * and forgets n more. As a single value the exclusivity is structural and the
 * checks are unnecessary.
 *
 *   MOD_ANCHOR_FIXED         a fixed address range, independent of both the
 *                            image and the linear map.
 *   MOD_ANCHOR_PAGE_OFFSET   a fixed delta from PAGE_OFFSET, so a runtime
 *                            VMSPLIT moves the band with it. Requires
 *                            MODULES_START_FOR / MODULES_END_FOR.
 *   MOD_ANCHOR_TEXT          placed relative to the kernel image, so it slides
 *                            with text KASLR.
 *   MOD_ANCHOR_BRACKETS_TEXT a window centred on the image,
 * MODULES_BRACKET_TEXT wide either side.
 *
 * The two long-standing booleans are DERIVED below rather than declared, so the
 * arch headers state the anchor once and every existing consumer keeps reading
 * the predicate it already reads. */
#define MOD_ANCHOR_FIXED 1
#define MOD_ANCHOR_PAGE_OFFSET 2
#define MOD_ANCHOR_TEXT 3
#define MOD_ANCHOR_BRACKETS_TEXT 4

/* MODULES_BAND_STRENGTH — how much the COMPILE-TIME band is trusted to say
 * about Q_MODULE_BASE. An ordinal, not a set of flags: each level is strictly
 * stronger than the one below, so the ladder is the exclusivity and the
 * implication between levels needs no #error to enforce.
 *
 *   MOD_BAND_ADMISSION  the band is wide enough not to REJECT a real module
 *                       address, and nothing more. Nothing is emitted.
 *   MOD_BAND_BOUNDS     [MODULES_START, MODULES_END] spans the region under
 *                       every configuration the header models, so both edges
 *                       bound the base.
 *   MOD_BAND_PINNED     the region STARTS at MODULES_START exactly -- a fixed
 *                       address with no randomization, allocator offset or
 *                       runtime term. The floor IS the base, so the rule pins.
 *
 * PINNED sits above BOUNDS rather than beside it, which asks an arch that pins
 * to have verified its ceiling too even though the pin never reads it. That is
 * deliberate: an arch confident enough to answer the quantity outright should
 * have established the band it sits in, and the alternative -- per-edge claims
 * -- buys an asymmetry no in-tree arch needs at the cost of another macro.
 *
 * ADMISSION is the default because the failure it prevents is the expensive
 * one: an unverified arch that says nothing costs precision, whereas one that
 * silently claims BOUNDS can put a guaranteed window where the base is not. It
 * must stay declarable independently of the anchor for that reason -- today
 * every ADMISSION arch is also PAGE_OFFSET-anchored, but that is a fact about
 * which arches have been checked, not a rule. */
#define MOD_BAND_ADMISSION 1
#define MOD_BAND_BOUNDS 2
#define MOD_BAND_PINNED 3

#define LM_ANCHOR_PHYS_OFFSET 1
#define LM_ANCHOR_DRAM_BASE 2
#define LM_ANCHOR_UNKNOWABLE 3

#if defined(__x86_64__) || defined(__amd64__)
#include "arch/x86_64.h"
#elif defined(__i386__)
#include "arch/x86_32.h"
#elif defined(__aarch64__)
#include "arch/arm64.h"
#elif defined(__arm__) || defined(__ARM_ARCH_6__) ||                           \
    defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) ||                    \
    defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__) ||                   \
    defined(__ARM_ARCH_6T2__) || defined(__ARM_ARCH_7__) ||                    \
    defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) ||                    \
    defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
#include "arch/arm32.h"
#elif defined(__mips64) || defined(__mips64__)
#include "arch/mips64.h"
#elif defined(__mips__)
#include "arch/mips32.h"
#elif defined(__powerpc64__) || defined(__POWERPC64__) ||                      \
    defined(__ppc64__) || defined(__PPC64__)
#include "arch/ppc64.h"
#elif defined(__powerpc__) || defined(__POWERPC__) || defined(__ppc__) ||      \
    defined(__PPC__)
#include "arch/ppc32.h"
#elif (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64
#include "arch/riscv64.h"
#elif (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 32
#include "arch/riscv32.h"
#elif defined(__loongarch__) && __loongarch_grlen == 64
#include "arch/loongarch64.h"
#elif defined(__s390x__) || defined(__zarch__)
#include "arch/s390.h" /* experimental */
#elif defined(__sparc__)
#include "arch/sparc.h"
#elif defined(__sh__)
#include "arch/sh.h"
#elif defined(__m68k__)
#include "arch/m68k.h"
#elif defined(__MICROBLAZE__) || defined(__microblaze__)
#include "arch/microblaze.h"
#elif defined(__or1k__) || defined(__OR1K__)
#include "arch/openrisc.h"
#else
#error "Unrecognized architecture!"
#endif

/* Sanity-check arch-supplied values. */
#if KERNEL_VIRT_VAS_START > KERNEL_VIRT_VAS_END
#error "Defined KERNEL_VIRT_VAS_START is larger than KERNEL_VIRT_VAS_END"
#endif
#if KERNEL_VIRT_VAS_START > KERNEL_VIRT_TEXT_MIN
#error "Defined KERNEL_VIRT_VAS_START is larger than KERNEL_VIRT_TEXT_MIN"
#endif
#if KERNEL_VIRT_TEXT_MAX > KERNEL_VIRT_VAS_END
#error "Defined KERNEL_VIRT_TEXT_MAX is larger than KERNEL_VIRT_VAS_END"
#endif
#if KERNEL_VIRT_TEXT_DEFAULT > KERNEL_VIRT_TEXT_MAX
#error "Generated KERNEL_VIRT_TEXT_DEFAULT is larger than KERNEL_VIRT_TEXT_MAX"
#endif
#if KERNEL_VIRT_TEXT_DEFAULT < KERNEL_VIRT_TEXT_MIN
#error "Generated KERNEL_VIRT_TEXT_DEFAULT is smaller than KERNEL_VIRT_TEXT_MIN"
#endif
#ifdef KERNEL_PHYS_MIN
#if KERNEL_PHYS_MIN > KERNEL_PHYS_MAX
#error "Defined KERNEL_PHYS_MIN is larger than KERNEL_PHYS_MAX"
#endif
/* Catch an N*GB upper bound that overflowed the word on a 32-bit arch (4*GB
 * wraps to 0). A `#if` can't see this: the preprocessor evaluates in intmax_t
 * (>= 64-bit), so the wrap that only happens in `unsigned long` is invisible to
 * it — and to the relational `#if` above. _Static_assert is evaluated by the
 * compiler in the target's own types, so it does see the wrap. (Unsigned
 * overflow is defined behaviour, so no warning flag catches it either.) */
__extension__ _Static_assert((unsigned long)KERNEL_PHYS_MAX >
                                 (unsigned long)KERNEL_PHYS_MIN,
                             "KERNEL_PHYS_MAX <= KERNEL_PHYS_MIN -- an N*GB "
                             "constant overflowed the 32-bit word?");
#endif

/* DIRECTMAP_STATIC and TEXT_TRACKS_DIRECTMAP must be declared by every arch
 * header — no defaults. Forcing each arch author to make the decision
 * explicitly is the whole point. See the arch-header contract banner above
 * for the 0/1 semantics.
 *
 * The two answer different questions, and both are read on their own:
 * DIRECTMAP_STATIC decides whether a direct-map base reconstructed from a leak
 * may be pinned to one value (PAGE_OFFSET_FIXED, below); TEXT_TRACKS_DIRECTMAP
 * decides whether a physical bound may propagate to the virtual text base.
 * Neither gates the compile-time projections — that is
 * PAGE_OFFSET_KNOWN_AT_BUILD's job, since projecting requires knowing the base
 * HERE, not merely that the target holds it still.
 *
 * They nonetheless hold the SAME value on every architecture supported today,
 * so no in-tree arch demonstrates the difference and neither can be inferred
 * from the other by example. Pick by the question being asked, not by what a
 * neighbouring header happens to say. The pair separates as soon as an arch
 * fixes one of the two independently:
 *
 *   DIRECTMAP_STATIC=1, TEXT_TRACKS_DIRECTMAP=0 — the linear map does not move
 *   at runtime while the image is randomized independently of it
 *   (x86_64 built without RANDOMIZE_MEMORY is exactly this shape; KASLD models
 *   x86_64 with DIRECTMAP_STATIC=0 because it cannot prove the build).
 *
 *   DIRECTMAP_STATIC=0, TEXT_TRACKS_DIRECTMAP=1 — text keeps a fixed offset
 *   inside a linear map whose own base is randomized, so the offset is known
 *   but neither endpoint is.
 *
 * Treating them as one flag would silently pick a side on whichever arch
 * arrives first. */
#ifndef PAGE_SIZE_MIN
#error                                                                         \
    "arch header must define PAGE_SIZE_MIN / PAGE_SIZE_MAX (the page sizes the arch admits)"
#endif
#ifndef PAGE_SIZE_MAX
#error                                                                         \
    "arch header must define PAGE_SIZE_MIN / PAGE_SIZE_MAX (the page sizes the arch admits)"
#endif
#ifndef DIRECTMAP_STATIC
#error "arch header must define DIRECTMAP_STATIC (0 or 1)"
#endif
#ifndef TEXT_TRACKS_DIRECTMAP
#error "arch header must define TEXT_TRACKS_DIRECTMAP (0 or 1)"
#endif
#ifndef LINEAR_MAP_ANCHOR
#error                                                                         \
    "arch header must define LINEAR_MAP_ANCHOR (LM_ANCHOR_PHYS_OFFSET / _DRAM_BASE / _UNKNOWABLE)"
#endif
#ifndef IMAGE_BASE_RESIDUE_FIXED
#error                                                                         \
    "arch header must define IMAGE_BASE_RESIDUE_FIXED (0 or 1) -- see its contract later in this header"
#endif

/* Is an address inside [KERNEL_VIRT_TEXT_MIN, KERNEL_VIRT_TEXT_MAX] necessarily
 * part of the kernel image or a module, so that ruling out the module band
 * leaves only the image?
 *
 * That window is the range in which the image base is ADMISSIBLE, not the
 * image's extent, so the answer is usually no: it spans the linear map on the
 * VMSPLIT arches and on ppc64, and s390's is the whole address space. Only
 * where the architecture places nothing else in that range can a bare address
 * be attributed to the image by its value alone.
 *
 * DECLARED rather than computed. Computing it means reasoning about
 * PAGE_OFFSET, and PAGE_OFFSET does not mean the same thing on every
 * architecture — it is 0 on s390, where the linear map is the identity map, and
 * on the VMSPLIT arches it names the split THIS binary was built with rather
 * than the target's, which is the substitution check-page-offset-substitution
 * exists to forbid. A declaration cannot make that mistake.
 *
 * Defaults to 0, so an architecture that has not considered the question gets
 * the safe answer: every range-classified address becomes
 * REGION_KERNEL_TEXT_BAND, which cannot bound the guaranteed window. Declaring
 * 1 is a claim about the address space, checked below against the one thing the
 * constants do say.
 *
 * Assessed for every architecture against the kernel's own layout headers. Note
 * what the assertion below can and cannot see: it tests the single PAGE_OFFSET
 * an arch header carries, so an arch whose kernel SELECTS that value at runtime
 * can satisfy it on the modelled value and violate it on another. riscv64 is
 * exactly that case, and is the reason this list is written out rather than
 * left to the assertion.
 *
 *   1  x86_64  — asm/page_64_types.h and pgtable_64_types.h put
 *                MODULES_VADDR at __START_KERNEL_map + KERNEL_IMAGE_SIZE, so
 *                the window IS [__START_KERNEL_map, MODULES_VADDR]: the image
 *                region, closed at the module boundary. The CPU entry area,
 *                vmalloc, vmemmap and vsyscall all fall outside it.
 *   0  riscv64 — vmalloc is below the linear map (asm/pgtable.h,
 *                VMALLOC_END == PAGE_OFFSET) but the LINEAR MAP is the
 *                occupant: asm/page.h selects PAGE_OFFSET at runtime from the
 *                VA mode, and PAGE_OFFSET_L3 (sv39) is 0xffffffd600000000 —
 *                40 GiB below KERNEL_VIRT_TEXT_MIN, growing upward with
 *                installed RAM. The header models the sv57 value, which clears
 *                the window by a wide margin; sv39 does not.
 *   0  arm64   — asm/pgtable.h has VMALLOC_START == MODULES_END ==
 * KIMAGE_VADDR, so vmalloc begins at the image and spans the window. 0  s390 —
 * vmalloc bounds are runtime variables, and the window here is effectively the
 * whole address space. 0  arm32, ppc32, x86_32, riscv32, mips32, mips64, ppc64,
 * loongarch64 — PAGE_OFFSET >= KERNEL_VIRT_TEXT_MIN, so the linear map starts
 *                inside the window; the assertion below rejects a 1 here.
 * The remaining headers (m68k, microblaze, openrisc, sh, sparc) exist for the
 * dispatch table and error at compile time, so the question does not arise. */
#ifndef TEXT_WINDOW_EXCLUSIVE
#define TEXT_WINDOW_EXCLUSIVE 0
#endif
/* The one part of that claim the constants can check. kasld_addr_is_directmap()
 * spans [PAGE_OFFSET, KERNEL_VIRT_TEXT_MIN), so an architecture whose linear
 * map begins inside the text window collapses that span to nothing and then
 * reports no direct-map match for any address at all — indistinguishable from
 * having no linear map. An arch in that state cannot be exclusive. */
#if TEXT_WINDOW_EXCLUSIVE
__extension__ _Static_assert((unsigned long)PAGE_OFFSET <
                                 (unsigned long)KERNEL_VIRT_TEXT_MIN,
                             "TEXT_WINDOW_EXCLUSIVE claims the text window "
                             "holds only the image and modules, but the linear "
                             "map begins inside it");
#endif
#ifndef MODULES_ANCHOR
#error                                                                         \
    "arch header must define MODULES_ANCHOR (MOD_ANCHOR_FIXED / _PAGE_OFFSET / _TEXT / _BRACKETS_TEXT)"
#endif
__extension__ _Static_assert(MODULES_ANCHOR == MOD_ANCHOR_FIXED ||
                                 MODULES_ANCHOR == MOD_ANCHOR_PAGE_OFFSET ||
                                 MODULES_ANCHOR == MOD_ANCHOR_TEXT ||
                                 MODULES_ANCHOR == MOD_ANCHOR_BRACKETS_TEXT,
                             "MODULES_ANCHOR must be one of the four "
                             "MOD_ANCHOR_* answers");
/* Derived, never declared: one anchor, so these cannot disagree. */
#define MODULES_RELATIVE_TO_TEXT (MODULES_ANCHOR == MOD_ANCHOR_TEXT)
#define MODULES_RELATIVE_TO_PAGE_OFFSET                                        \
  (MODULES_ANCHOR == MOD_ANCHOR_PAGE_OFFSET)
/* A typo'd or stale value would expand to 0 in an #if and silently match
 * nothing, so every consumer would fall to its else branch. Pin it to the three
 * declared answers. */
__extension__ _Static_assert(LINEAR_MAP_ANCHOR == LM_ANCHOR_PHYS_OFFSET ||
                                 LINEAR_MAP_ANCHOR == LM_ANCHOR_DRAM_BASE ||
                                 LINEAR_MAP_ANCHOR == LM_ANCHOR_UNKNOWABLE,
                             "LINEAR_MAP_ANCHOR must be one of the three "
                             "LM_ANCHOR_* answers");
/* A coupled arch cannot have an unknowable anchor. Text riding at a fixed
 * offset inside the linear map is what makes a physical bound projectable onto
 * the virtual text base, and that projection needs the anchor — so an arch
 * claiming the first while denying the second would put
 * text_base_coupling_synth in the position of projecting through a number it
 * cannot obtain. It holds on all twelve supported arches today; asserted
 * because that rule reads the coupling flag and takes a usable anchor for
 * granted rather than re-checking. */
__extension__ _Static_assert(!TEXT_TRACKS_DIRECTMAP ||
                                 LINEAR_MAP_ANCHOR != LM_ANCHOR_UNKNOWABLE,
                             "TEXT_TRACKS_DIRECTMAP arch must have a knowable "
                             "linear-map anchor");

/* ---- The linear-map base, as one axis ----------------------------------
 *
 * PAGE_OFFSET_MIN / PAGE_OFFSET_MAX bracket every linear-map base the
 * architecture admits. Required of every arch, and stated as literals rather
 * than derived: they appear in #if arithmetic and in static initialisers,
 * where a candidate array cannot be indexed.
 *
 * They exist because KERNEL_VIRT_VAS_START had quietly acquired this second
 * job, and it is not the same quantity. On mips64, loongarch64 and riscv64 the
 * kernel address space STARTS far below the linear map — VAS_START
 * 0x8000000000000000 against a PAGE_OFFSET of 0xffffffff80000000 on mips64 —
 * so reading it as "the lowest split" is wrong there, and right elsewhere only
 * by coincidence of which arches use it.
 *
 * The bracket is what Q_PAGE_OFFSET is resolved within, and it is an interval
 * on every architecture. An interval can represent any address between its
 * edges, so a base the target holds is at worst unresolved; an enumeration
 * would have to be complete for every kernel in scope, and a base missing from
 * it would be excluded outright.
 *
 * PAGE_OFFSET_CANDIDATES is the VMSPLIT boundary list, highest first, declared
 * ONLY where the base is a PRIMITIVE property of the build: a VMSPLIT choice,
 * or an architectural constant. It is what an observed kernel-text address is
 * snapped DOWN to in order to tell one split from another, and nothing reads it
 * as the set of admissible bases. Deliberately absent where the base is
 *
 *   DERIVED — arm64 and riscv64 compute it from the paging mode, which
 *     Q_VA_BITS already models as a finite set. A second list there would be
 *     two declarations obliged to agree, and riscv64's would additionally have
 *     to track kernel version (SV39 alone has had two bases). The coupling
 *     rule that maps one to the other is the single source of truth instead.
 *
 *   CONTINUOUS — x86_64 randomizes it (RANDOMIZE_MEMORY) and s390 shifts it;
 *     there is no set to enumerate.
 *
 * PAGE_OFFSET_KNOWN_AT_BUILD answers the question none of the older axes did:
 * can the ANALYSING BINARY know the target's linear-map base? That is distinct
 * from DIRECTMAP_STATIC, which asks whether the base moves at RUNTIME — a
 * property of the target kernel. A base can be perfectly static there and
 * still unknown here, which is exactly the x86_32 / arm32 VMSPLIT case. */
#ifndef PAGE_OFFSET_MIN
#error                                                                         \
    "arch header must define PAGE_OFFSET_MIN (lowest admissible linear-map base)"
#endif
#ifndef PAGE_OFFSET_MAX
#error "arch header must define PAGE_OFFSET_MAX (highest admissible base)"
#endif
#if PAGE_OFFSET_MIN > PAGE_OFFSET_MAX
#error "PAGE_OFFSET_MIN is above PAGE_OFFSET_MAX"
#endif
#if PAGE_OFFSET < PAGE_OFFSET_MIN || PAGE_OFFSET > PAGE_OFFSET_MAX
#error "the compile-time PAGE_OFFSET falls outside [PAGE_OFFSET_MIN, _MAX]"
#endif

/* Whether the boundary list exists, as a 0/1 an `#if` can combine with the
 * other axes. Not a statement about how Q_PAGE_OFFSET is represented — that is
 * an interval everywhere. */
#ifdef PAGE_OFFSET_CANDIDATES
#define PAGE_OFFSET_IS_FINITE 1
#else
#define PAGE_OFFSET_IS_FINITE 0
#endif

/* A bracket holding one address means this binary knows the target's base.
 * Any wider bracket means it does not, whatever the reason for the width. */
#define PAGE_OFFSET_KNOWN_AT_BUILD (PAGE_OFFSET_MIN == PAGE_OFFSET_MAX)

/* MODULES_RELATIVE_TO_PAGE_OFFSET is opt-in: an arch declares it 1 when its
 * module band is defined as a DELTA FROM PAGE_OFFSET rather than at fixed
 * addresses. Such an arch supplies MODULES_START_FOR(po) / MODULES_END_FOR(po)
 * -- the same arithmetic parameterised on PAGE_OFFSET -- so the orchestrator
 * can re-derive the band once the engine resolves it, and so the static macros
 * cannot drift from the relation they are an instance of.
 *
 * WHICH INSTANCE: the static MODULES_START/END must apply the relation at the
 * LOWEST PAGE_OFFSET the arch admits, not at the compile-time one. The two
 * differ wherever the split is a build choice the analysing binary cannot see
 * (arm32 and x86_32 VMSPLIT), and there the compile-time instance is a band
 * this binary's own default would have -- not the union the CONTRACT above
 * requires. It matters because the static macros are what
 * kasld_addr_is_module_band() enforces INSIDE each component, which runs
 * before the engine has resolved anything: a band drawn at the wrong split
 * discards every genuine module address at the source, and the orchestrator's
 * re-derivation comes too late to recover it. On every arch in scope the
 * lowest admissible split is KERNEL_VIRT_VAS_START, so that is the argument to
 * instantiate with; where PAGE_OFFSET cannot move the two coincide and the
 * choice is a no-op. The assertions below hold the property rather than the
 * spelling.
 *
 * Both accessors must stay integer CONSTANT EXPRESSIONS when applied to the
 * compile-time PAGE_OFFSET: MODULES_START/END appear in static initialisers and
 * in #if arithmetic.
 *
 * The default 0 means "the band is at fixed addresses": arches whose
 * PAGE_OFFSET cannot move, and MODULES_RELATIVE_TO_TEXT arches (whose band
 * follows the text base instead), are unaffected. */
#if MODULES_RELATIVE_TO_PAGE_OFFSET
#if !defined(MODULES_START_FOR) || !defined(MODULES_END_FOR)
#error "MODULES_RELATIVE_TO_PAGE_OFFSET=1 requires MODULES_START_FOR/END_FOR"
#endif
/* The union-vs-instance rule, enforced rather than merely documented: writing
 * the floor as the relation applied to the compile-time PAGE_OFFSET is the
 * mistake, and it is spelled almost identically to the correct form, so the
 * check has to be equality against the right argument. Both accessors are
 * monotone in PAGE_OFFSET, so this also fixes the floor as the widest the
 * relation can produce, whether it adds to PAGE_OFFSET or subtracts from it.
 * An arch needing a wider band widens the RELATION, which keeps the static
 * macros and the runtime projection describing the same geometry. */
#if MODULES_START != MODULES_START_FOR(KERNEL_VIRT_VAS_START)
#error "MODULES_START must instantiate the relation at the lowest split"
#endif
#if MODULES_END < MODULES_END_FOR(PAGE_OFFSET)
#error "MODULES_END is below the band's own ceiling at the compile-time split"
#endif
#endif

/* MODULES_BRACKET_TEXT is opt-in: an arch declares it as a byte size W when
 * its module allocator draws a window of at most W bytes that is GUARANTEED to
 * also contain the kernel image, then serves every module allocation from
 * inside that window. The consequence a rule can use is purely relative:
 *
 *   for every module allocation M:   |M - _text| < W
 *
 * so a single module address brackets the text base to a 2*W window, with no
 * dependence on where the band sits absolutely. That independence is the point
 * — it is what makes the axis usable on an arch whose static MODULES_START/END
 * are a wide multi-layout union rather than the live band.
 *
 * This is a DIFFERENT geometry from MODULES_RELATIVE_TO_TEXT, which means "the
 * band is at a fixed OFFSET from the text base" and yields a much tighter
 * bound via MODULES_END_TO_TEXT_OFFSET. An arch has one or the other, never
 * both; the default 0 means "no bracketing relation is claimed" and leaves
 * module_text_bracket inert.
 *
 * Soundness obligation on the arch: W must bound EVERY allocator path,
 * including fallbacks and the KASLR-disabled path, across every kernel version
 * the arch header claims to model. Understating W under-narrows the guaranteed
 * window and is a soundness bug, not a precision one. */
/* Admission and bounding are different obligations, which is why the band's
 * width and the trust placed in its edges are stated separately. Admission only
 * needs the band wide enough not to REJECT a real address; bounding also needs
 * its FLOOR low enough not to EXCLUDE one. A band whose floor moves at runtime
 * satisfies the first and fails the second.
 *
 * Declaring a level above ADMISSION requires its promise to hold under every
 * configuration the header models -- an arch whose base moves with the VA
 * width, the MMU, lowmem size or an allocator offset must not claim PINNED even
 * where its floor looks exact. See MODULES_BAND_STRENGTH above for the ladder.
 */
/* The level has a safe default, so a header that says nothing is silently
 * demoted to ADMISSION rather than rejected. That makes a half-finished
 * conversion invisible: the arch keeps a retired macro, declares no level, and
 * quietly stops bounding Q_MODULE_BASE -- a precision loss no test catches,
 * because every test asserts whatever the header declares. Name the retired
 * spellings so the omission fails the build of the arch that has it. */
#ifdef MODULES_BAND_EXACT
#error                                                                         \
    "MODULES_BAND_EXACT is retired -- declare MODULES_BAND_STRENGTH MOD_BAND_BOUNDS"
#endif
#ifdef MODULES_BASE_IS_BAND_FLOOR
#error                                                                         \
    "MODULES_BASE_IS_BAND_FLOOR is retired -- declare MODULES_BAND_STRENGTH MOD_BAND_PINNED"
#endif
#ifndef MODULES_BAND_STRENGTH
#define MODULES_BAND_STRENGTH MOD_BAND_ADMISSION
#endif
__extension__ _Static_assert(MODULES_BAND_STRENGTH == MOD_BAND_ADMISSION ||
                                 MODULES_BAND_STRENGTH == MOD_BAND_BOUNDS ||
                                 MODULES_BAND_STRENGTH == MOD_BAND_PINNED,
                             "MODULES_BAND_STRENGTH must be one of the three "
                             "MOD_BAND_* levels");
/* A PAGE_OFFSET-anchored band is re-derived from the resolved split, so its
 * compile-time edges describe only the compile-time split and cannot be trusted
 * beyond admission. The one cross-axis rule left: everything the ladder used to
 * need three #errors for is now the ordinal itself. */
#if MODULES_ANCHOR == MOD_ANCHOR_PAGE_OFFSET &&                                \
    MODULES_BAND_STRENGTH != MOD_BAND_ADMISSION
#error                                                                         \
    "a PAGE_OFFSET-anchored band is derived, so its compile-time edges are admission-only"
#endif

#ifndef MODULES_BRACKET_TEXT
#define MODULES_BRACKET_TEXT 0
#endif
/* The bracket width belongs to exactly one anchor, and MODULES_ANCHOR now makes
 * the exclusivity structural, so what remains is that the width and the anchor
 * agree: a width without the anchor is dead, an anchor without the width has no
 * geometry. */
__extension__ _Static_assert(
    (MODULES_BRACKET_TEXT > 0) == (MODULES_ANCHOR == MOD_ANCHOR_BRACKETS_TEXT),
    "MODULES_BRACKET_TEXT must be declared iff MODULES_ANCHOR is "
    "MOD_ANCHOR_BRACKETS_TEXT");

/* PHYS_OFFSET_EXACT is opt-in: an arch declares it 1 only when PHYS_OFFSET is
 * the genuine runtime linear-map physical base (see the contract banner). The
 * default 0 keeps the page_offset_base recovery inert on arches where the
 * offset is a placeholder, so a new arch cannot silently emit an unsound base.
 */
#ifndef PHYS_OFFSET_EXACT
#define PHYS_OFFSET_EXACT 0
#endif

/* PHYS_OFFSET_EXACT is the STRICTLY STRONGER claim, and the two are easy to
 * mistake for one question. LINEAR_MAP_ANCHOR says WHICH QUANTITY the anchor is
 * — the PHYS_OFFSET symbol, the DRAM base, or nothing reachable.
 * PHYS_OFFSET_EXACT says that the VALUE THIS BINARY COMPILED IN for that symbol
 * is also the target's. The first can hold while the second fails, whenever the
 * symbol is a per-platform constant: MIPS anchors the linear map at PHYS_OFFSET
 * (so LM_ANCHOR_PHYS_OFFSET) yet lets the platform set it — 0x08000000 on ip22
 * and pic32, 0x20000000 on ip28, or PFN_PHYS(ARCH_PFN_OFFSET) under
 * CONFIG_MIPS_AUTO_PFN_OFFSET — while KASLD compiles 0. So the implication runs
 * one way only, and asserting it is what stops the pair silently disagreeing.
 *
 * The converse is deliberately NOT asserted. x86_32, ppc64, loongarch64 and
 * s390 all anchor at a genuinely fixed 0 and could carry PHYS_OFFSET_EXACT=1;
 * they do not today, which costs precision (page_offset_from_leak and
 * proc_kcore stay inert there) and never soundness. Promoting them is a
 * deliberate per-arch decision with its own validation, not something to derive
 * from this axis. */
__extension__ _Static_assert(!PHYS_OFFSET_EXACT ||
                                 LINEAR_MAP_ANCHOR == LM_ANCHOR_PHYS_OFFSET,
                             "PHYS_OFFSET_EXACT requires the anchor to BE "
                             "PHYS_OFFSET");

/* Canonical directmap projections (both directions). Defined once here, gated
 * by the same predicate on every arch. Callers must use `#ifdef
 * phys_to_directmap_virt` or `#ifdef directmap_virt_to_phys` — unsound arches
 * don't get the macro, so forgetting the guard fails to compile rather than
 * silently emitting a wrong observation. Both macros are bijective on a
 * static linear map and share the same gate.
 *
 * The gate is PAGE_OFFSET_KNOWN_AT_BUILD, not DIRECTMAP_STATIC. Substituting
 * the compile-time PAGE_OFFSET is sound only where this binary knows the
 * target's base; that the target keeps it still is necessary but not
 * sufficient. On the VMSPLIT arches the two diverge, and projecting there
 * manufactures a direct-map address that is off by the difference between the
 * analysing build's split and the target's — an address indistinguishable from
 * a genuine leak once it reaches the evidence set, which the engine then reads
 * back as the base it was built from. Those arches get no macro, so every
 * caller falls to its existing decoupled branch and the linear map is
 * reconstructed from real leaks or not at all. */
#if PAGE_OFFSET_KNOWN_AT_BUILD
/* A directmap virtual address is by construction >= PAGE_OFFSET. A projection
 * where (p - PHYS_OFFSET) underflows or (+ PAGE_OFFSET) wraps the word -- a
 * high physical reserved region on a 32-bit arch -- is therefore not a
 * directmap address; it is discarded (0) so the VAS parser drops it rather than
 * admitting a below-PAGE_OFFSET phantom that could reject a true text leak. The
 * bijection holds only for a real linear-map input, so directmap_virt_to_phys
 * rejects any virtual below PAGE_OFFSET the same way. Kept as function-like
 * macros so the
 * `#ifdef phys_to_directmap_virt` gate at call sites still selects them. */
static inline unsigned long kasld__phys_to_directmap_virt(unsigned long p) {
  unsigned long v = (unsigned long)(p - PHYS_OFFSET + PAGE_OFFSET);
  if (v < (unsigned long)PAGE_OFFSET) /* wrapped below the linear-map base */
    return 0;
  return v;
}
static inline unsigned long kasld__directmap_virt_to_phys(unsigned long v) {
  if (v < (unsigned long)PAGE_OFFSET)
    return 0;
  return (unsigned long)(v - PAGE_OFFSET + PHYS_OFFSET);
}
#define phys_to_directmap_virt(p)                                              \
  kasld__phys_to_directmap_virt((unsigned long)(p))
#define directmap_virt_to_phys(v)                                              \
  kasld__directmap_virt_to_phys((unsigned long)(v))
#endif

/* Self-enforcing restatement of the gate above. Trivially satisfied as written,
 * and that is the point: widening the condition to any predicate that does not
 * imply PAGE_OFFSET_KNOWN_AT_BUILD breaks the build on the arches where the
 * substitution would be a guess, instead of quietly producing direct-map
 * addresses computed from the wrong base. Every caller is #ifdef-guarded WITH a
 * fallback, so removing the macro fails nothing at compile time — this is the
 * only compile-time backstop the projection has. */
#if defined(phys_to_directmap_virt) && !PAGE_OFFSET_KNOWN_AT_BUILD
#error                                                                         \
    "the compile-time directmap projection requires PAGE_OFFSET_KNOWN_AT_BUILD"
#endif

/* =========================================================================
 * Page-frame number conversion
 *
 * 1 iff this architecture admits exactly one page size, so a page-frame number
 * -- which counts the TARGET kernel's pages -- can be converted to a byte
 * address with a compile-time constant. Derived from the arch header's pair,
 * never declared: an arch cannot then claim a page size it does not admit, and
 * a mistyped axis value fails to compile instead of expanding to 0.
 *
 * Where the edges differ the multiplier is not knowable at build time, and the
 * error is not small: mips and loongarch64 reach 64 KiB and 32-bit powerpc
 * reaches 256 KiB, so a PFN converted at 4 KiB understates a physical address
 * by up to 64x. Understating the top of physical memory is precisely how a
 * bound derived from it lands past truth, which is why this is a gate rather
 * than a comment.
 * ========================================================================= */
#define PAGE_SIZE_KNOWN_AT_BUILD (PAGE_SIZE_MIN == PAGE_SIZE_MAX)

#if PAGE_SIZE_KNOWN_AT_BUILD
/* pfn_to_phys(pfn): first byte of the frame. phys_to_pfn(p): the frame holding
 * `p`. Defined ONLY where the page size is single-valued, so a conversion that
 * needs the target's runtime size cannot silently reach a constant instead:
 * the call does not compile on the arches where the constant would be wrong.
 * Callers must #ifdef and take SF_PAGE_SIZE on the other path.
 *
 * pfn_to_phys returns 0 on overflow rather than a wrapped address, so a caller
 * bounding a window from it cannot be handed a small number for a huge frame.
 */
static inline unsigned long kasld__pfn_to_phys(unsigned long pfn) {
  if (pfn > (unsigned long)-1 / (unsigned long)PAGE_SIZE_MIN)
    return 0;
  return pfn * (unsigned long)PAGE_SIZE_MIN;
}
static inline unsigned long kasld__phys_to_pfn(unsigned long p) {
  return p / (unsigned long)PAGE_SIZE_MIN;
}
#define pfn_to_phys(pfn) kasld__pfn_to_phys((unsigned long)(pfn))
#define phys_to_pfn(p) kasld__phys_to_pfn((unsigned long)(p))
#endif

/* Self-enforcing restatement of the gate above, in the same shape as the
 * directmap projection's. Trivially satisfied as written; widening the
 * condition to a predicate that does not imply PAGE_SIZE_KNOWN_AT_BUILD breaks
 * the build on the arches where the multiplier would be a guess, rather than
 * quietly producing physical addresses computed from the wrong page size. */
#if defined(pfn_to_phys) && !PAGE_SIZE_KNOWN_AT_BUILD
#error "pfn_to_phys requires PAGE_SIZE_KNOWN_AT_BUILD"
#endif

/* The linear-map base where this build genuinely knows it, 0 where it does not.
 *
 * For presentation. A renderer stating an address is asserting it, so it may
 * name the compile-time PAGE_OFFSET only where exactly one base is admissible
 * and that constant is therefore the runtime one. Everywhere else the honest
 * output is "unknown", never the link-time seed dressed as a measurement — that
 * regressed twice, once printing 0xc0008000 for a _text that was really at
 * 0x80008000. Returning 0 rather than a guess lets the caller fall through to
 * its own "not established" path.
 *
 * Exists so no renderer has to name PAGE_OFFSET at all: the licence lives here
 * once, in a name that states it, instead of being re-derived at each site from
 * whichever axes looked relevant. */
static inline unsigned long kasld_page_offset_if_known(void) {
#if PAGE_OFFSET_KNOWN_AT_BUILD
  return (unsigned long)PAGE_OFFSET;
#else
  return 0;
#endif
}

/* Conservative lower edges of Q_VIRT_IMAGE_BASE / Q_PHYS_IMAGE_BASE windows.
 *
 * KASLR_VIRT_TEXT_MIN / KASLR_PHYS_MIN can bake in configurable Kconfig values
 * (currently x86_64 with CONFIG_PHYSICAL_START) at their *default*. Real
 * kernels built with a smaller value place text below that floor, and the
 * engine's window then excludes truth. KASLR_VIRT_TEXT_MIN_WIDE /
 * KASLR_PHYS_MIN_WIDE are the *wider* variants — the smallest practical
 * value across all reasonable Kconfig choices on the arch — used by
 * quantities.c as the honest-top floor.
 *
 * Arches without configurable floors default these to KASLR_*_MIN
 * (no widening). The physical_start_lower_bound rule restores the tight
 * floor via a learned SF_PHYSICAL_START (CONF_PARSED) or the compile-time
 * default (CONF_HEURISTIC), overridable by any real evidence. */
#ifndef KASLR_VIRT_TEXT_MIN_WIDE
#define KASLR_VIRT_TEXT_MIN_WIDE KASLR_VIRT_TEXT_MIN
#endif
/* Honest-top ceiling counterpart: defaults to the KASLR window top; an arch
 * whose honest top must span more than one text-base layout (arm64 sub-48
 * VA_BITS) widens it. Widen-only — never below KASLR_VIRT_TEXT_MAX. */
#ifndef KASLR_VIRT_TEXT_MAX_WIDE
#define KASLR_VIRT_TEXT_MAX_WIDE KASLR_VIRT_TEXT_MAX
#endif
/* KASLR_PHYS_MIN_WIDE's default is deferred until after KASLR_PHYS_MIN is
 * resolved below — its guard tests defined(KASLR_PHYS_MIN), and most arches
 * only acquire KASLR_PHYS_MIN via the KERNEL_PHYS_DEFAULT chain further down.
 */

/* KASLR randomization window defaults (override per-arch when narrower) */
#ifndef KASLR_VIRT_TEXT_MIN
#define KASLR_VIRT_TEXT_MIN KERNEL_VIRT_TEXT_MIN
#endif
#ifndef KASLR_VIRT_TEXT_MAX
#define KASLR_VIRT_TEXT_MAX KERNEL_VIRT_TEXT_MAX
#endif
#ifndef KASLR_VIRT_ALIGN
#define KASLR_VIRT_ALIGN IMAGE_ALIGN
#endif

/* image_base_grid_align soundness gate. The rule snaps a resolved virtual
 * image-base bound to the KASLR grid, which is sound only if _text's residue
 * modulo KASLR_VIRT_ALIGN is an architectural constant (=
 * KERNEL_VIRT_TEXT_DEFAULT mod KASLR_VIRT_ALIGN) across every in-scope kernel:
 * true where KASLR places the base on the grid, or a fixed linker offset
 * guarantees it. 0 where the offset is config-dependent (arm32: TEXT_OFFSET
 * varies by config and _stext is padded to the section boundary), so snapping
 * could floor a bound below the true base.
 *
 * DECLARED BY EVERY ARCH HEADER; there is no default. A permissive one is the
 * wrong way round: the failure it admits is a bound raised PAST the true base,
 * which drops the truth out of the guaranteed window -- the one thing that
 * window promises. Sixteen of seventeen headers once took "the residue is
 * fixed" by silence, which is a claim about a kernel's linker layout that
 * nobody had made.
 *
 * State WHICH basis the answer rests on, because they are not equally strong:
 *
 *   by construction -- the residue is zero (the image starts on the granule),
 *     or the arch models no KASLR so the base is the compile-time default and
 *     the residue is right by definition. Nothing can drift.
 *   observed        -- the residue is non-zero and emerges from something the
 *     kernel is free to change, such as the size of a boot-code section. Real
 *     builds agreeing is evidence, not a guarantee, and 0 is the answer unless
 *     the sharpening is worth the risk.
 *
 * Enforced by the mandatory-macro block near the top of this header; there is
 * deliberately no #define here to fall back to. */

/* Physical firmware load offset (DRAM base -> phys image base). 0 where
 * firmware loads the image at the DRAM base; riscv64 overrides to 2 MiB
 * (OpenSBI). Defined here so the OpenSBI component (compiled for every arch)
 * builds everywhere; only riscv64 code uses a nonzero value, and generic rules
 * must not reference it. */
#ifndef RISCV_PHYS_LOAD_OFFSET
#define RISCV_PHYS_LOAD_OFFSET 0ul
#endif

#if defined(KERNEL_PHYS_MIN) && !defined(KERNEL_PHYS_DEFAULT)
#define KERNEL_PHYS_DEFAULT (KERNEL_PHYS_MIN + IMAGE_BASE_OFFSET)
#endif
#if !defined(KASLR_PHYS_MIN) && defined(KERNEL_PHYS_DEFAULT)
#define KASLR_PHYS_MIN KERNEL_PHYS_DEFAULT
#endif
/* Conservative lower edge of the Q_PHYS_IMAGE_BASE window (see the virtual
 * counterpart above). Must follow the KASLR_PHYS_MIN derivation: the guard is
 * evaluated eagerly, so placing it earlier would silently skip on every arch
 * that gets KASLR_PHYS_MIN from KERNEL_PHYS_DEFAULT, leaving the macro
 * undefined. Arches needing a wider floor (x86_64 CONFIG_PHYSICAL_START, s390
 * identity map) define KASLR_PHYS_MIN_WIDE themselves; the rest default to
 * KASLR_PHYS_MIN. */
#if defined(KASLR_PHYS_MIN) && !defined(KASLR_PHYS_MIN_WIDE)
#define KASLR_PHYS_MIN_WIDE KASLR_PHYS_MIN
#endif
#if !defined(KASLR_PHYS_MAX) && defined(KERNEL_PHYS_MAX)
#define KASLR_PHYS_MAX KERNEL_PHYS_MAX
#endif
#ifndef KASLR_PHYS_ALIGN
#define KASLR_PHYS_ALIGN IMAGE_ALIGN
#endif

/* KASLR_ALIGN_FIXED — 1 where KASLR_VIRT_ALIGN / KASLR_PHYS_ALIGN are the slot
 * granularity ITSELF rather than a minimum under a per-build one, so a count
 * taken over that grain is the size of the set the kernel drew from rather than
 * a ceiling over it.
 *
 * The distinction is the same one the alignment lattice carries (see
 * estimate.h): the granularity is proven from below by default, and a source
 * that establishes the value closes it from above as well. Here the source is
 * the architecture, for the arches whose placement code steps by a constant
 * with no config in it -- so no evidence is needed and every run on them can
 * state the value.
 *
 * Set it only after reading that architecture's placement code, and for BOTH
 * axes: kaslr_align_arch_default emits the physical and virtual constraints
 * alike, so a decoupled arch needs the physical base's granularity established
 * separately from the virtual one.
 *
 * Defaults to 0, which is the floor every architecture can honestly claim.
 * Omitting it -- or misspelling it, which expands to 0 -- costs precision in a
 * candidate count and never soundness in a window. */
#ifndef KASLR_ALIGN_FIXED
#define KASLR_ALIGN_FIXED 0
#endif

/* PAGE_OFFSET_FIXED — 1 when the direct-map base is a compile-time
 * architectural constant, so a virt_page_offset reconstructed from a direct-map
 * leak may be pinned to a single value; 0 when that base is runtime-variable
 * and such a reconstruction must stay a window. The base is variable on x86_64
 * (RANDOMIZE_MEMORY slides it) and on the decoupled arches whose linear-map
 * base tracks RAM/firmware placement (arm64 memstart_addr, riscv64
 * kernel_map.page_offset, s390 __identity_base). That predicate — the base
 * stays put at runtime — is exactly what DIRECTMAP_STATIC asserts, so
 * PAGE_OFFSET_FIXED IS DIRECTMAP_STATIC — one source of truth; two flags would
 * drift. Pinning a LEAKED base needs only that it not move, NOT that this build
 * know it in advance; the compile-time projection macros are the ones gated on
 * PAGE_OFFSET_KNOWN_AT_BUILD, which the VMSPLIT arches fail while still being
 * DIRECTMAP_STATIC. */
#define PAGE_OFFSET_FIXED DIRECTMAP_STATIC

/* STEXT_OFFSET — the head gap: _stext - _text (image base). The engine's one
 * virtual text quantity is the IMAGE BASE (_text); _stext is a projection,
 * _stext = _text + STEXT_OFFSET. This is distinct from IMAGE_BASE_OFFSET (the
 * alignment residue: where _text sits within its KASLR-alignment granule, used
 * only by the residue-aware floor). Zero on every arch where _text == _stext;
 * non-zero only where a fixed header precedes _stext (arm64 .head.text =
 * 0x10000).
 *
 * This compile-time constant is a FALLBACK. When the real _text symbol is
 * observable (proc_kallsyms emits it as a KERNEL_IMAGE base), the engine
 * anchors the image base on that symbol at runtime and STEXT_OFFSET is never
 * consulted — version-proof. The constant only bridges the gap for _stext-only
 * sources (e.g. /proc/iomem "Kernel code") and the _stext display projection
 * when no _text leak exists. Used at two edges: kasld_image_base_from() (IN),
 * _stext display (OUT).
 *
 * It is an ESTIMATE, not a bound: the gap this build most likely has, which is
 * what the two edges above want, since both feed the LIKELY answer. It must
 * never bound the guaranteed window -- STEXT_OFFSET_MIN and STEXT_OFFSET_MAX
 * are the sound floor and ceiling, and they are what the engine reads.
 *
 * The three are one value on an arch whose linker fixes the gap, and that is
 * the common case; the defaults collapse them so such an arch states one
 * number. Where they differ, keeping them apart is what stops a floor being
 * printed as a measurement, or an estimate being trusted as a bound. */
#ifndef STEXT_OFFSET
#define STEXT_OFFSET 0ul
#endif

/* STEXT_OFFSET_MAX — the largest the head gap can be on this arch.
 *
 * STEXT_OFFSET is only a usable conversion where the LINKER fixes the gap. It
 * does not everywhere:
 *
 *   arm32  .head.text is followed by ALIGN(1<<SECTION_SHIFT) under
 *          CONFIG_STRICT_KERNEL_RWX, so _stext is rounded up to a section
 *          boundary and the gap depends on where _text sits inside the granule
 *          -- 1 MiB with 2-level paging, 2 MiB under LPAE, and different again
 *          with CONFIG_ARM_MPU or another TEXT_OFFSET. Observed 0xf8000 on
 *          both a 6.12 and a 7.0 build, which is the ALIGN, not a constant.
 *   mips   head.S reserves `.fill 0x400` before EXPORT(_stext) -- a real
 *          constant, but `#ifndef CONFIG_NO_EXCEPT_FILL`, and five platforms
 *          select it (MIPS_GENERIC_KERNEL, BMIPS_GENERIC, BCM47XX, LANTIQ,
 *          MACH_LOONGSON64), where the gap is 0.
 *
 * So the gap is a RANGE: it lies in [STEXT_OFFSET_MIN, STEXT_OFFSET_MAX], and
 * STEXT_OFFSET is the value inside that range this build most likely has.
 * Where the two edges are equal the gap is exact and a _stext witness
 * determines the image base. Where they differ it only bounds it, and pinning
 * would put the guaranteed window a gap away from the truth -- which is what a
 * _stext-only arm32 kernel did: pinned to _stext, 0xf8000 above the real _text,
 * with the true base outside the window the tool called guaranteed.
 *
 * Both default to STEXT_OFFSET, so an arch whose linker fixes the gap states
 * one number and keeps the pin. */
#ifndef STEXT_OFFSET_MIN
#define STEXT_OFFSET_MIN STEXT_OFFSET
#endif
#ifndef STEXT_OFFSET_MAX
#define STEXT_OFFSET_MAX STEXT_OFFSET
#endif

/* STEXT_OFFSET_MAX may also say the gap has no ceiling this side can state.
 *
 * loongarch64 is the case: _stext is ALIGN(sizeof(.head.text), 64K) above _text
 * (PECOFF_SEGMENT_ALIGN), so the gap is a multiple of 64 KiB set by however
 * much head code the build has, and HEAD_TEXT_SECTION fixes no size. arm32's
 * ceiling is real -- SECTION_SHIFT is at most 21, capping it at 2 MiB -- but
 * there is no equivalent here, and a chosen number would be a guess with a
 * soundness claim attached, which is the failure this range exists to remove.
 *
 * Unbounded means a _stext witness gives the upper edge only: _text <= _stext,
 * true for any gap. The lower edge comes from whatever else the engine holds.
 */
#define KASLD_STEXT_GAP_UNBOUNDED (~0ul)

/* STEXT_GAP_CANDIDATES — the gap is a SET, where an arch can close one.
 *
 * The range above states how far the gap can reach. It does not say the gap can
 * take every value in between, and on the arches that widened it, it cannot:
 * the gap is an ALIGN over a handful of config values, so the admissible bases
 * are a few points rather than a span. Stating the range alone throws that
 * away, and the cost is real -- on arm64 a _stext witness bounds the base to 31
 * grid positions where only two are reachable.
 *
 * An arch that can enumerate its gaps declares them here, lowest first, and the
 * two edges are derived from the list so the three cannot disagree. The engine
 * then carves the space between consecutive candidates out of the estimate,
 * which is sound for the same reason the range is: every configuration the arch
 * admits is still inside.
 *
 * The bar for declaring one is COMPLETENESS over every configuration, not over
 * the ones that have been seen. An incomplete set is worse than the range it
 * replaces, because it excludes a real build while looking tight -- the exact
 * failure the widening removed. Where a gap depends on something the header
 * cannot close (arm32's TEXT_OFFSET varies with CONFIG_ARM_MPU; loongarch64's
 * head section has no fixed size), leave it enumerated by nothing and keep the
 * range. Same shape as PAGE_OFFSET_CANDIDATES, which sits beside
 * PAGE_OFFSET_MIN/MAX for the same reason. */
#ifdef STEXT_GAP_CANDIDATES
#define STEXT_GAP_ENUMERATED 1
#else
#define STEXT_GAP_ENUMERATED 0
#endif

/* 1 when a _stext witness determines the image base, 0 when it only bounds it.
 * Keyed on the two SOUND edges: the estimate sits between them and says nothing
 * about whether the gap is fixed. */
#define STEXT_GAP_EXACT                                                        \
  ((unsigned long)STEXT_OFFSET_MAX == (unsigned long)STEXT_OFFSET_MIN)

/* 1 when the gap has a stated ceiling, so the witness gives both edges. */
#define STEXT_GAP_BOUNDED                                                      \
  (!STEXT_GAP_EXACT &&                                                         \
   (unsigned long)STEXT_OFFSET_MAX != KASLD_STEXT_GAP_UNBOUNDED)

/* The estimate must lie inside the sound range, or a consumer reading it would
 * contradict one that reads the edges. Checked here rather than trusted: the
 * three are set in separate places in each arch header and drift silently. */
#if STEXT_OFFSET_MIN > STEXT_OFFSET
#error "STEXT_OFFSET_MIN exceeds STEXT_OFFSET: the estimate is below the floor"
#endif
#if STEXT_OFFSET_MAX != KASLD_STEXT_GAP_UNBOUNDED &&                           \
    STEXT_OFFSET > STEXT_OFFSET_MAX
#error                                                                         \
    "STEXT_OFFSET exceeds STEXT_OFFSET_MAX: the estimate is above the ceiling"
#endif

/* Alignment granularity the kernel randomizes the CONFIG_RANDOMIZE_MEMORY
 * region bases (direct map / vmalloc / vmemmap) to — kernel_randomize_memory()
 * places each on a PUD_SIZE boundary on x86_64. Used only to report the
 * residual positional entropy of a bounded region base (window / align =
 * candidate positions). 0 = the arch does not randomize these regions, so no
 * entropy is reported. */
#ifndef RANDOMIZE_MEMORY_ALIGN
#define RANDOMIZE_MEMORY_ALIGN 0
#endif

/* 1 iff the compile-time PAGE_OFFSET is the GUARANTEED runtime value on this
 * arch — i.e. virt_page_offset cannot vary by config
 * (VMSPLIT/CONFIG_PAGE_OFFSET), paging mode (arm64 VA_BITS, riscv SATP), or
 * randomization (x86_64 RANDOMIZE_MEMORY, s390). Only then is pinning
 * Q_PAGE_OFFSET to PAGE_OFFSET sound with no evidence. Set per-arch (mips
 * CKSEG0, ppc64 book3s linear base); defaults to 0 (the honest window is kept
 * until a landmark/probe resolves it).
 */
#ifndef PAGE_OFFSET_INVARIANT
#define PAGE_OFFSET_INVARIANT 0
#endif

/* 1 where the mmap user/kernel split (TASK_SIZE) equals PAGE_OFFSET exactly, so
 * a TASK_SIZE measurement (mmap_brute_vmsplit) bounds PAGE_OFFSET soundly. Set
 * only on x86_32 (page_32_types.h: TASK_SIZE == __PAGE_OFFSET). Defaults to 0 —
 * notably arm32, where TASK_SIZE = PAGE_OFFSET - 16 MiB sits a gap below it. */
#ifndef TASK_SIZE_IS_PAGE_OFFSET
#define TASK_SIZE_IS_PAGE_OFFSET 0
#endif

/* 1 iff CONFIG_PAGE_OFFSET is the AUTHORITATIVE runtime virt_page_offset on
 * this arch — i.e. virt_page_offset is a pure compile-time constant set by the
 * config/VMSPLIT and cannot be overridden at boot. True on x86_32/arm32/ppc32
 * (user/kernel split is fixed at build). NOT true on riscv64
 * (CONFIG_PAGE_OFFSET reflects the built SATP mode but the kernel may boot a
 * narrower mode) or arm64 (VA_BITS), so those must use the runtime probe, not
 * the config. Defaults to 0. */
#ifndef PAGE_OFFSET_FROM_CONFIG
#define PAGE_OFFSET_FROM_CONFIG 0
#endif

/* "KASLR-off ⇒ engine pins virt text base to the arch default" contract.
 *
 * On arches where this is 1, the absence of KASLR (nokaslr cmdline, kernel
 * compiled without CONFIG_RANDOMIZE_BASE, or an arch-specific equivalent) means
 * the kernel sits at the address returned by `arch_default_text_base()` below.
 * The virt_kaslr_disabled_pin rule pins Q_VIRT_IMAGE_BASE to that value when
 * SF_VIRT_KASLR_DISABLED is present, with a window-containment backstop
 * that refuses to pin if the computed default falls outside the honest
 * window (a misconfig the arch_default_text_base() formula does not model).
 *
 * MUST stay 0 (default) where pinning to a single compile-time default would be
 * wrong: arches whose bootloader can relocate the image even without KASLR
 * (CONFIG_RELOCATABLE in practice — x86_32, arm32, ppc, mips), and arches whose
 * no-KASLR base is layout-dependent and resolved by a bespoke rule instead
 * (riscv64: linear-map vs KERNEL_LINK_ADDR text — see rule_riscv64_text_base).
 * An arch that sets this explicitly, either way, states why beside the define:
 * raising it, or declining to raise it despite having a KASLR-off signal to act
 * on. */
#ifndef KASLR_DISABLED_PINS_VIRT_TEXT
#define KASLR_DISABLED_PINS_VIRT_TEXT 0
#endif

/* Per-arch derivation of the no-KASLR text base. Default stub never used (the
 * rule is gated on KASLR_DISABLED_PINS_VIRT_TEXT, which is 0 here). Arch
 * headers override with the actual constant. If a future arch needs to derive
 * this from engine-resolved quantities (PAGE_OFFSET, VA_BITS,
 * CONFIG_PHYSICAL_START …), extend the signature and add dependency gating to
 * the rule then. */
#ifndef KASLD_ARCH_DEFAULT_TEXT_BASE_DEFINED
static inline unsigned long arch_default_text_base(void) { return 0; }
#endif

/* Pin contract for the *physical* text base under KASLR-off. Parallel axis to
 * KASLR_DISABLED_PINS_VIRT_TEXT and orthogonal to it: virt and phys KASLR
 * offsets are not always linked, so per-arch reality decides per-quantity.
 *
 * 1 (locked) on arches where SF_PHYS_KASLR_DISABLED proves the kernel sits
 * at the compile-time physical default — i.e. the kernel's own
 * decompressor/relocator respects nokaslr for BOTH virt and phys:
 *   x86_64 (choose_random_location returns early; image stays at
 *           CONFIG_PHYSICAL_START)
 *   loongarch64 (kaslr_disabled() short-circuits relocate.c; image stays at
 *           VMLINUX_LOAD_ADDRESS = PAGE_OFFSET + IMAGE_BASE_OFFSET)
 *
 * MUST stay 0 (default) where the phys load is bootloader / platform /
 * memstart-determined and not a fixed compile-time value, even when
 * SF_PHYS_KASLR_DISABLED is true:
 *   arm64 (memstart_addr from DT/EFI; no compile-time default)
 *   riscv64 (DRAM_BASE varies by platform — QEMU virt 0x80000000,
 *            StarFive 0x40000000, ...)
 *   s390 (independent __kaslr_offset_phys; the fact may be true but the
 *         phys placement is not pinnable to a compile-time default) */
#ifndef KASLR_DISABLED_PINS_PHYS
#define KASLR_DISABLED_PINS_PHYS 0
#endif

/* Per-arch derivation of the no-KASLR physical text base. Parallel to
 * arch_default_text_base(). Default stub never used (the rule is gated on
 * KASLR_DISABLED_PINS_PHYS, which is 0 here). Arch headers override only when
 * KASLR_DISABLED_PINS_PHYS=1. */
#ifndef KASLD_ARCH_DEFAULT_PHYS_TEXT_BASE_DEFINED
static inline unsigned long arch_default_phys_text_base(void) { return 0; }
#endif

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <unistd.h>

/* Filesystem-fact reads route through the KASLD_SYSROOT redirection layer so a
 * copied filesystem tree can be analyzed offline. api.h is kasld's universal
 * include root, so pulling it here makes the wrappers visible in every
 * translation unit. */
#include "sysroot.h"

/* Parse an address out of kernel-supplied text.
 *
 * `base` is strtoul's (16 for the usual bare hex, 0 to honour a 0x prefix, 10
 * for the decimal fields in /proc/<pid>/stat and the iscsi transport handle).
 * Returns 1 and stores the value on success. Returns 0 — leaving *out
 * untouched — when the field holds no digits, holds a sign, or holds an address
 * too wide for this build's word. When `end` is non-NULL it receives the first
 * unconsumed character, so a caller walking a line can still step past a field
 * it rejected; on a no-digits or signed failure that is the original start, so
 * a moved end pointer means digits were consumed (see
 * kasld_addr_refused_wide).
 *
 * Width is the point. An address the analysing build cannot represent is not a
 * parse error to paper over: a 32-bit binary reading a PAE `/proc/iomem`, or
 * any 64-bit kernel, is being handed values it has no room for. Truncating one
 * yields a plausible wrong address that enters the evidence set at the same
 * confidence as a correct one — `sscanf("%lx")` on "100000000-13fffffff"
 * reports success and hands back 0x0-0x3fffffff. Parsing at 64-bit width and
 * range-checking against the word makes that unrepresentable value a refusal
 * instead, which the caller can report honestly. */
/* After a failed kasld_addr_parse, tells a field that held digits this build
 * cannot represent apart from one that held no digits at all. `end` is the
 * pointer the failed parse reported.
 *
 * The distinction matters to any caller accumulating an aggregate: a merely
 * malformed field says nothing, while one that was too wide means a real span
 * exists above everything gathered so far, and a bound derived from that
 * aggregate would understate it. */
static inline int kasld_addr_refused_wide(const char *s, const char *end) {
  return end != NULL && end != s;
}

static inline int kasld_addr_parse(const char *s, int base, kasld_addr_t *out,
                                   const char **end) {
  const char *p = s;
  /* strtoull skips leading whitespace, which callers rely on, but it also
   * accepts a sign and NEGATES: "-1" converts to ULLONG_MAX with no ERANGE, so
   * a signed field would be reported as a successful parse of a huge address —
   * exactly the plausible-wrong-value this refuses everywhere else. An address
   * field never carries a sign, so stop before one. */
  while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == '\f' ||
         *p == '\v')
    p++;
  if (*p == '-' || *p == '+') {
    if (end)
      *end = s;
    return 0;
  }

  char *e;
  errno = 0;
  unsigned long long v = strtoull(p, &e, base);
  if (e == p) {
    /* No digits at all. Report the ORIGINAL start, not the position after the
     * whitespace: a caller distinguishes "held nothing" from "held something
     * too wide" by whether the end pointer moved, and skipped blanks are not
     * progress. */
    if (end)
      *end = s;
    return 0;
  }
  if (end)
    *end = e;
  if (errno == ERANGE)
    return 0;
  if (v > (unsigned long long)(kasld_addr_t)-1)
    return 0; /* wider than this build's address type */
  *out = (kasld_addr_t)v;
  return 1;
}

/* Generic [lo, hi] half-open or inclusive range; semantics decided by the
 * caller. Used by component-side region accumulators (dmesg_* parsers,
 * sysfs walkers) that aggregate per-line spans before emitting a result. */
struct addr_range {
  unsigned long lo;
  unsigned long hi;
  /* Set when a span could not be represented in the word and was dropped. The
   * aggregate is then partial in a known direction — an unrepresentable span
   * lies above every representable one — so `lo` remains a sound floor while
   * `hi` understates the top and must not be published as a ceiling. */
  int incomplete;
};

/* MIPS64 XKPHYS: a 64-bit virtual address with bits [63:62] == 0b10 is a
 * hardware direct physical mapping. Bits [61:59] are the Cache Coherency
 * Attribute; bits [58:0] are the physical address (up to 2^59). A leaked
 * XKPHYS address looks like an ordinary kernel pointer but is really PHYS — the
 * observation boundary decodes it so it is never mistaken for a directmap VIRT
 * leak (which would let virt_page_offset synthesis derive a bogus PAGE_OFFSET).
 * Pure bit math; the WHEN (mips64 only) is the caller's gate. Ref:
 * arch/mips/include/asm/addrspace.h; MIPS64 PRA Vol. III §4.3. */
static inline int kasld_addr_is_xkphys(unsigned long va) {
  /* Shift via a 64-bit type: on 32-bit arches `unsigned long` is 32 bits, where
   * XKPHYS cannot exist (a 32-bit address has no bit 63) and `va >> 62` would
   * be a shift-count-overflow. The zero-extended value yields 0 there,
   * correctly. */
  return ((unsigned long long)va >> 62) == 2ull;
}
static inline unsigned long kasld_xkphys_to_phys(unsigned long va) {
  return (unsigned long)((unsigned long long)va &
                         0x07ffffffffffffffull); /* strip
                                                    marker[63:62]+CCA[61:59] */
}

/* Predicate: is `addr` in the half-open window [lo, hi)? Returns 0 for an empty
 * or inverted window (lo >= hi). Predicate: is `addr` in the closed range
 * [lo, hi]?  Both take the bounds as parameters on purpose: a per-arch bound
 * that folds to 0 / the type's max (e.g. PAGE_OFFSET, MODULES_START) would
 * otherwise turn the comparison into a compile-time tautology at the call site
 * (-Wlogical-op / -Wtype-limits). Routing the per-arch window checks through
 * these helpers keeps them honest and centralises the empty-window degradation.
 *
 * Bounds are unsigned long long: a physical-address range can legitimately
 * exceed the platform word on 32-bit arches (e.g. MAX_PLAUSIBLE_KERNEL_PHYS =
 * 1<<50), and an `unsigned long` parameter would silently truncate it.
 * Virtual-address callers pass `unsigned long`, which promotes losslessly.
 * Pure arithmetic; safe in any TU. */
static inline int kasld_addr_in_window(unsigned long long addr,
                                       unsigned long long lo,
                                       unsigned long long hi) {
  return lo < hi && addr >= lo && addr < hi;
}
static inline int kasld_addr_in_range(unsigned long long addr,
                                      unsigned long long lo,
                                      unsigned long long hi) {
  return addr >= lo && addr <= hi;
}

#if MODULES_RELATIVE_TO_PAGE_OFFSET
/* Guard for projecting the module band onto a resolved PAGE_OFFSET.
 *
 * MODULES_START_FOR either adds to PAGE_OFFSET or subtracts from it, so the
 * arithmetic can wrap at whichever end of the address space it moves toward: a
 * subtracting relation underflows past 0 when the split reaches the lowest one
 * admissible, an adding relation overflows past ULONG_MAX. Both present the
 * same way -- the projected floor lands on the far side of the PAGE_OFFSET it
 * was derived from. Which side that is depends only on the relation, so the
 * test is a compile-time constant and folds away.
 *
 * A wrapped floor is rejected, never clamped: on an arch that carves the band
 * out of the address space below PAGE_OFFSET, clamping to the bottom of the
 * kernel VAS collapses the band onto a point and rejects every genuine module
 * leak. */
static inline int kasld_module_band_floor_sane(unsigned long po,
                                               unsigned long floor) {
  return ((unsigned long)MODULES_START_FOR((unsigned long)PAGE_OFFSET) <=
          (unsigned long)PAGE_OFFSET)
             ? floor <= po
             : floor >= po;
}
#endif

/* Predicate: is `va` plausibly inside the kernel module BAND on this arch?
 *
 * Wraps the MODULES_START/END validation union (see the CONTRACT in the
 * arch-header contract banner above). Centralising the check here means the
 * per-arch widening / future per-version handling lives in one place.
 *
 * Two different uses, and the difference decides the region tag. A source that
 * already KNOWS it read a module's address (proc_modules,
 * sysfs_module_sections) uses this only as a sanity filter and still emits
 * REGION_MODULE. A source holding a bare pointer uses it to CLASSIFY, and must
 * emit REGION_MODULE_BAND — membership in the band is not evidence that an
 * address is a module, since the band overlaps other regions on several arches
 * (see the region note by the region table). */
static inline int kasld_addr_is_module_band(unsigned long va) {
  return kasld_addr_in_range(va, (unsigned long)MODULES_START,
                             (unsigned long)MODULES_END);
}

/* Predicate: is `va` plausibly a kernel direct-map (lowmem) address — in
 * [PAGE_OFFSET, KERNEL_VIRT_TEXT_MIN)? On coupled/inverted arches where the
 * direct map and kernel text meet or cross, the window is empty, so those
 * arches naturally yield no direct-map match (they have a fixed, non-randomized
 * page_offset and nothing to leak here). */
static inline int kasld_addr_is_directmap(unsigned long va) {
  return kasld_addr_in_window(va, (unsigned long)PAGE_OFFSET,
                              (unsigned long)KERNEL_VIRT_TEXT_MIN);
}

/* Predicate: is `va` in the kernel text window [KERNEL_VIRT_TEXT_MIN,
 * KERNEL_VIRT_TEXT_MAX]? The closed upper bound matches the "maximum plausible
 * kernel text address" contract (banner above) and the module/directmap
 * predicates:
 * a leaked virtual address is plausibly kernel text when it lands here. */
static inline int kasld_addr_is_kernel_text(unsigned long va) {
  return kasld_addr_in_range(va, (unsigned long)KERNEL_VIRT_TEXT_MIN,
                             (unsigned long)KERNEL_VIRT_TEXT_MAX);
}

/* Predicate: is `va` anywhere in the kernel virtual address space
 * [KERNEL_VIRT_VAS_START, KERNEL_VIRT_VAS_END]? Broader than the text and
 * direct-map windows — used to reject user-space pointers before (or in place
 * of) finer classification. */
static inline int kasld_addr_is_kernel_vas(unsigned long va) {
  return kasld_addr_in_range(va, (unsigned long)KERNEL_VIRT_VAS_START,
                             (unsigned long)KERNEL_VIRT_VAS_END);
}

/* Given an interior virtual kernel-text address `addr` (so image_base <= addr),
 * return the tightest sound aligned upper bound on the text base.
 *
 * The base is KASLR_VIRT_ALIGN-aligned only *up to a fixed sub-offset*: a KASLR
 * slide is a whole multiple of KASLR_VIRT_ALIGN, so the base's low bits always
 * equal KERNEL_VIRT_TEXT_DEFAULT mod KASLR_VIRT_ALIGN (0 on
 * x86_64/arm64/ppc/s390/loongarch64; 0x2000 on riscv64; 0x8000 on arm32; ...).
 * A plain `addr & -KASLR_VIRT_ALIGN` drops *below* the real base on the
 * sub-offset arches — an UNSOUND upper bound that wrongly rejects the true
 * base. This returns the largest value <= addr carrying the correct sub-offset
 * (which is exactly the floor when the sub-offset is 0). It is the single
 * sanctioned way to align a leaked text pointer to a base estimate — components
 * must not roll their own `& -ALIGN`. */
/* Pure, parameterised core: the largest value <= addr that is congruent to
 * (default_base mod align) modulo align. `align` must be a non-zero power of
 * two. Split out as a pure function of (align, default_base) so the sub-offset
 * arithmetic is independent of the arch macros.
 * Callers should use kasld_floor_text_base(), which binds the arch macros. */
static inline unsigned long
kasld_floor_aligned_suboffset(unsigned long addr, unsigned long align,
                              unsigned long default_base) {
  unsigned long sub = default_base & (align - 1);
  unsigned long v = (addr & ~(align - 1)) + sub;
  if (v > addr)
    v -= align;
  return v;
}

static inline unsigned long kasld_floor_text_base(unsigned long addr) {
  return kasld_floor_aligned_suboffset(addr, (unsigned long)KASLR_VIRT_ALIGN,
                                       (unsigned long)KERNEL_VIRT_TEXT_DEFAULT);
}

/* Mirror of kasld_floor_aligned_suboffset: the SMALLEST value >= addr congruent
 * to (default_base mod align) modulo align. Used to raise a lower bound on the
 * image base up to the first grid position >= it — sound because _text is on
 * that grid, so any grid candidate >= addr is also >= this result. */
static inline unsigned long
kasld_ceil_aligned_suboffset(unsigned long addr, unsigned long align,
                             unsigned long default_base) {
  unsigned long v = kasld_floor_aligned_suboffset(addr, align, default_base);
  if (v < addr)
    v += align;
  return v;
}

static inline unsigned long kasld_ceil_text_base(unsigned long addr) {
  return kasld_ceil_aligned_suboffset(addr, (unsigned long)KASLR_VIRT_ALIGN,
                                      (unsigned long)KERNEL_VIRT_TEXT_DEFAULT);
}

/* Engine-rule variant: floor a bound on the VIRTUAL kernel image base (_text)
 * to the RESOLVED alignment `align` (Q_VIRT_KASLR_ALIGN, which boot_params can
 * raise), preserving _text's alignment residue -- KERNEL_VIRT_TEXT_DEFAULT mod
 * align, NOT IMAGE_BASE_OFFSET, which is a different quantity on s390 and
 * loongarch64 -- so the result never drops below _text on arches where _text
 * isn't granule-aligned (riscv64 +0x2000, arm32 +0x8000, ...). This is the
 * single sanctioned way for a rule to floor a virt text-base bound; a bare `&
 * ~(align - 1)` is unsound there. A no-op floor where the residue is 0. The
 * phys axis needs no equivalent: the phys base carries no usable residue. */
static inline unsigned long kasld_floor_virt_text_bound(unsigned long v,
                                                        unsigned long align) {
  if (align == 0)
    return v;
  return kasld_floor_aligned_suboffset(v, align,
                                       (unsigned long)KERNEL_VIRT_TEXT_DEFAULT);
}

/* Normalise an observed kernel-base address to the IMAGE BASE (_text), the
 * engine's one virtual/physical text quantity. A KERNEL_TEXT base witness is
 * _stext (e.g. /proc/kallsyms _stext, /proc/iomem "Kernel code"), so subtract
 * the head gap; a KERNEL_IMAGE base witness already is the image base. The
 * single IN edge for STEXT_OFFSET (a no-op where the gap is 0). */
static inline unsigned long kasld_image_base_from(unsigned long base,
                                                  int base_is_stext) {
  if (!base_is_stext)
    return base;
  /* Compute then check the subtraction did not wrap. Doing it this way (rather
   * than `base >= STEXT_OFFSET`) keeps it warning-clean where STEXT_OFFSET is
   * 0, which would otherwise be an `unsigned >= 0` tautology (-Wtype-limits).
   */
  unsigned long img = base - (unsigned long)STEXT_OFFSET;
  return img <= base ? img : base;
}

/* =========================================================================
 * Result model: (extent, position, confidence) over a typed region
 * =========================================================================
 *
 * Tagged wire format:
 *   <type> <region>[:<name>] pos=<pos> conf=<conf> \
 *       [lo=<hex>] [hi=<hex>|sz=<hex>] [sample=<hex>] [base_align=<hex>]
 *
 *   type:    P (physical), V (virtual). Scalar system facts use the parallel
 *            `S <fact> conf=<c> value=<hex>` record (see kasld_emit_scalar).
 *   region:  closed vocabulary; see enum kasld_region
 *   name:    specific instance, when known (kernel symbol, module name,
 *            ACPI OEM ID, PCI BDF). Region:name splits on the FIRST `:`
 *            only — names may legitimately contain `:` (e.g. PCI BDF
 *            "0000:00:14.0").
 *   pos:     base | top | interior | unknown (what `sample` represents)
 *   conf:    parsed | derived | inferred | heuristic | timing | brute
 *
 * Components emit results via the kasld_result_* helpers. Each helper
 * picks one combination of bounds + sample + position. Components author
 * the helper that matches what they actually know — there is no path to
 * accidentally over-claim. There is no `_exact` helper — "exact" was a
 * precision conflation; precision lives in trust (`conf`) + bounds width.
 * ========================================================================= */

/* Wire-field widths — the single source of truth for the name/origin field
 * sizes, shared by every layer that carries them (result records, observations,
 * constraints). Defined here in the common ancestor header so the two sides of
 * the wire protocol cannot skew: a change here propagates everywhere, rather
 * than being silently first-include-wins across separate #ifndef copies. */
#define NAME_LEN 48   /* specific instance: kernel symbol, ACPI ID, BDF, ... */
#define ORIGIN_LEN 64 /* emitting component / rule name */

/* Address type. */
enum kasld_addr_type {
  KASLD_TYPE_UNKNOWN = 0,
  KASLD_TYPE_PHYS,
  KASLD_TYPE_VIRT,
};

/* Position: what does `sample` represent within the region's extent?
 * (Bounds-set-ness is carried independently in the HAS_LO/HAS_HI flags
 * — never derive "lo is known" from pos.) */
enum kasld_position {
  POS_UNKNOWN = 0,
  POS_BASE,
  POS_TOP,
  POS_INTERIOR,
  /* Member of a COMPLETE, single-source covering of the region (a map) — e.g.
   * one E820 / device-tree / hotplug-block RAM extent. Makes no positional
   * claim; its value is in the SET (the gaps between extents). The orchestrator
   * routes these out-of-band of the cross-source merge into the engine's
   * coverings[] so the map stays faithful and attributable. */
  POS_EXTENT,
};

/* Confidence: how reliable is the source of this claim?
 * Strictly a *trust* ordering, not a precision ordering — precision lives
 * in the width of [lo, hi]. PARSED > DERIVED > INFERRED > HEURISTIC >
 * TIMING > BRUTE. CONF_UNKNOWN = 0 is the memset-default; every wire
 * emission must declare a real confidence (UNKNOWN is rejected on the
 * wire and at the helper boundary). */
enum kasld_confidence {
  CONF_UNKNOWN = 0,
  CONF_BRUTE,
  CONF_TIMING,
  CONF_HEURISTIC,
  CONF_INFERRED,
  CONF_DERIVED,
  CONF_PARSED,
};

/* Region table — single source of truth for the closed enum vocabulary.
 *
 * One row per region, expanded into the enum (kasld_region), the
 * wire-name lookup (kasld_region_wire_table[]), and the per-region
 * descriptor (region_info[] in src/region_info.c) via X-macros.
 *
 * Row format: X(enum_id, wire_name, section_name, vas_kind)
 *
 *   enum_id      Full enum identifier (REGION_RAM, ...). Spelled in full so
 *                grep "REGION_RAM" lands on the definition.
 *   wire_name    Lowercase snake_case token used on the IPC line.
 *   section_name Render grouping ("dram" / "mmio" / "text" / ...).
 *                "" for the unknown sentinel; never appears in render.
 *   vas_kind     One of K_OPEN, K_VIRT, K_PAGEOFFSET, K_MODULE — selects
 *                the {static_vas, derive_vas} pair via VAS_<kind>_STATIC
 *                / VAS_<kind>_DERIVE in region_info.c. The K_ prefix is
 *                deliberate: arch headers define names like PAGE_OFFSET
 *                and would collide on the `kind` argument before
 *                token-pasting under the bare names.
 *                  K_OPEN       — {0, ULONG_MAX}, NULL (any phys address)
 *                  K_VIRT       — {KERNEL_VIRT_VAS_START, KERNEL_VIRT_VAS_END},
 * NULL (kernel-VAS-bounded virtual-only regions) K_PAGEOFFSET — {0, 0},
 * derive_vas_page_offset (PAGE_OFFSET itself; layout-derived) K_MODULE     —
 * coupled vs decoupled handled in region_info.c via #if !TEXT_TRACKS_DIRECTMAP
 *
 * Adding a region: add one row here. The enum value, the wire-name entry,
 * and the region_info[] entry all get generated. REGION__COUNT auto-sizes
 * the arrays — compile fails if anything is out of sync.
 *
 * REGION_UNKNOWN = 0 is the memset-default and is intentionally NOT in
 * the X-list: it's the sentinel, hardcoded with empty section and
 * {0, 0}/NULL VAS so result_in_bounds() short-circuits. */
#define KASLD_REGION_LIST(X)                                                     \
  /* ---- Physical landmarks (DRAM-resident and MMIO) -------------------- */    \
  X(REGION_RAM, "ram", "dram", K_OPEN)                                           \
  X(REGION_DMA, "dma", "dram", K_OPEN)                                           \
  X(REGION_DMA32, "dma32", "dram", K_OPEN)                                       \
  X(REGION_INITRD, "initrd", "dram", K_OPEN)                                     \
  X(REGION_CMDLINE, "cmdline", "dram", K_OPEN)                                   \
  X(REGION_CMDLINE_MEMMAP, "cmdline_memmap", "dram", K_OPEN)                     \
  X(REGION_RESERVED_MEM, "reserved_mem", "dram", K_OPEN)                         \
  X(REGION_SWIOTLB, "swiotlb", "dram", K_OPEN)                                   \
  X(REGION_VMCOREINFO, "vmcoreinfo", "dram", K_OPEN)                             \
  X(REGION_CRASHKERNEL, "crashkernel", "dram", K_OPEN)                           \
  X(REGION_PMEM, "pmem", "dram", K_OPEN)                                         \
  X(REGION_ACPI_TABLE, "acpi_table", "dram", K_OPEN)                             \
  X(REGION_ACPI_NVS, "acpi_nvs", "dram", K_OPEN)                                 \
  X(REGION_EFI_MEMMAP, "efi_memmap", "dram", K_OPEN)                             \
  /* One PHYS extent per EFI_LOADER_CODE memmap entry — the EFI stub's */        \
  /* PE/COFF image regions resident at ExitBootServices(). The running */        \
  /* kernel is exactly one of these on an EFI stub boot; bootloader / driver     \
   */                                                                            \
  /* images claim the others. efi_loader_kernel_pick filters by alignment + */   \
  /* SF_IMAGE_SIZE_MIN size match to identify the running-kernel entry. */       \
  X(REGION_EFI_LOADER_IMAGE, "efi_loader_image", "dram", K_OPEN)                 \
  X(REGION_NUMA_NODE, "numa_node", "dram", K_OPEN)                               \
  X(REGION_MMIO, "mmio", "mmio", K_OPEN)                                         \
  X(REGION_PCI_MMIO, "pci_mmio", "mmio", K_OPEN)                                 \
  /* ---- Kernel image (legitimately exists in both phys and virt) ------- */    \
  /* K_OPEN keeps PHYS leaks visible alongside VIRT — per-type narrowing   */    \
  /* lives in the parser / inference layer, not the region table.          */    \
  /* BASE semantics (POS_BASE): KERNEL_TEXT base == _stext (.text start);  */    \
  /* text_pin_from_observation subtracts STEXT_OFFSET (the head gap) to    */    \
  /* recover the image base. KERNEL_IMAGE base == _text (the image base)   */    \
  /* itself, used directly. Report the IMAGE BASE as KERNEL_IMAGE, never   */    \
  /* KERNEL_TEXT — mis-tagging it KERNEL_TEXT lands the base a head gap    */    \
  /* below _text on arm64/loongarch64 (checked by tests/check-text-region).*/    \
  X(REGION_KERNEL_TEXT, "kernel_text", "text", K_OPEN)                           \
  /* KERNEL_TEXT vs KERNEL_TEXT_BAND is the same PROVENANCE split as MODULE */   \
  /* vs MODULE_BAND below, and exists for the same reason: the windows */        \
  /* overlap. KERNEL_TEXT means the source KNOWS the address is in the image     \
   */                                                                            \
  /* -- a resolved symbol, a sampled instruction pointer, an ELF phdr, a */      \
  /* faulting IP. KERNEL_TEXT_BAND means it merely fell inside the */            \
  /* admissible text window, which is the KASLR-possible range rather than */    \
  /* the image's extent and on most arches contains the linear map, the */       \
  /* module band, or both. On ppc32 KASLR relocates the image throughout */      \
  /* lowmem, so a bare pointer there is genuinely inseparable from a kernel */   \
  /* stack by range alone. */                                                    \
  /*                                                                         */  \
  /* Load-bearing because an interior-image sample implies image_base <= */      \
  /* sample: a non-image address below the real _text carves the truth out */    \
  /* of the window that promises to contain it. BAND is therefore absent */      \
  /* from is_kernel_image_region(), so no image-base rule can read it */         \
  /* by accident; range_from_interior opts in explicitly and caps the bound */   \
  /* below the sound floor. */                                                   \
  /*                                                                         */  \
  /* Emit BAND when the region rests on a range test --                          \
   * kasld_addr_classify()*/                                                     \
  /* picks it automatically wherever the windows are not exclusive. */           \
  X(REGION_KERNEL_TEXT_BAND, "kernel_text_band", "text", K_OPEN)                 \
  X(REGION_KERNEL_DATA, "kernel_data", "data", K_OPEN)                           \
  X(REGION_KERNEL_BSS, "kernel_bss", "bss", K_OPEN)                              \
  X(REGION_KERNEL_IMAGE, "kernel_image", "text", K_OPEN)                         \
  /* The two module regions differ by PROVENANCE, not by address range —    */   \
  /* both are validated against the same [MODULES_START, MODULES_END] band. */   \
  /* MODULE: the source structurally KNOWS the address belongs to a loaded  */   \
  /* module (it read a module's own address — /proc/modules, a sysfs        */   \
  /* per-module sections entry, a named symbol in a known module).          */   \
  /* MODULE_BAND: the band itself, OR an address merely CLASSIFIED as a     */   \
  /* module because it fell inside the band (dmesg parsers, opportunistic   */   \
  /* pointer leaks, perf JIT/trampoline records).                           */   \
  /*                                                                        */   \
  /* The distinction is load-bearing wherever a module address moves a TEXT */   \
  /* base, because the band overlaps other regions on every such arch: on   */   \
  /* arm64 a VA_BITS=48 direct map starts at MODULES_START, and on riscv64  */   \
  /* and s390 the band contains the whole kernel-text range. A              */   \
  /* range-classified address is then indistinguishable from a module one.  */   \
  /* So module_text_bracket AND module_text_bound both read MODULE only.    */   \
  /*                                                                        */   \
  /* MODULE_BAND is read where the claim is about the REGION rather than a  */   \
  /* module: the rendered band, and (with POS_BASE) the kernel's own        */   \
  /* "modules : 0x..." layout line, which pins Q_MODULE_BASE.               */   \
  /*                                                                        */   \
  /* Emit MODULE_BAND when in any doubt — it is the weaker, always-safe tag.*/   \
  X(REGION_MODULE, "module", "module", K_MODULE)                                 \
  X(REGION_MODULE_BAND, "module_band", "module", K_MODULE)                       \
  /* ---- Direct-map / virtual landmarks --------------------------------- */    \
  X(REGION_DIRECTMAP, "directmap", "directmap", K_VIRT)                          \
  /* The same PROVENANCE split again, for the linear map. DIRECTMAP means the    \
   */                                                                            \
  /* source knew it held a linear-map object -- a slab pointer, a page-table     \
   */                                                                            \
  /* entry, an iomem line. DIRECTMAP_BAND means only that the value landed in    \
   */                                                                            \
  /* the window kasld_addr_is_directmap() draws, which is "below the text */     \
  /* window" rather than "in the linear map", and so also spans vmalloc and */   \
  /* vmemmap wherever those are not separately bounded. */                       \
  /*                                                                          */ \
  /* Not narrowable to the compile-time VMALLOC_BASE_*: under */                 \
  /* CONFIG_RANDOMIZE_MEMORY the x86_64 bases are laid out sequentially from     \
   */                                                                            \
  /* the defaults, but the linear-map region SHRINKS to the machine's memory     \
   */                                                                            \
  /* size (arch/x86/mm/kaslr.c), so vmalloc_base sits far below its own */       \
  /* default on a small-memory host and a window closed at that constant */      \
  /* would swallow real vmalloc addresses. */                                    \
  /*                                                                          */ \
  /* Load-bearing because rules bound Q_PAGE_OFFSET from a linear-map */         \
  /* address; a vmalloc pointer arriving as DIRECTMAP moves that bound in the    \
   */                                                                            \
  /* unsound direction. Emitted only by kasld_addr_classify(); the components    \
   */                                                                            \
  /* that KNOW what they leaked keep saying DIRECTMAP. */                        \
  X(REGION_DIRECTMAP_BAND, "directmap_band", "directmap", K_VIRT)                \
  X(REGION_PAGE_OFFSET, "virt_page_offset", "pageoffset", K_PAGEOFFSET)          \
  X(REGION_VMALLOC, "vmalloc", "directmap", K_VIRT)                              \
  X(REGION_VMEMMAP, "vmemmap", "directmap", K_VIRT)

/* Closed-enum vocabulary of kernel memory areas. */
enum kasld_region {
  REGION_UNKNOWN = 0,
#define X(name, wire, sec, kind) name,
  KASLD_REGION_LIST(X)
#undef X
  /* Sentinel. Must be last so iteration over 0..REGION__COUNT-1 covers every
   * real region. */
  REGION__COUNT,
};

/* Wire-token mappings. Generated from KASLD_REGION_LIST; do not edit
 * directly. Convention: lowercase snake_case of the enum suffix
 * (REGION_KERNEL_IMAGE -> "kernel_image"). */
static const char *const kasld_region_wire_table[REGION__COUNT] = {
    [REGION_UNKNOWN] = "unknown",
#define X(name, wire, sec, kind) [name] = wire,
    KASLD_REGION_LIST(X)
#undef X
};

static inline const char *kasld_region_wire(enum kasld_region r) {
  if ((unsigned)r >= REGION__COUNT)
    return "unknown";
  const char *s = kasld_region_wire_table[r];
  return s ? s : "unknown";
}

/* Classify a bare kernel virtual address into the region that contains it,
 * reporting AMBIGUITY rather than resolving it.
 *
 * For a component that leaks an address carrying no evidence of what it points
 * at — a raw %px pointer, a stale stack word, a %ps function pointer — the
 * region is decided by which window the value lands in. That only works where
 * the windows are exclusive, and mostly they are not: the text window is the
 * KASLR-ADMISSIBLE range, not the image's extent, so it contains the linear map
 * on ppc32/arm32/x86_32/mips32/riscv32/ppc64/s390 and the module band on nearly
 * everything. kasld_addr_is_directmap() is already written as "below the text
 * window", which makes that window empty exactly where the two collide — so a
 * classifier that asks the predicates in order silently resolves every
 * ambiguous address in favour of text, the strongest tag available.
 *
 * A text claim therefore has to clear two independent bars. The architecture
 * must put nothing else in that window at all, which it declares as
 * TEXT_WINDOW_EXCLUSIVE and which defaults to 0; and THIS address must not also
 * be admitted by the module band or the linear map, which is a per-address
 * test, so where a window is only partly overlapped — x86_64 text below
 * MODULES_START is unambiguous, above it is not — precision is kept where it is
 * real. Failing either bar yields REGION_KERNEL_TEXT_BAND.
 *
 * REGION_MODULE is never returned: it asserts the source knew the address
 * belonged to a loaded module, which a range test cannot establish.
 *
 * The DIRECTMAP and VMALLOC answers carry no such band form, and they are
 * weaker than they look: kasld_addr_is_directmap() means "below the text
 * window", not "in the linear map", so on x86_64 it spans
 * [PAGE_OFFSET, KERNEL_VIRT_TEXT_MIN) and swallows vmalloc and vmemmap whole.
 * Rules that bound page_offset from a direct-map address read REGION_DIRECTMAP,
 * and a vmalloc pointer arriving under that tag moves the bound in the unsound
 * direction. Callers that cannot vouch for what they are passing should keep to
 * the text family and drop the rest, as the current three do.
 *
 * Returns REGION_UNKNOWN for anything outside the kernel VAS; callers drop it.
 */
static inline enum kasld_region kasld_addr_classify(unsigned long va) {
  int mod = kasld_addr_is_module_band(va);
  int dmap = kasld_addr_is_directmap(va);

  if (kasld_addr_is_kernel_text(va)) {
    /* Two independent reasons the image cannot be asserted. The architecture
     * may put other things in the window at all (TEXT_WINDOW_EXCLUSIVE), and
     * even where it does not, THIS address may also be admitted by the module
     * band or the linear map — on x86_64 the window holds the image below
     * MODULES_START and modules above it, so the per-address test keeps the
     * precision a per-architecture answer alone would throw away. */
    if (!TEXT_WINDOW_EXCLUSIVE || mod || dmap)
      return REGION_KERNEL_TEXT_BAND;
    return REGION_KERNEL_TEXT;
  }
  if (mod)
    return REGION_MODULE_BAND;
  if (dmap)
    return REGION_DIRECTMAP_BAND;
  /* Deliberately NOT REGION_VMALLOC. That is the "none of the above" answer,
   * and rules derive page_offset from the vmalloc base — asserting it from a
   * value that merely failed three window tests would be the same mistake in a
   * third place. An address in the kernel VAS that nothing else claims carries
   * no attribution worth publishing. */
  return REGION_UNKNOWN;
}

static inline char kasld_type_wire(enum kasld_addr_type t) {
  switch (t) {
  case KASLD_TYPE_PHYS:
    return 'P';
  case KASLD_TYPE_VIRT:
    return 'V';
  default:
    return '?';
  }
}

static inline const char *kasld_pos_wire(enum kasld_position p) {
  switch (p) {
  case POS_BASE:
    return "base";
  case POS_TOP:
    return "top";
  case POS_INTERIOR:
    return "interior";
  case POS_EXTENT:
    return "extent";
  default:
    return "unknown";
  }
}

static inline const char *kasld_conf_wire(enum kasld_confidence c) {
  switch (c) {
  case CONF_PARSED:
    return "parsed";
  case CONF_DERIVED:
    return "derived";
  case CONF_INFERRED:
    return "inferred";
  case CONF_HEURISTIC:
    return "heuristic";
  case CONF_TIMING:
    return "timing";
  case CONF_BRUTE:
    return "brute";
  default:
    return "unknown";
  }
}

/* Kernel-text function ordering class, carried as the value of SF_TEXT_ORDER.
 * A traditional -O2 kernel lays functions out in source/link order (canonical);
 * LTO/AutoFDO/Propeller reorder deterministically per build (static, single
 * KASLR slide, needs the exact-build System.map); FG-KASLR reorders per boot
 * (dynamic, per-function offsets, no static map resolves). The value gates
 * symbol-offset propagation: a generic version-level map is sound only on
 * `canonical`. Values start at 1 (0 == fact absent in the scalar pipeline). */
enum kasld_text_order {
  TEXT_ORDER_CANONICAL = 1, /* source/link order; generic System.map OK */
  TEXT_ORDER_STATIC,  /* LTO/AutoFDO/Propeller; needs exact-build map     */
  TEXT_ORDER_DYNAMIC, /* FG-KASLR / per-boot; no static map resolves      */
  TEXT_ORDER_UNKNOWN, /* could not be determined                          */
};

/* =========================================================================
 * Scalar system facts (non-address). A component emits these as `S` wire
 * records via kasld_emit_scalar(); the engine consumes them as OBS_SCALAR.
 * Closed vocabulary — add an entry, a wire token below, and a rule.
 * ========================================================================= */
/* SF_PPC64_MMU_MODE values. The kernel prints this from radix_enabled(), the
 * same runtime feature bit that selects __vmalloc_start, so it states the LIVE
 * translation mode rather than a CPU capability. */
#define KASLD_PPC64_MMU_RADIX 1ul
#define KASLD_PPC64_MMU_HASH 2ul

enum kasld_scalar_fact {
  SF_NONE = 0,
  SF_PHYS_MEMTOTAL,  /* total RAM bytes (/proc/meminfo)                  */
  SF_PHYS_ADDR_BITS, /* CPU physical-address width (/proc/cpuinfo)       */
  SF_IMAGE_SIZE_MIN, /* proven LOWER bound on the image footprint, bytes. The */
                     /* ceiling/exclusion/match rules subtract it from a      */
                     /* window edge, so it must be <= the true footprint.     */
                     /* Emitted by EVERY size source (exact and compressed/   */
                     /* lower-bound alike). Read via evidence_image_size_min. */
  SF_VIRT_ADDR_BITS, /* virtual-address width / paging level             */
  SF_IMAGE_SIZE_MAX, /* proven UPPER bound on the in-image extent (>= _end -  */
                     /* _text), bytes. The image-base floor rule needs a      */
                     /* value no in-image leak can exceed. Emitted only by    */
                     /* EXACT sources (which also emit SF_IMAGE_SIZE_MIN).    */
                     /* Read via evidence_image_size_max.                     */
  SF_PHYS_LOWMEM,    /* 32-bit lowmem bytes (/proc/meminfo LowTotal)     */
  SF_PHYS_FW_RESERVED_BASE, /* ppc64 firmware reserved region base (OPAL/RTAS)
                             */
  SF_PHYS_MAX_PFN,      /* highest spanned PFN (/proc/zoneinfo)             */
  SF_PHYS_KERNEL_ALIGN, /* CONFIG_PHYSICAL_ALIGN slot granularity (x86)     */
  SF_PAGE_SIZE,         /* host page size in bytes                          */
  SF_VIRT_RANDOMIZE_MAX_OFFSET, /* CONFIG_RANDOMIZE_BASE_MAX_OFFSET
                              (MIPS/LoongArch)*/
  SF_VIRT_CONFIG_PAGE_OFFSET,   /* CONFIG_PAGE_OFFSET (VMSPLIT; authoritative
                                   arches)*/
  SF_VIRT_PAGE_OFFSET,          /* exact runtime linear-map base
                                   (page_offset_base), recovered from a parse —
                                   pins Q_PAGE_OFFSET, unlike a directmap-address
                                   leak which only upper-bounds it */
  SF_EFI_PRESENT,         /* 1 if /sys/firmware/efi exists (EFI boot)         */
  SF_FDT_KASLR_SEED,      /* FDT /chosen/kaslr-seed (riscv64)                 */
  SF_VIRT_KASLR_DISABLED, /* 1 if a detector observed VIRTUAL KASLR off       */
                          /* (nokaslr cmdline, !CONFIG_RANDOMIZE_BASE, riscv64*/
                          /* no FDT seed, dmesg "KASLR disabled", hibernation,*/
                          /* arch-no-kaslr synth on !KASLR_SUPPORTED). Pinned */
  /* by virt_kaslr_disabled_pin to KERNEL_VIRT_TEXT_DEFAULT*/
  /* on arches where KASLR_DISABLED_PINS_VIRT_TEXT holds.  */
  SF_PHYS_KASLR_DISABLED, /* 1 if a detector observed PHYSICAL KASLR off.     */
                          /* On most current emitters this fires together     */
                          /* with SF_VIRT_KASLR_DISABLED (the same disable    */
                          /* mechanism turns off both axes). Pinned by        */
                          /* phys_kaslr_disabled_pin to the per-arch default  */
                          /* phys text base on arches where                   */
                          /* KASLR_DISABLED_PINS_PHYS holds (x86_64,          */
                          /* loongarch64). A future detector that proves only */
                          /* phys is off (e.g. EFI_RNG_PROTOCOL unavailable   */
                          /* with virt randomization intact via DTB) emits    */
                          /* this fact alone.                                 */
  /* 64-bit PowerPC translation mode, as KASLD_PPC64_MMU_* below. Which of the
   * three module-region bases is live follows from this plus SF_PAGE_SIZE, so
   * it is emitted as a raw measurement and interpreted by a rule. Values are
   * non-zero because a scalar fact of 0 reads as absent. */
  SF_PPC64_MMU_MODE,
  SF_KMSAN_ENABLED, /* 1 if CONFIG_KMSAN=y, 0 where the config was read and  */
                    /* it is not. Emitted alongside SF_KASAN_ENABLED because  */
                    /* s390 sizes its kernel stacks on EITHER (thread_info.h  */
                    /* THREAD_SIZE_ORDER 4 under KASAN or KMSAN, 2 otherwise) */
                    /* and s390 selects HAVE_ARCH_KMSAN, so KASAN alone does  */
                    /* not settle the stack size there. The two are mutually  */
                    /* exclusive in Kconfig (KMSAN depends on !KASAN).        */
  SF_KASLR_RANDOMIZED, /* 1 where the x86 boot stub recorded that it actually */
                       /* randomized the kernel this boot: KASLR_FLAG in      */
                       /* boot_params.hdr.loadflags, which misc.c clears and  */
                       /* choose_random_location sets only after its nokaslr  */
  /* early return. The randomizer lives in kaslr.o, built */
  /* only under CONFIG_RANDOMIZE_BASE, so a set flag also */
  /* proves that option -- and therefore KERNEL_IMAGE_SIZE */
  /* and MODULES_VADDR. Emitted only when set: a clear    */
  /* flag is the KASLR-off signal the SF_*_KASLR_DISABLED */
  /* facts already carry.                                 */
  SF_VIRT_KASLR_RANDOMIZATION_FAILED, /* 1 if the boot stub attempted    */
  /* virtual KASLR but could not produce a random virt offset (current   */
  /* emitters: arm64/riscv64 "lack of seed", arm64 "FDT remapping        */
  /* failure", s390 "CPU has no PRNG" / "not enough memory" — all four   */
  /* fail BOTH axes, so they emit this and SF_PHYS_KASLR_RANDOMIZATION_  */
  /* FAILED together). Kernel was still relocated to a firmware- or      */
  /* boot-stub-determined virt position — NOT the link-time default —    */
  /* so this signal does NOT pin a value via virt_kaslr_disabled_pin.    */
  /* Consumed by: the orchestrator's s->kaslr.randomization_failed flag  */
  /* + the hardening report posture section (entropy downgrade — the     */
  /* user-visible "0 entropy" claim is about virt text).                 */
  SF_PHYS_KASLR_RANDOMIZATION_FAILED, /* 1 if the boot stub attempted    */
  /* physical KASLR but could not produce a random phys offset (current  */
  /* emitters: same as the virt variant, all four affect both axes; a    */
  /* future detector for "EFI_RNG_PROTOCOL unavailable" on EFI arm64 /   */
  /* riscv64 emits this alone — virt KASLR there is independent via      */
  /* the DTB seed and may have succeeded). Kernel was relocated by the   */
  /* EFI stub or boot-stub fallback to a deterministic phys position.    */
  /* Consumed by: efi_loader_kernel_pick (lowest-survivor pick from      */
  /* multiple EFI_LOADER_CODE entries when the stub fell back to         */
  /* deterministic allocation); s390_text_no_random (low-memory upper    */
  /* bound on s390 phys text from the boot stub's nokaslr_text_lma       */
  /* path).                                                              */
  SF_PHYS_CMDLINE_MEM,  /* `mem=N` cmdline cap on usable RAM (bytes; x86)   */
  SF_CMDLINE_HUGEPAGES, /* 1 if `hugepages=` on cmdline (x86 EFI)      */
  SF_CMDLINE_MEMMAP_COUNT, /* count of `memmap=size{@,$,!,#}start` with offset
                            */
  SF_PHYSICAL_START, /* CONFIG_PHYSICAL_START (kernel's LOAD_PHYSICAL_ADDR  */
                     /* / pref_address; x86). Used to raise the Q_*_TEXT   */
                     /* honest-top floors above their conservative default.*/
  SF_KASAN_ENABLED,  /* 1 if CONFIG_KASAN=y. On x86_64 KASAN forces        */
                     /* kaslr_memory_enabled()=false (= kaslr_enabled() && */
                     /* !IS_ENABLED(CONFIG_KASAN)), so the direct map /    */
                     /* vmalloc / vmemmap bases stay at their compile-time */
                     /* defaults even when CONFIG_RANDOMIZE_MEMORY=y.      */
                     /* Pinned by directmap_kaslr_disabled_pin.            */
  SF_STRUCT_PAGE_BYTES, /* exact sizeof(struct page)
                           (/sys/kernel/btf/vmlinux).*/
                        /* vmemmap_size = max_pfn * this; the s390/x86_64/    */
                        /* arm64 vmemmap rules consume it, falling back to 64 */
                        /* (the common value) when BTF is unavailable.        */
  SF_TEXT_ORDER,        /* kernel-text function ordering class                */
                        /* (enum kasld_text_order). Gates whether a generic   */
                        /* System.map can resolve symbols from the slide;     */
                        /* informational — no engine pin rule consumes it.    */
  SF_VIRT_KERNEL_IMAGE_BASE, /* configured virtual kernel image-base floor,   */
  /* parsed from a readable kernel config. The fact is   */
  /* arch-neutral (named for the value, not the arch);    */
  /* the consuming rule gates on the arch. Today only    */
  /* s390 has the knob (CONFIG_KERNEL_IMAGE_BASE, s390-  */
  /* only) and a consumer: a positive value selects the  */
  /* modern (v6.8+) high separate-kernel-mapping layout  */
  /* and gives its relocation floor; 0 means the config  */
  /* is an s390 config that LACKS the knob — the pre-v6.8 */
  /* identity-mapped layout (kernel text in low RAM).    */
  /* Consumed by s390_image_base_from_config to recover  */
  /* a tight Q_VIRT_IMAGE_BASE window without trusting    */
  /* version numbers.                                    */
  SF__COUNT,
};

/* SF_* <-> wire token, single source of truth for both directions. */
static const char *const kasld_scalar_fact_wire_table[SF__COUNT] = {
    [SF_NONE] = "none",
    [SF_PHYS_MEMTOTAL] = "phys_memtotal",
    [SF_PHYS_ADDR_BITS] = "phys_addr_bits",
    [SF_IMAGE_SIZE_MIN] = "image_size_min",
    [SF_VIRT_ADDR_BITS] = "virt_addr_bits",
    [SF_IMAGE_SIZE_MAX] = "image_size_max",
    [SF_PHYS_LOWMEM] = "phys_lowmem",
    [SF_PHYS_FW_RESERVED_BASE] = "phys_fw_reserved_base",
    [SF_PHYS_MAX_PFN] = "phys_max_pfn",
    [SF_PHYS_KERNEL_ALIGN] = "phys_kernel_align",
    [SF_PAGE_SIZE] = "page_size",
    [SF_VIRT_RANDOMIZE_MAX_OFFSET] = "virt_randomize_max_offset",
    [SF_VIRT_CONFIG_PAGE_OFFSET] = "virt_config_page_offset",
    [SF_VIRT_PAGE_OFFSET] = "virt_page_offset",
    [SF_EFI_PRESENT] = "efi_present",
    [SF_FDT_KASLR_SEED] = "fdt_kaslr_seed",
    [SF_VIRT_KASLR_DISABLED] = "virt_kaslr_disabled",
    [SF_PHYS_KASLR_DISABLED] = "phys_kaslr_disabled",
    [SF_VIRT_KASLR_RANDOMIZATION_FAILED] = "virt_kaslr_randomization_failed",
    [SF_PHYS_KASLR_RANDOMIZATION_FAILED] = "phys_kaslr_randomization_failed",
    [SF_PHYS_CMDLINE_MEM] = "phys_cmdline_mem",
    [SF_CMDLINE_HUGEPAGES] = "cmdline_hugepages",
    [SF_CMDLINE_MEMMAP_COUNT] = "cmdline_memmap_count",
    [SF_PHYSICAL_START] = "physical_start",
    [SF_KASAN_ENABLED] = "kasan_enabled",
    [SF_STRUCT_PAGE_BYTES] = "struct_page_bytes",
    [SF_TEXT_ORDER] = "text_order",
    [SF_VIRT_KERNEL_IMAGE_BASE] = "virt_kernel_image_base",
    [SF_PPC64_MMU_MODE] = "ppc64_mmu_mode",
    [SF_KMSAN_ENABLED] = "kmsan_enabled",
    [SF_KASLR_RANDOMIZED] = "kaslr_randomized",
};
/* Adding an SF_* without a wire token shrinks this below SF__COUNT -> error. */
typedef char kasld_sf_wire_table_complete
    [(sizeof(kasld_scalar_fact_wire_table) / sizeof(char *)) == SF__COUNT ? 1
                                                                          : -1];

static inline const char *kasld_scalar_fact_wire(enum kasld_scalar_fact f) {
  if ((unsigned)f >= SF__COUNT)
    return NULL;
  return kasld_scalar_fact_wire_table[f];
}

static inline enum kasld_scalar_fact
kasld_scalar_fact_from_wire(const char *s) {
  for (int i = SF_NONE + 1; i < SF__COUNT; i++)
    if (kasld_scalar_fact_wire_table[i] &&
        strcmp(s, kasld_scalar_fact_wire_table[i]) == 0)
      return (enum kasld_scalar_fact)i;
  return SF_NONE;
}

/* =========================================================================
 * Emitter helpers
 *
 * All helpers return 1 on emit, 0 on rejection (with a stderr warning).
 * Rejection happens for: CONF_UNKNOWN, invalid type, invalid region,
 * helper-specific preconditions (e.g. _sized overflow).
 * `name = NULL` or `""` means no specific instance (the wire form omits
 * the `:name` suffix).
 *
 * The character set is not checked here; the parser at ingest enforces it, and
 * what it enforces is this: a name is made only of printable ASCII excluding
 * space, 0x21..0x7E, and a record carrying anything else is rejected whole
 * rather than truncated or scrubbed. The same rule governs a disposition's
 * `gate`, while its quoted `msg` additionally admits the space. Every source
 * these fields draw on is ASCII by its own specification, so a byte outside
 * the set is an artefact; and since all three reach a terminal, a control byte
 * among them is an escape sequence rather than a cosmetic flaw.
 * ========================================================================= */

static inline int kasld__emit_check(enum kasld_addr_type t, enum kasld_region r,
                                    enum kasld_confidence c, const char *who) {
  if (t == KASLD_TYPE_UNKNOWN) {
    fprintf(stderr, "%s: KASLD_TYPE_UNKNOWN rejected; no result emitted\n",
            who);
    return 0;
  }
  if ((unsigned)r >= REGION__COUNT || r == REGION_UNKNOWN) {
    fprintf(stderr, "%s: invalid region %u rejected; no result emitted\n", who,
            (unsigned)r);
    return 0;
  }
  if (c == CONF_UNKNOWN) {
    fprintf(stderr, "%s: CONF_UNKNOWN rejected; no result emitted\n", who);
    return 0;
  }
  return 1;
}

static inline void kasld__emit_prefix(enum kasld_addr_type t,
                                      enum kasld_region r, const char *name) {
  if (name && *name)
    printf("%c %s:%s", kasld_type_wire(t), kasld_region_wire(r), name);
  else
    printf("%c %s", kasld_type_wire(t), kasld_region_wire(r));
}

/* `lo`+`hi` known (extent fully bounded). pos=base, addr=lo. */
static inline int kasld_result_range(enum kasld_addr_type t,
                                     enum kasld_region r, unsigned long lo,
                                     unsigned long hi, const char *name,
                                     enum kasld_confidence c) {
  if (!kasld__emit_check(t, r, c, "kasld_result_range"))
    return 0;
  if (lo > hi) {
    fprintf(stderr,
            "kasld_result_range: lo=0x%lx > hi=0x%lx; no result emitted\n", lo,
            hi);
    return 0;
  }
  kasld__emit_prefix(t, r, name);
  printf(" pos=base conf=%s lo=0x%lx hi=0x%lx\n", kasld_conf_wire(c), lo, hi);
  return 1;
}

/* One [lo, hi] member of a COMPLETE, single-source covering of the region — a
 * map. CONTRACT: the caller emits its WHOLE map (every extent); the gaps
 * between extents are then known-empty, which is what gap-carving rules rely
 * on. Emit pos=extent, never base/top: it makes no positional claim (the lowest
 * online hotplug block can sit above reserved low RAM, so pos=base would
 * wrongly pin the floor), and its value is in the SET, not any one edge.
 *
 * These records are NOT merged with other sources' evidence: the orchestrator
 * routes them out-of-band into the engine's coverings[], keeping each source's
 * map faithful and attributable (a partial map would make gap-carving unsound,
 * which is why a make-test guard reviews every new caller of this helper). */
static inline int kasld_result_extent(enum kasld_addr_type t,
                                      enum kasld_region r, unsigned long lo,
                                      unsigned long hi, const char *name,
                                      enum kasld_confidence c) {
  if (!kasld__emit_check(t, r, c, "kasld_result_extent"))
    return 0;
  if (lo > hi) {
    fprintf(stderr,
            "kasld_result_extent: lo=0x%lx > hi=0x%lx; no result emitted\n", lo,
            hi);
    return 0;
  }
  kasld__emit_prefix(t, r, name);
  printf(" pos=extent conf=%s lo=0x%lx hi=0x%lx\n", kasld_conf_wire(c), lo, hi);
  return 1;
}

/* `lo`+`size` known. Normalises to inclusive hi = lo + sz - 1. */
static inline int kasld_result_sized(enum kasld_addr_type t,
                                     enum kasld_region r, unsigned long lo,
                                     unsigned long sz, const char *name,
                                     enum kasld_confidence c) {
  if (!kasld__emit_check(t, r, c, "kasld_result_sized"))
    return 0;
  if (sz == 0 || sz - 1 > ULONG_MAX - lo) {
    fprintf(stderr,
            "kasld_result_sized: invalid sz=0x%lx lo=0x%lx "
            "(would overflow lo+sz-1); no result emitted\n",
            sz, lo);
    return 0;
  }
  unsigned long hi = lo + sz - 1;
  kasld__emit_prefix(t, r, name);
  printf(" pos=base conf=%s lo=0x%lx hi=0x%lx\n", kasld_conf_wire(c), lo, hi);
  return 1;
}

/* Base only — `lo` known, `hi` unknown. pos=base, addr=lo. */
static inline int kasld_result_base(enum kasld_addr_type t, enum kasld_region r,
                                    unsigned long lo, const char *name,
                                    enum kasld_confidence c) {
  if (!kasld__emit_check(t, r, c, "kasld_result_base"))
    return 0;
  kasld__emit_prefix(t, r, name);
  printf(" pos=base conf=%s lo=0x%lx\n", kasld_conf_wire(c), lo);
  return 1;
}

/* Top only — `hi` known, `lo` unknown. pos=top, addr=hi. */
static inline int kasld_result_top(enum kasld_addr_type t, enum kasld_region r,
                                   unsigned long hi, const char *name,
                                   enum kasld_confidence c) {
  if (!kasld__emit_check(t, r, c, "kasld_result_top"))
    return 0;
  kasld__emit_prefix(t, r, name);
  printf(" pos=top conf=%s hi=0x%lx\n", kasld_conf_wire(c), hi);
  return 1;
}

/* Interior sample — address known, position within extent unknown. */
static inline int kasld_result_sample(enum kasld_addr_type t,
                                      enum kasld_region r, unsigned long addr,
                                      const char *name,
                                      enum kasld_confidence c) {
  if (!kasld__emit_check(t, r, c, "kasld_result_sample"))
    return 0;
  kasld__emit_prefix(t, r, name);
  printf(" pos=interior conf=%s sample=0x%lx\n", kasld_conf_wire(c), addr);
  return 1;
}

/* Emit one scalar system fact: `S <fact> conf=<c> value=0x<hex>`. */
static inline int kasld_emit_scalar(enum kasld_scalar_fact f,
                                    unsigned long value,
                                    enum kasld_confidence c) {
  const char *w = kasld_scalar_fact_wire(f);
  if (f == SF_NONE || !w) {
    fprintf(stderr, "kasld_emit_scalar: invalid fact %d; nothing emitted\n",
            (int)f);
    return 0;
  }
  if (c == CONF_UNKNOWN) {
    fprintf(stderr, "kasld_emit_scalar: CONF_UNKNOWN for %s; nothing emitted\n",
            w);
    return 0;
  }
  printf("S %s conf=%s value=0x%lx\n", w, kasld_conf_wire(c), value);
  return 1;
}

/* Component disposition — why a component produced no tagged result, in a
 * closed vocabulary. It refines the exit code, which names only the coarse
 * class. The category carries the distinction the exit code structurally
 * cannot: whether an unavailable technique was stopped by a *defensive control
 * on the target* (mitigation) or merely lacks a *prerequisite on this host*
 * (absent), and whether an empty run is a deliberate opt-out (disabled) or an
 * honest "ran, no clean signal, cannot prove why" (inconclusive). */
enum kasld_disp {
  DISP_NONE = 0,     /* no disposition reported */
  DISP_MITIGATION,   /* a defensive control on the target/host foiled it */
  DISP_ABSENT,       /* an attacker prerequisite is missing on this host */
  DISP_DISABLED,     /* deliberate operator opt-out (needs a flag/env) */
  DISP_INCONCLUSIVE, /* ran, no clean signal, cannot prove why */
};

/* Category <-> wire token. Kept adjacent so the emitter and the orchestrator's
 * parser share one source of the token strings and cannot drift. */
static inline const char *kasld_disp_wire(enum kasld_disp d) {
  switch (d) {
  case DISP_MITIGATION:
    return "mitigation";
  case DISP_ABSENT:
    return "absent";
  case DISP_DISABLED:
    return "disabled";
  case DISP_INCONCLUSIVE:
    return "inconclusive";
  case DISP_NONE:
    break;
  }
  return NULL;
}

static inline enum kasld_disp kasld_disp_parse(const char *tok) {
  if (!tok)
    return DISP_NONE;
  if (!strcmp(tok, "mitigation"))
    return DISP_MITIGATION;
  if (!strcmp(tok, "absent"))
    return DISP_ABSENT;
  if (!strcmp(tok, "disabled"))
    return DISP_DISABLED;
  if (!strcmp(tok, "inconclusive"))
    return DISP_INCONCLUSIVE;
  return DISP_NONE;
}

/* Emit one disposition line:
 *   R cat=<category> [gate=<token>] [msg="<text>"]
 * A leak or probe component that ends without a tagged result reports why here.
 * The orchestrator records it on the per-component log; renderers surface the
 * mitigation category (a confirmed defensive control) in the hardening report
 * and in text/JSON output. Emit at most once.
 *
 * `gate` names the specific control and is REQUIRED for DISP_MITIGATION (e.g.
 * "kpti", a CONFIG_ id, or a CVE id) and ignored for every other category; a
 * mitigation with no gate is a bug and emits nothing. Newlines fold to spaces
 * and a `"` in `msg` folds to `'` so the record stays one trivially-parsed
 * line. Prefer the typed wrappers below, which also return the exit code the
 * category implies, so the two channels cannot disagree. */
static inline void kasld_disposition(enum kasld_disp cat, const char *gate,
                                     const char *msg) {
  const char *cw = kasld_disp_wire(cat);
  if (!cw) {
    fprintf(stderr, "kasld_disposition: invalid category %d; nothing emitted\n",
            (int)cat);
    return;
  }
  int want_gate = (cat == DISP_MITIGATION);
  int have_gate = gate && *gate;
  if (want_gate && !have_gate) {
    fprintf(stderr, "kasld_disposition: %s requires a gate; nothing emitted\n",
            cw);
    return;
  }
  fputs("R cat=", stdout);
  fputs(cw, stdout);
  if (want_gate) {
    fputs(" gate=", stdout);
    for (const char *p = gate; *p; p++) {
      unsigned char ch = (unsigned char)*p;
      int sep = (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' ||
                 ch == '"' || ch == '=');
      putchar(sep ? '_' : ch);
    }
  }
  if (msg && *msg) {
    fputs(" msg=\"", stdout);
    for (const char *p = msg; *p; p++) {
      unsigned char ch = (unsigned char)*p;
      if (ch == '\n' || ch == '\r')
        ch = ' ';
      else if (ch == '"')
        ch = '\'';
      putchar(ch);
    }
    putchar('"');
  }
  putchar('\n');
}

/* Component exit codes — the component-side ABI for signalling run status to
 * the orchestrator, which maps them to a component_outcome (outcome.h) for the
 * summary and hardening report. There are exactly three classes; the specific
 * gate a technique tripped on is reported separately, not encoded in the code.
 *
 *   0    Ran to completion. Any results are in the tagged output. Exit 0 with
 *        no tagged line means the technique applied but produced nothing this
 *        run: a source with no matching entry, transient side-channel noise, or
 *        an empty result that is genuinely ambiguous between "mitigated" and
 *        "would resolve elsewhere". A miss that cannot be proven structural
 *        stays 0 — a flat side-channel that a quieter run might resolve is not
 *        UNAVAILABLE.
 *
 *   69   KASLD_EXIT_UNAVAILABLE — the technique provably cannot apply on this
 *        host: a required data source, instruction, or CPU feature is absent;
 *        the CPU vendor is wrong for a vendor-specific attack; a mitigation is
 *        conclusively present (e.g. KPTI under a prefetch timing leak); or the
 *        configuration is unsupported.
 *
 *   77   KASLD_EXIT_NOPERM — a data source or syscall the technique needs was
 *        denied: EPERM/EACCES, a missing capability, or a restrictive sysctl.
 *
 * Precedence: a tagged result always wins (exit however is convenient — the
 * orchestrator counts the result). Otherwise report the class that is provably
 * true; when the only honest answer is "ran, found nothing, cannot prove why",
 * that is 0. */
#define KASLD_EXIT_UNAVAILABLE                                                 \
  69                         /* feature/hardware not present (EX_UNAVAILABLE) */
#define KASLD_EXIT_NOPERM 77 /* access denied (EX_NOPERM) */

/* The exit class a failed probe implies, read from errno.
 *
 * A denial and an absence are different facts about the target — one is its
 * hardening, the other its build — and open()/access()/stat() report both by
 * returning the same failure. Deciding UNAVAILABLE without looking records a
 * mandatory-access-control denial as a missing prerequisite, which says nothing
 * about the target while looking like it says something.
 *
 * Call it immediately after the failed probe, before any other library call has
 * a chance to overwrite errno, and only where a SINGLE candidate path was
 * tried: after a helper that walks several, errno belongs to the last one
 * attempted rather than to the most informative. */
static inline int kasld_exit_for_errno(void) {
  return (errno == EACCES || errno == EPERM) ? KASLD_EXIT_NOPERM
                                             : KASLD_EXIT_UNAVAILABLE;
}

/* Typed disposition wrappers: emit the `R` line (see kasld_disposition above)
 * and return the exit code the category implies, so a component ends a gated
 * path with a single expression — `return kasld_disp_absent("no RTM");` or
 * `exit(kasld_disp_mitigation("kpti", "KPTI active"));` — and the disposition
 * and exit code cannot disagree. A mitigation is UNAVAILABLE when a control is
 * present (kasld_disp_mitigation) or NOPERM when a control denied the source
 * (kasld_disp_mitigation_denied); an inconclusive run is always exit 0. Where
 * the exit code is decided elsewhere (a helper, a loop break), call the untyped
 * kasld_disposition() directly. */
static inline int kasld_disp_mitigation(const char *gate, const char *msg) {
  kasld_disposition(DISP_MITIGATION, gate, msg);
  return KASLD_EXIT_UNAVAILABLE;
}
static inline int kasld_disp_mitigation_denied(const char *gate,
                                               const char *msg) {
  kasld_disposition(DISP_MITIGATION, gate, msg);
  return KASLD_EXIT_NOPERM;
}
/* Only for a prerequisite that is provably not there. An access()/stat()
 * failure alone does not establish that: a path denied by DAC or by a MAC
 * policy fails identically to a missing one, and reporting a denial as an
 * absence blames the target's build for what its configuration did. Split on
 * errno — ENOENT is absence, EACCES/EPERM are a denial and belong on the
 * KASLD_EXIT_NOPERM path. */
static inline int kasld_disp_absent(const char *msg) {
  kasld_disposition(DISP_ABSENT, NULL, msg);
  return KASLD_EXIT_UNAVAILABLE;
}
static inline int kasld_disp_disabled(const char *msg) {
  kasld_disposition(DISP_DISABLED, NULL, msg);
  return KASLD_EXIT_UNAVAILABLE;
}
static inline int kasld_disp_inconclusive(const char *msg) {
  kasld_disposition(DISP_INCONCLUSIVE, NULL, msg);
  return 0;
}

/* When stdout is a pipe (as when the orchestrator captures output), glibc
 * switches to fully-buffered mode. stderr remains unbuffered. Both pipes
 * merge, so stderr lines can arrive before stdout lines that were logically
 * printed first. Force stdout to line-buffered so output order matches the
 * printf call order in each component. */
__attribute__((constructor)) static void kasld_init_buffering(void) {
  setvbuf(stdout, NULL, _IOLBF, 0);
}

/* environ is undeclared under a strict -std=c99 compile and declared by
 * unistd.h under a feature-test macro, so this covers the first case and the
 * pragma the second, whichever order a translation unit reaches them in. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wredundant-decls"
extern char **environ;
#pragma GCC diagnostic pop

/* Unlink every environment entry whose name starts with `prefix`.
 *
 * The entries are removed from environ directly. unsetenv() is the obvious
 * call and is not declared under a strict -std=c99 compile, whereas environ
 * needs no library function at all; getenv() reads the same array, so a name
 * removed here is a name no later read can find. The strings themselves are
 * left alone — they may not be the allocator's to release. */
__attribute__((unused)) static void kasld_env_drop_prefix(const char *prefix) {
  size_t n = strlen(prefix);
  char **src, **dst;

  if (environ == NULL)
    return;
  for (src = dst = environ; *src != NULL; src++) {
    if (strncmp(*src, prefix, n) == 0)
      continue;
    *dst++ = *src;
  }
  *dst = NULL;
}

/* Non-zero when this exec gained privilege: a set-uid or set-gid binary, or
 * one carrying file capabilities.
 *
 * AT_SECURE is the kernel's own verdict and the only one of the two tests that
 * accounts for file capabilities; the uid/gid comparison stands in where the
 * auxiliary vector carries no such entry. */
__attribute__((unused)) static int kasld_exec_gained_privilege(void) {
  unsigned long secure;
  int gained;

  errno = 0;
  secure = getauxval(AT_SECURE);
  gained = (secure == 0 && errno != 0)
               ? (getuid() != geteuid()) || (getgid() != getegid())
               : (secure != 0);
  errno = 0;
  return gained;
}

/* An exec that gained privilege holds rights its caller does not, while the
 * caller still chose the environment it started in. KASLD_COMPONENT_DIR and
 * KASLD_EXEC_WRAPPER name programs this process executes and KASLD_SYSROOT
 * names the files it reads, so honouring them there lends those rights to
 * whoever set them. The dynamic loader strips only the variables it owns;
 * these are not among them.
 *
 * The whole KASLD_ prefix goes, so a variable added later needs no change
 * here. Dropping the entries rather than ignoring them at each read also
 * cleans the environment the orchestrator's component children inherit, which
 * matters because those children gain no privilege of their own at exec and so
 * cannot detect the case themselves. Nothing aborts: a privileged install
 * still runs, on its own configuration rather than a caller's. */
__attribute__((constructor)) static void kasld_drop_inherited_env(void) {
  if (kasld_exec_gained_privilege())
    kasld_env_drop_prefix("KASLD_");
}

/* Suppress -Wpedantic "ISO C forbids an empty translation unit". */
typedef int make_iso_compilers_happy;

/* Plain-text technique explanation, placed in a dedicated ELF section.
 * The orchestrator reads it (without executing the binary) for --explain. */
#define KASLD_EXPLAIN(text)                                                    \
  __attribute__((                                                              \
      used, section(".kasld_explain"))) static const char kasld_explain[] =    \
      text

/* Machine-readable metadata in a dedicated ELF section. Newline-delimited
 * key:value pairs. Recognised keys:
 *   method:  Technique category for the hardening report. Values: parsed,
 *            heuristic, inferred, timing, brute, detection.
 *   phase:   "inference" (default) or "probing".
 *   discloses: what the component reveals — "virtual", "physical" or "both"
 *            (a kernel address of that kind), or "facts" (scalar system facts
 *            only, no address).
 *   source:  Where the technique's own inputs come from. Mandatory, one of
 *            "files", "live" or "hybrid" — a closed axis, and the one the
 *            orchestrator schedules on when the run reads a captured tree
 *            rather than the running kernel.
 *              "files"  — every input is a fact file, so the technique
 *                         replays against a capture unchanged.
 *              "live"   — the result derives from live runtime state of the
 *                         executing kernel/CPU (a syscall, a CPU instruction,
 *                         a timing measurement, a setuid helper, or a
 *                         self-referential /proc/self pseudo-file), which no
 *                         captured tree carries. The orchestrator drops it
 *                         against a capture and the standalone binary skips
 *                         itself (kasld_skip_live_probe).
 *              "hybrid" — a live step AND a captured-file read, so it runs in
 *                         either mode with the live step suppressed. Such a
 *                         component branches on kasld_fact_source().
 *            It names what the COMPONENT'S OWN code needs: where a shared
 *            header answers the same question from a file under a capture
 *            (the kernel log, the process identity), the component is
 *            "files" — the abstraction, not the component, holds the branch.
 *            Absent from a metadata block, or unrecognised, reads as "live" —
 *            the safe direction: a component that does not say is not run
 *            against a capture.
 *   status:  "experimental" — opt-in via -x. Optional, and the only key here
 *            whose mere presence is the signal: a value this build does not
 *            recognise gates the component rather than running it.
 *
 * Hardening-report inputs — a technique names what would neutralise it:
 *   sysctl:  Mitigating sysctl.
 *   config:  Kernel config the technique depends on (may repeat).
 *   patch:   Kernel version that closed the bug.
 *   cve:     Associated CVE.
 *   lockdown: Lockdown mode that blocks the technique.
 *   hardware: Hardware requirement -- the positive condition the leak needs
 *            (e.g. "TSX required", "prefetch side-channel"). A feature that
 *            disables the leak goes in a trailing "(mitigated by <feature>)",
 *            never as the bare value: KPTI, UMIP and the like name the
 *            mitigation, not the requirement.
 *   bypass:  Capability that bypasses the mitigation.
 *   fallback: Path of the alternative source (e.g. /var/log/dmesg); the report
 *            reads only whether the key is present. The technique also reads a
 *            log-file fallback, not only a restricted syscall, so the report
 *            can distinguish a syscall restriction (dmesg_restrict) from a
 *            file-permission fix.
 */
#define KASLD_META(text)                                                       \
  __attribute__((                                                              \
      used, section(".kasld_meta"))) static const char kasld_meta[] = text

#endif /* KASLD_API_H */
