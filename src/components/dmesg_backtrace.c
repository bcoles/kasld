// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Search the kernel log for oops/WARNING dumps and extract kernel addresses.
//
// The log is walked as an ordered stream of lines (one pass), so a register
// dump can be associated with the process context of its own dump. Three kinds
// of value are recovered:
//
// 1. Kernel text addresses from [<addr>] call-trace tokens (pre-symbolised,
//    i.e. older, kernels; modern call traces print "func+off/size" with no raw
//    address). On LoongArch the register dump additionally prints the raw pc/ra
//    kernel-text registers — other arches symbolise PC/LR with %pS — so they
//    are read directly there.
// 2. The physical page-table base from the x86 CR3 register. CR3 is the only
//    page-table base any architecture prints in a register dump (arm64/riscv
//    dump PC/LR/SP + GPRs but no TTBR/SATP), so this is x86-only. Its meaning
//    depends on the faulting task:
//      - idle task (PID 0 / comm "swapper"): CR3 == swapper_pg_dir, which lives
//        in the kernel .bss section -> a kernel-image landmark
//        (REGION_KERNEL_BSS) that pins the physical image base.
//      - any other task: CR3 is that process's PGD, allocated anywhere in DRAM
//        by the buddy allocator -> generic RAM (REGION_RAM), carrying no
//        image-base information.
//    The dump header (CPU/PID/Comm) provides the discriminator; the register
//    value itself cannot, as the kernel image base is not yet known.
// 3. Direct-map virtual addresses: register values that fall in the
//    PAGE_OFFSET..KERNEL_VIRT_TEXT_MIN range. This generalises across
//    architectures (x86 GPRs, arm64 x0-x30, riscv a*/s*/t*).
//
// Leak primitive:
//   Data leaked:      kernel text addresses, physical page-table base (CR3),
//                     directmap virtual addresses from register dumps
//   Kernel subsystem: arch/*/kernel — kernel oops handler (show_regs) +
//                     lib/dump_stack.c (the CPU/PID/Comm header)
//   Data structure:   struct pt_regs (register dump), call trace addresses
//   Address type:     virtual (kernel text / directmap) + physical (CR3 on x86)
//   Method:           parsed (dmesg oops output)
//   Status:           unfixed (oops output is essential for debugging)
//   Access check:     do_syslog() → check_syslog_permissions(); gated by
//                     dmesg_restrict
//   Source:
//   https://elixir.bootlin.com/linux/v6.12/source/arch/x86/kernel/dumpstack.c
//
// Mitigations:
//   Access gated by dmesg_restrict (see syslog.h for the shared access gate).
//   Oops output cannot be suppressed without CONFIG_PANIC_ON_OOPS.
//   %pK/%pS sanitization does not apply to oops register dumps.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
// - kernel.panic_on_oops = 0 (Default on most systems).
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include "include/syslog.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Extracts kernel addresses from oops/WARNING register dumps in dmesg. "
    "Bracketed [<ffffffff...>] tokens are kernel text pointers; register "
    "values in the direct-map range bound the direct-map base; the x86 CR3 "
    "register exposes the physical page-table base. CR3 is classified by the "
    "dump's process context — the idle task's CR3 is swapper_pg_dir (kernel "
    ".bss), any other task's is a process page table in generic DRAM. Access "
    "is gated by dmesg_restrict.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:virtual\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

/* Extraction state, accumulated across the whole log in one ordered pass. */
struct btctx {
  unsigned long text;      /* lowest kernel-text address seen (0 = none)      */
  unsigned long directmap; /* lowest directmap-range register value (0 = none)*/
  unsigned long cr3; /* lowest CR3 page-table base, phys (0 = none)      */
  int cr3_swapper;   /* chosen CR3's dump was idle-task (swapper) context*/
  /* Current dump's context, set by a header line and consumed by the next CR3
   * line, then reset — so each CR3 is attributed to its own dump, and an
   * evicted header degrades to the conservative non-swapper tag. */
  int ctx_known;
  int ctx_swapper;
};

/* True if an address is in the direct-map region: at/above PAGE_OFFSET but
 * below the text and module regions. On arches where the direct map overlaps
 * text (arm32, x86_32) PAGE_OFFSET >= KERNEL_VIRT_TEXT_MIN, so this is always
 * false — correctly, those arches expose no separable direct-map window here.
 */
static int in_directmap_range(unsigned long val) {
#if PAGE_OFFSET
  if (val < PAGE_OFFSET) /* vacuous where PAGE_OFFSET is 0 (s390) */
    return 0;
#endif
  if (val >= KERNEL_VIRT_TEXT_MIN)
    return 0;
#if MODULES_START >= PAGE_OFFSET
  if (kasld_addr_is_module_region(val))
    return 0;
#endif
  return 1;
}

/* Case-insensitive substring search; `needle` must be lower-case. Used instead
 * of strcasestr(), which is not portable across the cross toolchains. */
static const char *ci_find(const char *hay, const char *needle) {
  for (; *hay; hay++) {
    const char *h = hay, *n = needle;
    while (*n) {
      int hc = (unsigned char)*h;
      if (hc >= 'A' && hc <= 'Z')
        hc = hc - 'A' + 'a';
      if (hc != (unsigned char)*n)
        break;
      h++;
      n++;
    }
    if (!*n)
      return hay;
  }
  return NULL;
}

/* A dump header line carries both a pid and a comm token. The idle task — whose
 * CR3 is swapper_pg_dir (in .bss) — is PID 0 / comm "swapper". Matched
 * case-insensitively to cover every format dump_stack_print_info has printed:
 *   "CPU: 3 PID: 633 Comm: foo ..."           (current)
 *   "CPU: 3 UID: 0 PID: 633 Comm: foo ..."    (UID field added in v6.11)
 *   "Pid: 633, comm: foo ..."                 (pre-~v3.9: lower-case, comma)
 * Returns 1 and sets *swapper when the line is a header; 0 otherwise. */
static int parse_header(const char *line, int *swapper) {
  const char *pid = ci_find(line, "pid:");
  const char *comm = ci_find(line, "comm:");
  if (!pid || !comm)
    return 0;

  int sw = 0;

  const char *p = pid + 4; /* past "pid:" */
  while (*p == ' ' || *p == '\t')
    p++;
  char *endp;
  unsigned long pidv = strtoul(p, &endp, 10);
  if (endp != p && pidv == 0)
    sw = 1;

  const char *c = comm + 5; /* past "comm:" */
  while (*c == ' ' || *c == '\t')
    c++;
  if (ci_find(c, "swapper") == c) /* comm begins with "swapper" */
    sw = 1;

  *swapper = sw;
  return 1;
}

/* Architecture register-dump line markers. Each entry matches the start of a
 * register line in that architecture's show_regs() output; a matched line is
 * then scanned for all its hex values (the direct-map range check discards the
 * rest). Only architectures with a *separable* direct-map window are listed —
 * i.e. PAGE_OFFSET < KERNEL_VIRT_TEXT_MIN (equivalently
 * !TEXT_TRACKS_DIRECTMAP):
 *
 *   x86_64   RAX/RBX/RCX, RDX/RSI/RDI, RBP/R8/R9, R10..R15  (+ CR3)
 *   arm64    x0..x30   (three per line: "x0 :", "x4 :", ...)
 *   riscv64  gp/tp, t0..t6, s0..s11, a0..a7 (" gp :", " s1 :", ...)
 *
 * On coupled arches (x86_32, mips, loongarch, arm32, ppc) the kernel image
 * lives inside the direct-map region, so in_directmap_range() is always false
 * and register scanning would yield nothing; they fall through to the empty
 * list and rely on the call-trace path (and, on x86, the separate CR3 path).
 * The CR3 page-table base is x86-only — no other architecture prints a
 * page-table base register (TTBR/SATP) in its dump. */
#if defined(__x86_64__)
static const char *reg_needles[] = {
    "RAX:", "RDX:", "RBP:", "R10:", "R13:", NULL};
#elif defined(__aarch64__)
static const char *reg_needles[] = {
    "x0 :", "x4 :", "x8 :", "x12:", "x16:", "x20:", "x24:", "x28:", NULL};
#elif defined(__riscv) && __riscv_xlen == 64
static const char *reg_needles[] = {
    " gp :", " s1 :", " a2 :", " s2 :", " s5 :", " s8 :", " s11:", NULL};
#else
static const char *reg_needles[] = {NULL};
#endif

static int is_regdump_line(const char *line) {
  for (int i = 0; reg_needles[i]; i++)
    if (strstr(line, reg_needles[i]))
      return 1;
  return 0;
}

/* Hex-digit test (locale-independent; avoids <ctype.h>). */
static int is_hex_digit(int c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
         (c >= 'A' && c <= 'F');
}

/* Parse the next run of hex digits at or after *pp as a base-16 value (a "0x"
 * prefix is accepted). Leading non-hex characters are skipped. On success sets
 * *out, advances *pp past the run, and returns 1; returns 0 when the line is
 * exhausted. Bounds-safe: never reads past the terminating NUL, and always
 * advances, so callers cannot loop forever. The single hex extractor shared by
 * the text, direct-map, and CR3 scanners; incidental short runs (register-name
 * letters, symbol offsets) are filtered by each caller's range predicate. */
static int next_addr_token(const char **pp, unsigned long *out) {
  const char *p = *pp;
  while (*p && !is_hex_digit((unsigned char)*p))
    p++;
  if (!*p) {
    *pp = p;
    return 0;
  }
  char *end;
  *out = strtoul(p, &end, 16);
  *pp = (end > p) ? end : p + 1;
  return 1;
}

/* Scan a call-trace line for kernel-text addresses, keeping the lowest. */
static void scan_text(const char *line, struct btctx *c) {
  const char *p = line;
  unsigned long a;
  while (next_addr_token(&p, &a))
    if (a && kasld_addr_is_kernel_text(a) && (!c->text || a < c->text))
      c->text = a;
}

/* Scan a register-dump line for direct-map-range values, keep the lowest.
 *
 * A register value at/above PAGE_OFFSET is only a HEURISTIC upper bound on the
 * direct-map base, not a sound one: a real kernel VA (direct map / vmalloc /
 * vmemmap) is >= page_offset_base, but a register need NOT hold a pointer, and
 * a non-pointer value that lands in the wide window below the randomized
 * page_offset_base would be below the true base. The window floor here
 * (PAGE_OFFSET = 0xff00... on x86_64) sits far below the KASLR minimum base
 * (__PAGE_OFFSET_BASE_L4 = 0xffff888000000000) and even spans the non-canonical
 * hole, and page_offset_base randomizes only UPWARD from that minimum, so the
 * [floor, base) gap is real and can be many TB. No local test proves a value is
 * >= the (unknown, randomized) base, and "keep the lowest" actively selects the
 * value most likely to sit below it — so the emission is sub-floor (likely
 * window only). The stack pointer under CONFIG_VMAP_STACK is also a
 * vmalloc_base witness, but a register value cannot be classified as vmalloc vs
 * direct map before the randomized region bases are resolved, so a
 * vmalloc-specific bound belongs to the inference layer, not here. */
static void scan_directmap(const char *line, struct btctx *c) {
  const char *p = line;
  unsigned long v;
  while (next_addr_token(&p, &v))
    if (v && in_directmap_range(v) && (!c->directmap || v < c->directmap))
      c->directmap = v;
}

/* Parse the LoongArch first GPR line, "pc <hex> ra <hex> tp <hex> sp <hex>",
 * setting *pc and *ra to the raw kernel-text registers (0 when not found). pc
 * (= CSR.ERA, the faulting instruction) and ra (return address) are in kernel
 * text; tp/sp are not, but LoongArch is coupled (text and data share the
 * 0x9000... window) so they cannot be excluded by address range — hence the two
 * registers are read positionally by field name rather than range-scanned.
 * Always compiled (so it is unit-testable); only invoked on LoongArch, where
 * the marked-unused attribute is moot. */
__attribute__((unused)) static void
parse_loongarch_pc_ra(const char *line, unsigned long *pc, unsigned long *ra) {
  *pc = 0;
  *ra = 0;
  const char *p = strstr(line, "pc ");
  if (!p)
    return;
  p += 3;
  next_addr_token(&p, pc);
  const char *r = strstr(p, "ra ");
  if (r) {
    r += 3;
    next_addr_token(&r, ra);
  }
}

/* Per-line state machine for the single ordered pass. */
static void on_line(char *line, void *vctx) {
  struct btctx *c = vctx;

  /* Header line → (re)set the current dump context. */
  int sw;
  if (parse_header(line, &sw)) {
    c->ctx_known = 1;
    c->ctx_swapper = sw;
    return;
  }

  /* CR3 line (x86): "CR2: %lx CR3: %lx CR4: %lx". Attribute the value to the
   * current dump's context, then reset the context so the next CR3 must see its
   * own header (correct across multiple dumps; an evicted header → non-swapper,
   * i.e. the conservative REGION_RAM tag). */
  const char *cr3 = strstr(line, "CR3:");
  if (cr3) {
    const char *p = cr3 + 4;
    unsigned long v;
    if (next_addr_token(&p, &v) && v) {
      v &= ~(unsigned long)(PAGE_SIZE - 1); /* strip PCID/ASID low bits */
      if (!c->cr3 || v < c->cr3) {
        c->cr3 = v;
        c->cr3_swapper = c->ctx_known ? c->ctx_swapper : 0;
      }
    }
    c->ctx_known = 0;
    return;
  }

  /* Legacy bracketed call-trace text tokens (pre-symbolised kernels). */
  if (strstr(line, "[<")) {
    scan_text(line, c);
    return;
  }

  /* Register-dump line → direct-map-range values. */
  if (is_regdump_line(line)) {
    scan_directmap(line, c);
    return;
  }

#if defined(__loongarch__) && __loongarch_grlen == 64
  /* LoongArch prints raw kernel-text registers (pc/ra) instead of the
   * %pS-symbolised PC/LR of other arches. Read them positionally and keep the
   * lowest that is genuinely vmlinux text (a module ra in the 0xffff... region
   * is filtered out by the text-range check). */
  {
    unsigned long pc, ra;
    parse_loongarch_pc_ra(line, &pc, &ra);
    if (pc && kasld_addr_is_kernel_text(pc) && (!c->text || pc < c->text))
      c->text = pc;
    if (ra && kasld_addr_is_kernel_text(ra) && (!c->text || ra < c->text))
      c->text = ra;
  }
#endif
}

/* Walk every line of the kernel log in order, calling fn(line, ctx) per line.
 *
 * mmap_syslog gives a single ordered source so line order — hence dump-block
 * structure — is preserved: klogctl on a live system, or the captured
 * /var/log/dmesg under KASLD_SYSROOT (mmap_syslog handles that redirect). The
 * mapping is left to be reclaimed at process exit — these components are
 * one-shot. Returns 0 on success, -1 if no source is accessible. */
typedef void (*line_fn)(char *line, void *ctx);
static int foreach_dmesg_line(line_fn fn, void *ctx) {
  char *buf;
  int size;

  if (mmap_syslog(&buf, &size) != 0 || size <= 0)
    return -1;

  /* The mmap allocation is page-rounded strictly above `size`, so buf[size] is
   * a valid, writable byte — the buffer is safe to treat as line-terminable. */
  char *end = buf + size;
  char *p = buf;
  while (p < end) {
    char *nl = memchr(p, '\n', (size_t)(end - p));
    size_t len = nl ? (size_t)(nl - p) : (size_t)(end - p);
    p[len] = '\0';
    fn(p, ctx);
    if (!nl)
      break;
    p += len + 1;
  }
  return 0;
}

int main(void) {
  struct btctx ctx;
  memset(&ctx, 0, sizeof(ctx));

  kasld_info("searching dmesg for kernel oops information ...");

  if (foreach_dmesg_line(on_line, &ctx) < 0) {
    kasld_err("dmesg unavailable (klogctl denied and /var/log/dmesg "
              "unreadable)");
    return KASLD_EXIT_NOPERM;
  }

  if (!ctx.text && !ctx.directmap && !ctx.cr3) {
    kasld_err("no kernel oops information found in dmesg");
    return 0;
  }

  if (ctx.text) {
    kasld_info("lowest leaked text address: %lx", ctx.text);
    kasld_info("possible kernel base: %lx", kasld_floor_text_base(ctx.text));
    /* Call-trace addresses point at specific kernel text symbols; the symbol
     * name is not resolved, so the result is unnamed. */
    kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, ctx.text, NULL,
                        CONF_PARSED);
  }

  if (ctx.cr3) {
    kasld_found("leaked physical page-table base (CR3): %lx", ctx.cr3);
    if (ctx.cr3_swapper) {
      /* Idle-task context: CR3 == swapper_pg_dir, in kernel .bss. A genuine
       * image landmark — kernel_image_phys_bound pins the physical image base
       * from it (swapper sits a small fixed offset above _stext). */
      kasld_result_sample(KASLD_TYPE_PHYS, REGION_KERNEL_BSS, ctx.cr3, "cr3",
                          CONF_PARSED);
    } else {
      /* Task or unknown context: CR3 is a process PGD, allocated anywhere in
       * DRAM by the buddy allocator — not a kernel-image landmark. Tagged as
       * generic RAM: honest provenance, and it carries no image-base
       * information (the engine has no constraint to derive from it). */
      kasld_result_sample(KASLD_TYPE_PHYS, REGION_RAM, ctx.cr3, "cr3",
                          CONF_PARSED);
    }
#if defined(phys_to_directmap_virt) && TEXT_TRACKS_DIRECTMAP
    /* Coupled arches: project the CR3 phys to its direct-map virtual address.
     * Defensive — CR3 is x86-only and x86 is decoupled, so this is unreached in
     * practice — but kept correct: swapper → .bss virt, otherwise a generic
     * direct-map landmark. */
    {
      unsigned long virt = phys_to_directmap_virt(ctx.cr3);
      enum kasld_region r =
          ctx.cr3_swapper ? REGION_KERNEL_BSS : REGION_DIRECTMAP;
      kasld_info("possible direct-map virtual address: %lx", virt);
      kasld_result_sample(KASLD_TYPE_VIRT, r, virt, "cr3", CONF_PARSED);
    }
#endif
  }

  if (ctx.directmap) {
    kasld_found("leaked directmap virtual address: %lx", ctx.directmap);
    /* A register value that MIGHT be a direct-map address — but a register need
     * not hold a pointer, and one below the randomized page_offset_base would
     * forge a too-low page_offset ceiling (no local test rules that out; see
     * scan_directmap). Emit sub-floor (CONF_HEURISTIC) so it shapes only the
     * likely window and can never move the guaranteed one; a real direct-map
     * leak (proc_kcore, proc_net_sock_ptr) governs the guaranteed page_offset
     * bound. */
    kasld_result_sample(KASLD_TYPE_VIRT, REGION_DIRECTMAP, ctx.directmap, NULL,
                        CONF_HEURISTIC);
  }

  return 0;
}
