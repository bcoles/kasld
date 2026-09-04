// This file is part of KASLD - https://github.com/bcoles/kasld
//
// The observing environment: the system's runtime hardening settings, and this
// process's vantage within them.
//
// Everything here answers "what can be seen from where kasld is standing",
// which is a different question from where the kernel is. Nothing in this file
// constrains a layout quantity or reaches the inference engine; the readout,
// the machine formats and the hardening advisor consume it.
//
// Two rules hold throughout:
//
//   Every fact is read from a path, through the SYSROOT layer, so replaying a
//   captured tree describes THAT system. A syscall answering for the machine
//   running the analysis would be invisible to anything that watches which
//   paths a fact came from — which is why the identity is parsed out of
//   /proc/self/status rather than asked of getuid(). The syscalls remain a
//   fallback for a live run that cannot read the file.
//
//   Every value carries an unknown distinct from a permissive one. "Could not
//   look" is not an observation, and reporting it as "nothing there" asserts an
//   absence of confinement that nothing established.
//
// The whole environment is taken once, before the first component runs, so the
// settings a denial is attributed to are the settings that denial happened
// under, and so nothing a renderer reports about the environment depends on the
// filesystem still answering the way it did when the analysis ran.
// ---
// <bcoles@gmail.com>

/* Stated here rather than inherited: this is a standalone translation unit, and
 * a suite that includes it alongside others must not have to order them to make
 * the declarations appear. */
#define _POSIX_C_SOURCE 200809L

#include "include/kasld/internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/* Read the first line of a file into `out`, without its trailing newline.
 * Returns 0 on success, -1 if the file could not be read or was empty.
 * /proc/self/attr entries are NUL-terminated rather than newline-terminated,
 * which the string handling below takes as the end of the value either way. */
static int read_proc_line(const char *path, char *out, size_t outsz) {
  out[0] = '\0';
  FILE *f = kasld_fopen(path, "r");
  if (!f)
    return -1;
  size_t n = fread(out, 1, outsz - 1, f);
  fclose(f);
  out[n] = '\0';
  out[strcspn(out, "\n")] = '\0';
  return out[0] ? 0 : -1;
}

/* Which marker a failed open of a hardening source earns, from errno.
 *
 * A refused read is kept apart from an absent one: every source read through
 * here is world-readable, so a refusal is not ordinary file permissions —
 * something above DAC is withholding the system's own settings. The two
 * support opposite conclusions about the vantage, and under a mandatory access
 * control policy a denied path can fail lookup exactly as a missing one does,
 * so the distinction has to come from errno or not at all.
 *
 * One place decides it for every reader that answers with these markers, so a
 * source cannot come to report a denial as an absence by being read somewhere
 * new. The lockdown mode and the string reads carry their own unknown and have
 * no denied to tell apart: securityfs is root-only on an ordinary system, so an
 * unprivileged refusal there is the normal case rather than a policy signal. */
static int unread_marker(void) {
  return (errno == EACCES || errno == EPERM) ? KASLD_SYSCTL_DENIED
                                             : KASLD_SYSCTL_UNREAD;
}

/* Read a /proc/sys/ file and return its integer value, or the marker its
 * failure earns.
 *
 * Neither marker is a small negative, because a small negative is a real
 * setting: perf_event_paranoid reports -1 for "unrestricted". */
static int read_sysctl_int(const char *path) {
  FILE *f = kasld_fopen(path, "r");
  if (!f)
    return unread_marker();
  int val;
  if (fscanf(f, "%d", &val) != 1)
    val = KASLD_SYSCTL_UNREAD;
  fclose(f);
  return val;
}

/* Detect kernel pointer hashing from /proc/cmdline. %pK (and %p) print a hashed
 * id unless no_hash_pointers / hash_pointers=never is on the boot cmdline.
 * Returns 1 (hashed — the default), 0 (raw), or the marker the failure earns.
 * /proc/cmdline is 0440 root:radio on Android, so a refusal here is a routine
 * vantage fact rather than a corner case. */
static int read_pointer_hashing(void) {
  FILE *f = kasld_fopen("/proc/cmdline", "r");
  if (!f)
    return unread_marker();
  char buf[4096];
  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  fclose(f);
  buf[n] = '\0';
  if (strstr(buf, "no_hash_pointers") || strstr(buf, "hash_pointers=never"))
    return 0;
  return 1;
}

/* Read /sys/kernel/security/lockdown and parse the active mode.
 * Format: "none [integrity] confidentiality" — bracketed word is active. */
static enum lockdown_mode read_lockdown(void) {
  FILE *f = kasld_fopen("/sys/kernel/security/lockdown", "r");
  if (!f)
    return LOCKDOWN_UNAVAILABLE;
  char buf[128];
  if (!fgets(buf, sizeof(buf), f)) {
    fclose(f);
    return LOCKDOWN_UNAVAILABLE;
  }
  fclose(f);

  char *open = strchr(buf, '[');
  char *close = open ? strchr(open, ']') : NULL;
  if (!open || !close)
    return LOCKDOWN_NONE;

  size_t len = (size_t)(close - open - 1);
  if (len >= 15 && memcmp(open + 1, "confidentiality", 15) == 0)
    return LOCKDOWN_CONFIDENTIALITY;
  if (len >= 9 && memcmp(open + 1, "integrity", 9) == 0)
    return LOCKDOWN_INTEGRITY;
  if (len >= 4 && memcmp(open + 1, "none", 4) == 0)
    return LOCKDOWN_NONE;
  return LOCKDOWN_NONE;
}

/* Read the runtime hardening state: the sysctls, kernel lockdown and pointer
 * hashing that gate what any process on this system can read. */
static void read_hardening_state(struct kasld_hardening *h) {
  h->kptr_restrict = read_sysctl_int("/proc/sys/kernel/kptr_restrict");
  h->dmesg_restrict = read_sysctl_int("/proc/sys/kernel/dmesg_restrict");
  h->perf_event_paranoid =
      read_sysctl_int("/proc/sys/kernel/perf_event_paranoid");
  h->unprivileged_bpf_disabled =
      read_sysctl_int("/proc/sys/kernel/unprivileged_bpf_disabled");
  h->panic_on_oops = read_sysctl_int("/proc/sys/kernel/panic_on_oops");
  h->lockdown = read_lockdown();
  h->hashed_pointers = read_pointer_hashing();
}

/* ---- Recon vantage: container + confinement facts, shared by all renderers
 * (text verbose block, JSON, markdown) so they can't diverge. Outside the
 * KASLD_TESTING guard because the render modules link against these. ------- */

const struct kasld_oracle kasld_oracles[KASLD_N_ORACLES] = {
    {"/proc/kallsyms", NULL, 0},
    {"/proc/kcore", NULL, 0},
    {"/proc/iomem", NULL, 0},
    {"/proc/modules", NULL, 0},
    {"/var/log/dmesg", NULL, 0},
    {"/var/log/kern.log", NULL, 0},
    {"/var/log/syslog", NULL, 0},
    {"/sys/kernel/debug", "debugfs", 0},
    {"/boot/System.map-", "/boot/System.map", 1},
    {"/boot/config-", "/boot/config", 1},
};

/* Held-cap → the kasld leak it unlocks. Bit numbers are the stable capability
 * ABI (linux/capability.h): CAP_SYS_RAWIO=17, CAP_SYS_ADMIN=21, CAP_SYSLOG=34,
 * CAP_PERFMON=38, CAP_BPF=39. Each maps to a real component. */
/* Groups that gate a source kasld reads. The Android ids are the reason this
 * table exists: `readproc` decides whether /proc/<pid> entries of other tasks
 * are visible at all under hidepid, and `radio` owns /proc/cmdline at 0440. */
const struct kasld_group_gate kasld_group_gates[KASLD_N_GROUP_GATES] = {
    {0, "root", "everything DAC-gated"},
    {4, "adm", "/var/log/dmesg past dmesg_restrict"},
    {1001, "radio", "/proc/cmdline (Android, 0440 root:radio)"},
    {1007, "log", "the Android log sources"},
    {3009, "readproc", "other tasks' /proc entries under hidepid"},
    {3012, "readtracefs",
     "tracefs printk_formats / available_filter_functions_addrs"},
};

const char *kasld_group_name(const struct kasld_vantage *v, int i) {
  if (i < 0 || i >= v->ngroups || !v->group_names[i][0])
    return NULL;
  return v->group_names[i];
}

const struct kasld_cap_leak kasld_cap_leaks[KASLD_N_CAP_LEAKS] = {
    {17, "CAP_SYS_RAWIO", "/proc/kcore _stext"},
    {21, "CAP_SYS_ADMIN", "/proc/iomem physical addresses"},
    {34, "CAP_SYSLOG", "/proc/kallsyms (kptr_restrict unmasked)"},
    {38, "CAP_PERFMON", "perf_event_open kernel sampling"},
    {39, "CAP_BPF", "BPF verifier-log pointer"},
};

/* Detect whether the run is inside a container and, if so, the runtime. All
 * reads
 * are unprivileged and SYSROOT-redirectable. Returns a runtime name or NULL
 * (not containerized / undetectable). Marker files are most reliable; cgroup
 * path patterns catch the rest. */
static const char *detect_container(void) {
  if (kasld_access("/.dockerenv", F_OK) == 0)
    return "docker";
  if (kasld_access("/run/.containerenv", F_OK) == 0)
    return "podman";

  const char *paths[] = {"/proc/self/cgroup", "/proc/1/cgroup"};
  for (int i = 0; i < 2; i++) {
    FILE *f = kasld_fopen(paths[i], "r");
    if (!f)
      continue;
    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    /* Substring scan of the whole cgroup file (covers both v1 multi-line and
     * v2's single "0::/…" line). Order is deliberate: most-specific runtime
     * markers first. Best-effort labelling only — never a security decision. */
    if (strstr(buf, "kubepods"))
      return "kubernetes";
    if (strstr(buf, "docker"))
      return "docker";
    if (strstr(buf, "libpod"))
      return "podman";
    if (strstr(buf, "/lxc"))
      return "lxc";
    if (strstr(buf, "machine.slice"))
      return "systemd-nspawn";
  }
  return NULL;
}

/* The /proc/self/status fields the vantage reads, taken in one pass.
 *
 * One open rather than one per field, and the identity is among them: this file
 * resolves through the sysroot layer, so replaying a captured tree reports the
 * identity that tree was collected under. getuid()/getgroups() answer for the
 * machine running the analysis, and being syscalls they are invisible to
 * anything that watches which paths a fact came from.
 *
 * Each value is the text after the colon with leading blanks removed. A field
 * the file does not carry stays empty, which every reader below takes as
 * unknown — so an unreadable file and a file missing one field need no
 * separate handling. */
struct status_fields {
  char uid[64];     /* "<real>\t<eff>\t<saved>\t<fs>", the kernel's own order */
  char gid[64];     /* likewise */
  char groups[512]; /* "<gid> <gid> ..." */
  int groups_cut;   /* the group list did not fit and was taken short */
  char seccomp[32];
  char no_new_privs[32];
  char cap_eff[32];
  char cap_bnd[32];
};

/* Copy the value of `field` out of one /proc/self/status line. Returns 0 when
 * the line names a different field, 1 when the whole value was taken, and 2
 * when it did not fit — which only the group list is long enough to reach.
 *
 * The name must be followed by its colon, so "Seccomp" does not also match
 * "Seccomp_filters" and "Gid" does not match "Ngid". */
static int status_take(const char *line, const char *field, char *out,
                       size_t outsz) {
  size_t flen = strlen(field);
  if (strncmp(line, field, flen) != 0 || line[flen] != ':')
    return 0;
  const char *v = line + flen + 1;
  while (*v == ' ' || *v == '\t')
    v++;
  /* No newline means fgets stopped mid-line: the value continues past what was
   * read. Checked before the copy, which can truncate for its own reason. */
  int cut = strchr(v, '\n') == NULL;
  int n = snprintf(out, outsz, "%s", v);
  out[strcspn(out, "\n")] = '\0';
  return (cut || n < 0 || (size_t)n >= outsz) ? 2 : 1;
}

static void read_status_fields(struct status_fields *s) {
  memset(s, 0, sizeof(*s));
  FILE *f = kasld_fopen("/proc/self/status", "r");
  if (!f)
    return;
  /* Wide enough for the whole Groups: line at any membership reported in full.
   * A longer one is split, and the continuation cannot be mistaken for a field
   * — it starts mid-number, never at "<name>:" — so it is noted as a cut,
   * which is the same answer the membership cap gives for such a list. */
  char line[1024];
  while (fgets(line, sizeof(line), f)) {
    int r = status_take(line, "Groups", s->groups, sizeof(s->groups));
    if (r) {
      s->groups_cut = r == 2;
      continue;
    }
    if (status_take(line, "Uid", s->uid, sizeof(s->uid)))
      continue;
    if (status_take(line, "Gid", s->gid, sizeof(s->gid)))
      continue;
    if (status_take(line, "Seccomp", s->seccomp, sizeof(s->seccomp)))
      continue;
    if (status_take(line, "NoNewPrivs", s->no_new_privs,
                    sizeof(s->no_new_privs)))
      continue;
    if (status_take(line, "CapEff", s->cap_eff, sizeof(s->cap_eff)))
      continue;
    if (status_take(line, "CapBnd", s->cap_bnd, sizeof(s->cap_bnd)))
      continue;
  }
  fclose(f);
}

/* Parse the first two ids of a status Uid:/Gid: line ("<real> <eff> ..."), the
 * only two the report names. Returns 0 leaving both alone if either is absent
 * or unparseable, so a malformed line yields no identity rather than half of
 * one. */
static int parse_id_pair(const char *s, unsigned long *real,
                         unsigned long *eff) {
  unsigned long r, e;
  const char *p;
  if (!kasld_addr_parse(s, 10, &r, &p) || !kasld_addr_parse(p, 10, &e, &p))
    return 0;
  *real = r;
  *eff = e;
  return 1;
}

/* Name each held group, in ONE pass over the group database rather than one
 * pass per member. Two sources, in order of authority:
 *
 *   /etc/group   read through the sysroot layer, so replaying a captured tree
 *                names ITS groups rather than the analysing host's — getgrgid()
 *                would silently answer from the wrong machine. Present but
 *                EMPTY on Android, where the ids live inside bionic.
 *   the gate table  for the ids kasld knows gate a source, which is exactly the
 *                set Android cannot name.
 *
 * A group neither knows keeps an empty name and is reported by number, which is
 * what the kernel checks anyway. */
static void resolve_group_names(struct kasld_vantage *v) {
  FILE *f = kasld_fopen("/etc/group", "r");
  if (f) {
    char line[512];
    while (fgets(line, sizeof(line), f)) {
      /* name:passwd:gid:members */
      char *c1 = strchr(line, ':');
      char *c2 = c1 ? strchr(c1 + 1, ':') : NULL;
      if (!c2)
        continue;
      unsigned long g;
      const char *e;
      if (!kasld_addr_parse(c2 + 1, 10, &g, &e))
        continue;
      *c1 = '\0';
      /* First entry wins for a repeated gid, matching a per-member lookup that
       * stopped at its first match. */
      for (int i = 0; i < v->ngroups; i++)
        if (v->groups[i] == g && !v->group_names[i][0])
          snprintf(v->group_names[i], sizeof(v->group_names[i]), "%.*s",
                   (int)sizeof(v->group_names[i]) - 1, line);
    }
    fclose(f);
  }
  for (int i = 0; i < v->ngroups; i++) {
    if (v->group_names[i][0])
      continue;
    for (int g = 0; g < KASLD_N_GROUP_GATES; g++)
      if (kasld_group_gates[g].gid == v->groups[i])
        snprintf(v->group_names[i], sizeof(v->group_names[i]), "%s",
                 kasld_group_gates[g].name);
  }
}

/* Ask the kernel directly for this process's identity. Only ever correct about
 * the machine kasld is running on, so it is reached only when no sysroot is
 * set — see kasld_gather_vantage(). Cannot fail: getuid() and friends have no
 * error return, and a group list too long for the report is counted rather
 * than dropped. */
static void identity_from_syscalls(struct kasld_vantage *v) {
  v->have_ids = 1;
  v->uid = (unsigned long)getuid();
  v->euid = (unsigned long)geteuid();
  v->gid = (unsigned long)getgid();
  v->egid = (unsigned long)getegid();
  gid_t buf[KASLD_N_GROUPS];
  int n = getgroups(KASLD_N_GROUPS, buf);
  if (n < 0) {
    /* Either the call failed or there are more than the array holds; ask for
     * the count alone to tell those apart. */
    int total = getgroups(0, NULL);
    v->ngroups = 0;
    v->groups_truncated = total > KASLD_N_GROUPS;
    if (total < 0)
      v->ngroups = -1;
  } else {
    v->ngroups = n;
    for (int i = 0; i < n; i++)
      v->groups[i] = (unsigned long)buf[i];
  }
}

/* Fill the supplementary group list from a status Groups: line. The membership
 * is kept up to KASLD_N_GROUPS and counted past it, so a longer list reports
 * as truncated rather than silently short. */
static void parse_groups(const char *s, int cut, struct kasld_vantage *v) {
  int total = 0;
  unsigned long g;
  const char *p;
  while (kasld_addr_parse(s, 10, &g, &p)) {
    if (total < KASLD_N_GROUPS)
      v->groups[total] = g;
    total++;
    s = p;
  }
  v->ngroups = total < KASLD_N_GROUPS ? total : KASLD_N_GROUPS;
  v->groups_truncated = cut || total > KASLD_N_GROUPS;
}

void kasld_gather_vantage(struct kasld_vantage *v) {
  memset(v, 0, sizeof(*v));
  v->container = detect_container();

  struct status_fields st;
  read_status_fields(&st);
  v->seccomp = st.seccomp[0] ? atoi(st.seccomp) : -1;
  v->no_new_privs = st.no_new_privs[0] ? atoi(st.no_new_privs) : -1;
  if (st.cap_eff[0]) {
    v->have_caps = 1;
    v->cap_eff = strtoull(st.cap_eff, NULL, 16);
    v->cap_bnd = st.cap_bnd[0] ? strtoull(st.cap_bnd, NULL, 16) : 0;
  }
  /* Resolved and probed here rather than where they are printed: the two
   * release-suffixed paths need the identity taken at the top of
   * kasld_env_snapshot(), and every format has to answer from one moment. A
   * run with no identity probes the bare prefix, which is not a file. */
  const char *release = kasld_env.have_uts ? kasld_env.uts.release : "";
  for (int i = 0; i < KASLD_N_ORACLES; i++) {
    if (kasld_oracles[i].release_suffixed)
      snprintf(v->oracle_path[i], sizeof v->oracle_path[i], "%s%s",
               kasld_oracles[i].path, release);
    else
      snprintf(v->oracle_path[i], sizeof v->oracle_path[i], "%s",
               kasld_oracles[i].path);
    v->oracle_readable[i] = kasld_access(v->oracle_path[i], R_OK) == 0;
  }

  /* Discretionary identity: the uid/gid pair the kernel checks first, and the
   * supplementary groups that decide the group-gated sources.
   *
   * From the status file above, so a replayed tree reports its own identity.
   * getuid()/getgroups() are the fallback for a live run that cannot read it:
   * there they cannot fail and are authoritative. Under a sysroot there is no
   * fallback — an unreadable status file leaves the identity unknown, because
   * answering with this host's is the error the file read avoids. */
  v->ngroups = -1;
  if (parse_id_pair(st.uid, &v->uid, &v->euid) &&
      parse_id_pair(st.gid, &v->gid, &v->egid)) {
    v->have_ids = 1;
    parse_groups(st.groups, st.groups_cut, v);
  } else if (kasld_fact_source() == KASLD_FACTS_LIVE) {
    identity_from_syscalls(v);
  }
  if (v->ngroups > 0)
    resolve_group_names(v);

  /* Mandatory access control. Three unprivileged reads, none of which is
   * available everywhere: securityfs carries the authoritative LSM list but is
   * unreachable under some policies (Android hides it from an app or shell
   * context), while selinuxfs and /proc/self/attr/current stay readable there.
   * Take whatever this vantage can see. */
  v->selinux = SELINUX_UNAVAILABLE;
  v->lsm_list[0] = '\0';
  v->sec_context[0] = '\0';
  read_proc_line("/sys/kernel/security/lsm", v->lsm_list, sizeof(v->lsm_list));
  read_proc_line("/proc/self/attr/current", v->sec_context,
                 sizeof(v->sec_context));
  char enf[16];
  if (read_proc_line("/sys/fs/selinux/enforce", enf, sizeof(enf)) == 0)
    v->selinux = enf[0] == '1' ? SELINUX_ENFORCING : SELINUX_PERMISSIVE;
}

/* An AppArmor profile is reported as "<profile> (<mode>)"; SELinux contexts
 * carry no parenthesised mode. Only enforce mode denies. */
static int apparmor_enforcing(const char *ctx) {
  return ctx[0] && strstr(ctx, "(enforce)") != NULL;
}

int kasld_vantage_mac_enforcing(const struct kasld_vantage *v) {
  return v->selinux == SELINUX_ENFORCING || apparmor_enforcing(v->sec_context);
}

const char *kasld_vantage_lsm_str(const struct kasld_vantage *v, char *out,
                                  size_t outsz) {
  const char *mode = v->selinux == SELINUX_ENFORCING    ? "enforcing"
                     : v->selinux == SELINUX_PERMISSIVE ? "permissive"
                                                        : NULL;
  if (v->lsm_list[0] && mode)
    snprintf(out, outsz, "%s (selinux %s)", v->lsm_list, mode);
  else if (v->lsm_list[0])
    snprintf(out, outsz, "%s", v->lsm_list);
  else if (mode)
    snprintf(out, outsz, "selinux (%s)", mode);
  else
    snprintf(out, outsz, "unknown");
  return out;
}

/* Confined = the confinement detail is meaningful; otherwise the values are
 * unprivileged defaults, not restrictions (see print_confinement). */
int kasld_vantage_confined(const struct kasld_vantage *v) {
  return v->container != NULL || v->seccomp > 0 || v->no_new_privs == 1 ||
         kasld_vantage_mac_enforcing(v);
}

const char *kasld_vantage_caps(const struct kasld_vantage *v, char *out,
                               size_t outsz) {
  if (!v->have_caps)
    return NULL;
  if (v->cap_eff == 0)
    snprintf(out, outsz, "none");
  else if (v->cap_eff == v->cap_bnd)
    snprintf(out, outsz, "full");
  else
    snprintf(out, outsz, "0x%llx", v->cap_eff);
  return out;
}

const char *kasld_vantage_seccomp_str(int seccomp) {
  return seccomp == 0   ? "none"
         : seccomp == 1 ? "strict"
         : seccomp == 2 ? "filter"
                        : "unknown";
}

void kasld_env_snapshot(void) {
  /* Identity first, with the rest: one acquisition for every format. */
  kasld_env.have_uts = (kasld_uname(&kasld_env.uts) == 0);
  read_hardening_state(&kasld_env.hardening);
  kasld_gather_vantage(&kasld_env.vantage);
}
