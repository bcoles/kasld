// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Parser unit tests for the sysfs / ACPI / device-tree leak components. Each
// component is #included with its main() (and its static read_file_line, where
// present) renamed so the parser is in scope, then driven over a staged
// KASLD_SYSROOT tree of hand-built fixture files. The fixtures reproduce the
// exact text/byte format the kernel exposes for each interface, so a test
// failing here means the parser no longer matches the kernel ABI it targets:
//
//   acpi_mrrm                 /sys/firmware/acpi/memory_ranges/rangeN/base
//   sysfs_cbmem_address       /sys/bus/coreboot/devices/cbmem-*/address
//   sysfs_cxl_region          /sys/bus/cxl/devices/regionN/resource
//   sysfs_qcom_rmtfs_mem      /sys/class/rmtfs/qcom_rmtfs_memN/phys_addr
//   sysfs_iommu_reserved_..   /sys/kernel/iommu_groups/N/reserved_regions
//   sysfs_efi_runtime_map     /sys/firmware/efi/runtime-map/N/{virt,phys}_addr
//   sysfs_devicetree_elf..    /sys/firmware/devicetree/base/chosen/...
//
// The components route their directory and file reads through the KASLD_SYSROOT
// wrappers, so the fixture tree is read in place of the live system. Each
// parser's main() is captured on stdout (the wire channel) and the emitted
// P/V record is checked.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

/* Pull in the public API once, then neutralise the two ELF-section macros so
 * the per-component KASLD_EXPLAIN/KASLD_META definitions do not collide when
 * several components are included into this single translation unit. */
#include "../src/include/kasld/api.h"
#undef KASLD_EXPLAIN
#undef KASLD_META
/* Expand to a uniquely-named file-scope declaration (not a definition) so
 * several components coexist in one TU without colliding ELF-section arrays or
 * redundant redeclarations, and the trailing ';' after each KASLD_EXPLAIN(...)
 * / KASLD_META(...) is absorbed. __COUNTER__ makes every name distinct. */
#define KASLD_CAT_(a, b) a##b
#define KASLD_CAT(a, b) KASLD_CAT_(a, b)
#define KASLD_EXPLAIN(t)                                                       \
  extern char KASLD_CAT(kasld_explain_unused_, __COUNTER__)[]
#define KASLD_META(t) extern char KASLD_CAT(kasld_meta_unused_, __COUNTER__)[]

/* Forward declarations for the renamed component entry points (avoids
 * -Wmissing-prototypes; the includes below define them). */
int efi_main(void);
int acpi_main(void);
int cbmem_main(void);
int cxl_main(void);
int qcom_main(void);
int iommu_main(void);
int dt_main(void);
int nd_main(void);
int uio_main(void);
int iscsi_main(void);

#define main efi_main
#define read_file_line efi_read_file_line
#include "../src/components/sysfs_efi_runtime_map.c"
#undef read_file_line
#undef main

#define main acpi_main
#define read_file_line acpi_read_file_line
#include "../src/components/acpi_mrrm.c"
#undef read_file_line
#undef main

#define main cbmem_main
#define read_file_line cbmem_read_file_line
#include "../src/components/sysfs_cbmem_address.c"
#undef read_file_line
#undef main

#define main cxl_main
#define read_file_line cxl_read_file_line
#include "../src/components/sysfs_cxl_region.c"
#undef read_file_line
#undef main

#define main qcom_main
#define read_file_line qcom_read_file_line
#include "../src/components/sysfs_qcom_rmtfs_mem.c"
#undef read_file_line
#undef main

#define main iommu_main
#include "../src/components/sysfs_iommu_reserved_regions.c"
#undef main

#define main dt_main
#include "../src/components/sysfs_devicetree_elfcorehdr.c"
#undef main

#define main nd_main
#include "../src/components/sysfs_nd_region.c"
#undef main

#define main uio_main
#define read_file_line uio_read_file_line
#include "../src/components/sysfs_uio_map.c"
#undef read_file_line
#undef main

#define main iscsi_main
#include "../src/components/sysfs_iscsi_transport_handle.c"
#undef main

#include "test_harness.h"

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static char g_root[256];

/* mkdir -p of the parent directory of <g_root><rel>, then return the full
 * path in `out`. */
static void full_path(const char *rel, char *out, size_t n) {
  snprintf(out, n, "%s%s", g_root, rel);
}

static void mkparents(const char *path) {
  char buf[512];
  snprintf(buf, sizeof(buf), "%s", path);
  for (char *p = buf + 1; *p; p++) {
    if (*p == '/') {
      *p = '\0';
      mkdir(buf, 0755);
      *p = '/';
    }
  }
}

/* Write `len` bytes to the sysroot-relative path. */
static void stage(const char *rel, const void *data, size_t len) {
  char path[512];
  full_path(rel, path, sizeof(path));
  mkparents(path);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  assert(fd >= 0);
  assert(write(fd, data, len) == (ssize_t)len);
  close(fd);
}

static void stage_text(const char *rel, const char *text) {
  stage(rel, text, strlen(text));
}

static void put_be64(unsigned char *p, uint64_t v) {
  for (int i = 0; i < 8; i++)
    p[i] = (unsigned char)(v >> (56 - 8 * i));
}

/* Run a renamed component main(), capturing its stdout (the wire channel) into
 * `cap`. Diagnostics go to stderr and are left alone. */
static char cap[16384];
static void run_capture(int (*fn)(void)) {
  fflush(stdout);
  char tmpl[] = "/tmp/kasld_parser_capXXXXXX";
  int fd = mkstemp(tmpl);
  assert(fd >= 0);
  int saved = dup(1);
  dup2(fd, 1);
  /* Silence the component's stderr diagnostics (kasld_info / kasld_err /
   * kasld_found) so they do not bleed into the test harness output. */
  fflush(stderr);
  int saved_err = dup(2);
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0)
    dup2(devnull, 2);
  fn();
  fflush(stdout);
  fflush(stderr);
  dup2(saved, 1);
  close(saved);
  dup2(saved_err, 2);
  close(saved_err);
  if (devnull >= 0)
    close(devnull);
  lseek(fd, 0, SEEK_SET);
  ssize_t n = read(fd, cap, sizeof(cap) - 1);
  cap[n > 0 ? n : 0] = '\0';
  close(fd);
  unlink(tmpl);
}

/* --- ACPI MRRM: base is "0x%llx" text ----------------------------------- */
static void test_acpi_mrrm_base(void) {
  stage_text("/sys/firmware/acpi/memory_ranges/range0/base", "0x100000000\n");
  run_capture(acpi_main);
  assert(strstr(cap, "P pmem:range0") != NULL);
  assert(strstr(cap, "sample=0x100000000") != NULL);
}

/* --- coreboot CBMEM: address is "0x%llx" text --------------------------- */
static void test_cbmem_address(void) {
  stage_text("/sys/bus/coreboot/devices/cbmem-00000abc/address",
             "0x100000000\n");
  run_capture(cbmem_main);
  assert(strstr(cap, "P reserved_mem:cbmem-00000abc") != NULL);
  assert(strstr(cap, "sample=0x100000000") != NULL);
}

/* --- CXL region: resource is "%#llx" text; -1 means unallocated ---------- */
static void test_cxl_region(void) {
  stage_text("/sys/bus/cxl/devices/region0/resource", "0x100000000\n");
  /* An unallocated region reports 0xff..ff and must be skipped. */
  stage_text("/sys/bus/cxl/devices/region1/resource", "0xffffffffffffffff\n");
  run_capture(cxl_main);
  assert(strstr(cap, "sample=0x100000000") != NULL);
  assert(strstr(cap, "ffffffffffffffff") == NULL);
}

/* --- Qualcomm RMTFS: phys_addr is "%pa" text ("0x%llx") ------------------ */
static void test_qcom_rmtfs(void) {
  stage_text("/sys/class/rmtfs/qcom_rmtfs_mem0/phys_addr", "0x100000000\n");
  run_capture(qcom_main);
  assert(strstr(cap, "P reserved_mem:qcom_rmtfs_mem0") != NULL);
  assert(strstr(cap, "sample=0x100000000") != NULL);
}

/* --- IOMMU reserved_regions: "0x%016llx 0x%016llx <type>" lines.
 * "msi" entries are skipped by type (even at a DRAM address); "reserved"
 * entries in plausible DRAM are emitted. ---------------------------------- */
static void test_iommu_reserved_regions(void) {
  stage_text("/sys/kernel/iommu_groups/0/reserved_regions",
             "0x0000000100000000 0x000000010000ffff msi\n"
             "0x0000000200000000 0x000000020000ffff reserved\n");
  run_capture(iommu_main);
  /* the reserved DRAM range is emitted (start and end) */
  assert(strstr(cap, "sample=0x200000000") != NULL);
  /* the msi range is skipped despite its DRAM address */
  assert(strstr(cap, "0x100000000") == NULL);
}

/* --- device-tree elfcorehdr: two big-endian u64 (address, size) --------- */
static void test_devicetree_elfcorehdr(void) {
  unsigned char blob[16];
  put_be64(blob + 0, 0x100000000ULL); /* address */
  put_be64(blob + 8, 0x10000ULL);     /* size    */
  stage("/sys/firmware/devicetree/base/chosen/linux,elfcorehdr", blob,
        sizeof(blob));
  run_capture(dt_main);
  assert(strstr(cap, "P crashkernel:elfcorehdr") != NULL);
  /* big-endian decode: address 0x100000000, hi = addr + size - 1 */
  assert(strstr(cap, "lo=0x100000000 hi=0x10000ffff") != NULL);
}

/* --- EFI runtime-map: virt_addr / phys_addr "0x%llx" text; the parser
 * derives virt_page_offset = virt - phys for a direct-map virtual address.
 * Uses host-arch direct-map constants (this interface is x86-only). ------- */
static void test_efi_runtime_map(void) {
  unsigned long virt = 0xffff888000001000UL;
  unsigned long phys = 0x1000UL;
  /* Only meaningful where the chosen virt is in the host's direct-map window
   * and virt-phys lands in the page-offset window (true on x86_64). */
  if (!kasld_addr_is_directmap(virt))
    return;
  stage_text("/sys/firmware/efi/runtime-map/0/virt_addr",
             "0xffff888000001000\n");
  stage_text("/sys/firmware/efi/runtime-map/0/phys_addr", "0x1000\n");
  run_capture(efi_main);
  assert(strstr(cap, "V virt_page_offset") != NULL);
  char want[64];
  snprintf(want, sizeof(want), "sample=0x%lx", virt - phys);
  assert(strstr(cap, want) != NULL);
}

/* --- libnvdimm nd_region: resource is "%#llx" text ---------------------- */
static void test_nd_region(void) {
  stage_text("/sys/bus/nd/devices/ndregion0/resource", "0x4000000000\n");
  run_capture(nd_main);
  assert(strstr(cap, "P pmem:ndregion0") != NULL);
  assert(strstr(cap, "sample=0x4000000000") != NULL);
}

/* --- UIO map: maps/mapN/addr is "%pa" text ("0x%llx"); region defaults to
 * mmio when /proc/iomem does not place the address in System RAM. ---------- */
static void test_uio_map(void) {
  stage_text("/sys/class/uio/uio0/maps/map0/addr", "0x90000000\n");
  stage_text("/sys/class/uio/uio0/maps/map0/name", "uio-mem\n");
  run_capture(uio_main);
  assert(strstr(cap, "P mmio:uio0/map0") != NULL);
  assert(strstr(cap, "sample=0x90000000") != NULL);
}

/* --- iSCSI transport handle (CVE-2021-27363): the "handle" attribute is a
 * decimal kernel pointer. KASLD_SYSROOT short-circuits the netlink autoload,
 * so the fixture is read directly. Uses a host-arch kernel-text address. --- */
static void test_iscsi_transport_handle(void) {
  unsigned long addr =
      0xffffffff81000000UL; /* in the host kernel-text window */
  if (!kasld_addr_is_kernel_text(addr))
    return;
  char dec[32];
  snprintf(dec, sizeof(dec), "%lu\n", addr);
  stage_text("/sys/class/iscsi_transport/iser/handle", dec);
  stage_text("/sys/class/iscsi_transport/tcp/handle", dec);
  run_capture(iscsi_main);
  assert(strstr(cap, "V kernel_data:iscsi_iser_transport") != NULL);
  char want[64];
  snprintf(want, sizeof(want), "sample=0x%lx", addr);
  assert(strstr(cap, want) != NULL);
}

int main(void) {
  /* One sysroot for the whole suite: each parser reads a distinct path, and
   * kasld_sysroot() caches its value process-wide, so a single root must be
   * set before any component runs. */
  char tmpl[] = "/tmp/kasld_parser_rootXXXXXX";
  char *r = mkdtemp(tmpl);
  assert(r != NULL);
  snprintf(g_root, sizeof(g_root), "%s", r);
  setenv("KASLD_SYSROOT", g_root, 1);

  TEST_SUITE("test_sysfs_parsers");
  BEGIN_CATEGORY("sysfs / ACPI / DT leak parsers");
  RUN(test_acpi_mrrm_base);
  RUN(test_cbmem_address);
  RUN(test_cxl_region);
  RUN(test_qcom_rmtfs);
  RUN(test_iommu_reserved_regions);
  RUN(test_devicetree_elfcorehdr);
  RUN(test_efi_runtime_map);
  RUN(test_nd_region);
  RUN(test_uio_map);
  RUN(test_iscsi_transport_handle);
  return TEST_DONE();
}
