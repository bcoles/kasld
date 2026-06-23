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
int mmio_main(int argc, char **argv); /* this one parses CLI; see mmio_run() */
int pci_main(void);
int printk_main(int argc, char **argv); /* parses CLI; see printk_run() */
int rm_main(void); /* reserved-memory; (void) main, called directly */

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

#define main mmio_main
#include "../src/components/sysfs_devicetree_mmio.c"
#undef main

#define main printk_main
#include "../src/components/tracefs_printk_formats.c"
#undef main

#define main pci_main
#include "../src/components/sysfs_pci_resource.c"
#undef main

/* reserved_memory shares read_be32/read_cells names with the mmio component
 * already in this TU; rename on include to avoid static-symbol collisions. */
#define main rm_main
#define read_be32 rm_read_be32
#define read_cells rm_read_cells
#define read_binary rm_read_binary
#include "../src/components/sysfs_devicetree_reserved_memory.c"
#undef read_binary
#undef read_cells
#undef read_be32
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

/* Stage a device-tree property holding `n` big-endian 32-bit cells. */
static void stage_cells(const char *rel, const uint32_t *cells, int n) {
  unsigned char b[64];
  assert(n * 4 <= (int)sizeof(b));
  for (int i = 0; i < n; i++) {
    b[i * 4 + 0] = (unsigned char)(cells[i] >> 24);
    b[i * 4 + 1] = (unsigned char)(cells[i] >> 16);
    b[i * 4 + 2] = (unsigned char)(cells[i] >> 8);
    b[i * 4 + 3] = (unsigned char)(cells[i]);
  }
  stage(rel, b, (size_t)n * 4);
}

/* mmio_main parses CLI (-v etc.); the harness invokes parsers as fn(void), so
 * wrap it with a safe argv (argc=1 => no option parsing). */
static int mmio_run(void) {
  char arg0[] = "sysfs_devicetree_mmio";
  char *av[] = {arg0, NULL};
  return mmio_main(1, av);
}

static int printk_run(void) {
  char arg0[] = "tracefs_printk_formats";
  char *av[] = {arg0, NULL};
  return printk_main(1, av);
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

/* --- ACPI MRRM: base is "0x%llx" text. MRRM ranges are addressable system
 * memory (the image can live there), so they are a RAM landmark, never a
 * forbidden region. ------------------------------------------------------- */
static void test_acpi_mrrm_base(void) {
  stage_text("/sys/firmware/acpi/memory_ranges/range0/base", "0x100000000\n");
  run_capture(acpi_main);
  assert(strstr(cap, "P ram:range0") != NULL);
  assert(strstr(cap, "sample=0x100000000") != NULL);
}

/* --- coreboot CBMEM: address + sibling size ("0x%llx") -> reserved range. */
static void test_cbmem_address(void) {
  stage_text("/sys/bus/coreboot/devices/cbmem-00000abc/address",
             "0x100000000\n");
  stage_text("/sys/bus/coreboot/devices/cbmem-00000abc/size", "0x10000\n");
  run_capture(cbmem_main);
  assert(strstr(cap, "reserved_mem:cbmem-00000abc pos=base conf=parsed "
                     "lo=0x100000000 hi=0x10000ffff") != NULL);
}

/* --- CXL region: resource + sibling size ("%#llx") -> pmem range; -1 means
 * unallocated and is skipped. ------------------------------------------------
 */
static void test_cxl_region(void) {
  stage_text("/sys/bus/cxl/devices/region0/resource", "0x100000000\n");
  stage_text("/sys/bus/cxl/devices/region0/size", "0x40000000\n");
  /* An unallocated region reports 0xff..ff and must be skipped. */
  stage_text("/sys/bus/cxl/devices/region1/resource", "0xffffffffffffffff\n");
  run_capture(cxl_main);
  assert(strstr(cap, "pmem:region0 pos=base conf=parsed lo=0x100000000 "
                     "hi=0x13fffffff") != NULL);
  assert(strstr(cap, "ffffffffffffffff") == NULL);
}

/* --- Qualcomm RMTFS: phys_addr + sibling size ("%pa" = "0x%llx") -> reserved
 * range; a region with no size attribute falls back to a base-only sample. --
 */
static void test_qcom_rmtfs(void) {
  stage_text("/sys/class/rmtfs/qcom_rmtfs_mem0/phys_addr", "0x100000000\n");
  stage_text("/sys/class/rmtfs/qcom_rmtfs_mem0/size", "0x200000\n");
  stage_text("/sys/class/rmtfs/qcom_rmtfs_mem1/phys_addr", "0x200000000\n");
  run_capture(qcom_main);
  assert(strstr(cap, "reserved_mem:qcom_rmtfs_mem0 pos=base conf=parsed "
                     "lo=0x100000000 hi=0x1001fffff") != NULL);
  /* no size sibling -> base-only sample (degrades to the prior behavior) */
  assert(strstr(cap, "reserved_mem:qcom_rmtfs_mem1 pos=interior conf=parsed "
                     "sample=0x200000000") != NULL);
}

/* --- IOMMU reserved_regions: "0x%016llx 0x%016llx <type>" lines.
 * "msi" entries are skipped by type (even at a DRAM address); a "reserved"
 * entry in plausible DRAM is emitted as a single bounded range over its whole
 * contiguous span (each line is one fully-reserved region). --------------- */
static void test_iommu_reserved_regions(void) {
  stage_text("/sys/kernel/iommu_groups/0/reserved_regions",
             "0x0000000100000000 0x000000010000ffff msi\n"
             "0x0000000200000000 0x000000020000ffff reserved\n");
  run_capture(iommu_main);
  /* the reserved range is emitted as one bounded range [start, end], not two
   * disconnected interior points */
  assert(strstr(cap, "lo=0x200000000 hi=0x20000ffff") != NULL);
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

/* --- device-tree MMIO harvester: per-device "reg" (address+size cells)
 * decoded in CPU-physical space. Verifies the four soundness paths on one tree:
 * real MMIO below DRAM is emitted; a carveout inside the /memory range, an i2c
 * child (non-CPU child address space), and a CPU hartid (#size-cells 0) are all
 * excluded. -------------------------------------------------------------- */
static void test_devicetree_mmio(void) {
#define DTB "/sys/firmware/devicetree/base"
  uint32_t two = 2, one = 1, zero = 0;
  stage_cells(DTB "/#address-cells", &two, 1);
  stage_cells(DTB "/#size-cells", &two, 1);

  /* /memory@80000000 device_type=memory reg=0x80000000 size 0x20000000 */
  stage_text(DTB "/memory@80000000/device_type", "memory");
  uint32_t mem[] = {0, 0x80000000u, 0, 0x20000000u};
  stage_cells(DTB "/memory@80000000/reg", mem, 4);

  /* /soc: identity bus (empty ranges), 2/2 child cells */
  stage(DTB "/soc/ranges", "", 0);
  stage_cells(DTB "/soc/#address-cells", &two, 1);
  stage_cells(DTB "/soc/#size-cells", &two, 1);

  /* real MMIO below DRAM -> MUST emit */
  uint32_t uart[] = {0, 0x10000000u, 0, 0x1000u};
  stage_cells(DTB "/soc/uart@10000000/reg", uart, 4);

  /* i2c controller (own MMIO emitted) with a child in i2c address space */
  uint32_t i2c[] = {0, 0x10010000u, 0, 0x1000u};
  stage_cells(DTB "/soc/i2c@10010000/reg", i2c, 4);
  stage_cells(DTB "/soc/i2c@10010000/#address-cells", &one, 1);
  stage_cells(DTB "/soc/i2c@10010000/#size-cells", &zero, 1); /* no ranges */
  uint32_t eep[] = {0x50};
  stage_cells(DTB "/soc/i2c@10010000/eeprom@50/reg", eep, 1);

  /* carveout INSIDE the DRAM range -> MUST be excluded */
  uint32_t cz[] = {0, 0x90000000u, 0, 0x1000u};
  stage_cells(DTB "/carveout@90000000/reg", cz, 4);

  /* /cpus: hartids (#size-cells 0, no ranges) -> MUST be excluded */
  stage_cells(DTB "/cpus/#address-cells", &one, 1);
  stage_cells(DTB "/cpus/#size-cells", &zero, 1);
  uint32_t hart0[] = {0};
  stage_cells(DTB "/cpus/cpu@0/reg", hart0, 1);

  run_capture(mmio_run);

  /* emitted: real device MMIO (controller reg included) */
  assert(strstr(cap, "P mmio:uart@10000000") != NULL);
  assert(strstr(cap, "lo=0x10000000 hi=0x10000fff") != NULL);
  assert(strstr(cap, "P mmio:i2c@10010000") != NULL);
  /* excluded: i2c child, in-DRAM carveout, CPU hartid */
  assert(strstr(cap, "eeprom") == NULL);
  assert(strstr(cap, "carveout") == NULL);
  assert(strstr(cap, "0x90000000") == NULL);
  assert(strstr(cap, "cpu@0") == NULL);
#undef DTB
}

/* --- device-tree reserved-memory: each /reserved-memory child's reg is emitted
 * as a [base, base+size-1] RESERVED_MEM range (an in-RAM forbidden hole), not a
 * bare base point — so phys_reservation_exclude can carve it. -------------- */
static void test_devicetree_reserved_memory(void) {
#define RMB "/sys/firmware/devicetree/base"
  uint32_t two = 2;
  stage_cells(RMB "/#address-cells", &two, 1);
  stage_cells(RMB "/#size-cells", &two, 1);
  stage_cells(RMB "/reserved-memory/#address-cells", &two, 1);
  stage_cells(RMB "/reserved-memory/#size-cells", &two, 1);
  stage(RMB "/reserved-memory/ranges", "", 0);
  uint32_t reg[] = {0, 0x80000000u, 0, 0x40000u}; /* base 0x80000000, 256 KiB */
  stage_cells(RMB "/reserved-memory/mmode_resv0@80000000/reg", reg, 4);
  run_capture(rm_main);
  assert(strstr(cap, "P reserved_mem:mmode_resv0@80000000") != NULL);
  /* full extent, not just the base point */
  assert(strstr(cap, "lo=0x80000000 hi=0x8003ffff") != NULL);
#undef RMB
}

/* --- tracefs printk_formats: "0x<addr> : \"<fmt>\"" lines. The address is a
 * bare 0x%lx (no kptr_restrict gate). Kernel-text addresses are emitted as
 * interior witnesses; userspace addresses are skipped. Lowest+highest only. */
static void test_tracefs_printk_formats(void) {
  unsigned long ktext = 0xffffffff81000040UL; /* host kernel-text window */
  if (!kasld_addr_is_kernel_text(ktext))
    return;
  stage_text("/sys/kernel/tracing/printk_formats",
             "0xffffffff81000040 : \"alloc %d bytes\\n\"\n"
             "0xffffffff81234560 : \"hello %s\\n\"\n"
             "0x00007f0012340000 : \"userspace bogus\\n\"\n");
  run_capture(printk_run);
  assert(strstr(cap, "V kernel_text:printk_fmt") != NULL);
  assert(strstr(cap, "sample=0xffffffff81000040") != NULL); /* lowest */
  assert(strstr(cap, "sample=0xffffffff81234560") != NULL); /* highest */
  assert(strstr(cap, "0x00007f0012340000") == NULL);        /* user skipped */
}

/* --- PCI BARs: /sys/bus/pci/devices/<BDF>/resource — "start end flags" per
 * line. Each memory BAR is emitted as its own PCI_MMIO range named by BDF; the
 * BARs are scattered, so they must stay per-BAR ranges (never one [min,max]
 * span). I/O-port BARs (flag bit 0x100) and unallocated (0/0) BARs are skipped.
 */
static void test_pci_resource_per_bar(void) {
  /* dev A: one 8 MiB memory BAR + an unallocated BAR (0 0 0, skipped) */
  stage_text("/sys/bus/pci/devices/0000:00:02.0/resource",
             "0x00000000fb000000 0x00000000fb7fffff 0x0000000000040200\n"
             "0x0000000000000000 0x0000000000000000 0x0000000000000000\n");
  /* dev B: one 64 KiB memory BAR + an I/O-port BAR (flag 0x...101, skipped) */
  stage_text("/sys/bus/pci/devices/0000:00:14.0/resource",
             "0x00000000fe000000 0x00000000fe00ffff 0x0000000000040200\n"
             "0x000000000000c000 0x000000000000c0ff 0x0000000000040101\n");
  run_capture(pci_main);
  /* each memory BAR -> its own BDF-named PCI_MMIO range */
  assert(strstr(cap, "pci_mmio:0000:00:02.0 pos=base conf=parsed lo=0xfb000000 "
                     "hi=0xfb7fffff") != NULL);
  assert(strstr(cap, "pci_mmio:0000:00:14.0 pos=base conf=parsed lo=0xfe000000 "
                     "hi=0xfe00ffff") != NULL);
  /* the I/O-port BAR is skipped (not emitted as a band) */
  assert(strstr(cap, "0xc000") == NULL);
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
  RUN(test_devicetree_mmio);
  RUN(test_devicetree_reserved_memory);
  RUN(test_pci_resource_per_bar);
  RUN(test_tracefs_printk_formats);
  return TEST_DONE();
}
