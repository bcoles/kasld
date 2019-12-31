// This file is part of KASLD - https://github.com/bcoles/kasld
// Check CPU for Intel TSX/RTM support
// - https://www.blackhat.com/docs/us-16/materials/us-16-Jang-Breaking-Kernel-Address-Space-Layout-Randomization-KASLR-With-Intel-TSX.pdf
// Excerpt from original code by vn1k:
// - https://github.com/vnik5287/kaslr_tsx_bypass/blob/master/util.c
// Note: may not be accurate for virtual machines:
// - https://stackoverflow.com/questions/47153723/how-to-check-for-tsx-support

#include <stdio.h>
#include <cpuid.h>

#define RTM_BIT (1 << 11)

/* CPU supports RTM execution if CPUID.07H.EBX.RTM [bit 11] = 1 */
int cpu_has_rtm(void) {
  if (__get_cpuid_max(0, NULL) >= 7) {
    unsigned a, b, c, d;
    __cpuid_count(7, 0, a, b, c, d);
    return (b & RTM_BIT);
  }
  return 0;
}

int main (int argc, char **argv) {
  printf("[.] checking CPU TSX/RTM support ...\n");

  if (cpu_has_rtm()) {
    printf("[.] CPU has TSX/RTM support. Try:\n- https://github.com/vnik5287/kaslr_tsx_bypass\n");
  } else {
    printf("[-] CPU does not support TSX/RTM\n");
  }
  return 0;
}
