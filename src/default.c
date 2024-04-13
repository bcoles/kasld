// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Print architecture default kernel base text virtual address
// ---
// <bcoles@gmail.com>

#include "include/kasld.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned long get_kernel_addr_default() {
  return (unsigned long)KERNEL_TEXT_DEFAULT;
}

int main() {
  unsigned long addr = get_kernel_addr_default();
  if (!addr)
    return 1;

  printf("common default kernel text for arch: %lx\n", addr);

  return 0;
}
