// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Definitions for OpenRISC (or1k / openrisc)
//
// Linux for OpenRISC does not support KASLR.
//
// PAGE_OFFSET (KERNELBASE) is fixed at 0xc0000000 and kernel text is placed
// there at compile time; there is no relocation.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/openrisc/include/asm/page.h
// ---
// <bcoles@gmail.com>

#ifndef KASLD_OPENRISC_H
#define KASLD_OPENRISC_H

#error "OpenRISC architecture is not supported!"

#define KASLR_SUPPORTED 0

#endif /* KASLD_OPENRISC_H */
