// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Definitions for Motorola 68000 series (m68k)
//
// Linux for m68k does not support KASLR.
//
// Kernel text is placed at a fixed, platform-defined base with no relocation:
// PAGE_OFFSET_RAW is CONFIG_RAMBASE on Motorola MMU, 0x0E000000 on Sun3, and
// 0x00000000 on nommu / ColdFire.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/m68k/include/asm/page_offset.h
// ---
// <bcoles@gmail.com>

#ifndef KASLD_M68K_H
#define KASLD_M68K_H

#error "m68k architecture is not supported!"

#define KASLR_SUPPORTED 0

#endif /* KASLD_M68K_H */
