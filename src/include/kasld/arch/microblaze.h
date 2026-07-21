// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Definitions for Xilinx MicroBlaze (microblaze)
//
// Linux for MicroBlaze does not support KASLR.
//
// With an MMU, PAGE_OFFSET is CONFIG_KERNEL_START (default 0xC0000000) and
// kernel text is fixed there at compile time; there is no relocation.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/microblaze/include/asm/page.h
// ---
// <bcoles@gmail.com>

#ifndef KASLD_MICROBLAZE_H
#define KASLD_MICROBLAZE_H

#error "MicroBlaze architecture is not supported!"

#define KASLR_SUPPORTED 0

#endif /* KASLD_MICROBLAZE_H */
