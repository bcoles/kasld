// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Definitions for SuperH (sh / sh4)
//
// Linux for SuperH does not support KASLR.
//
// With an MMU, PAGE_OFFSET defaults to 0x80000000 and kernel text is placed
// at a fixed compile-time offset above it; there is no relocation.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/sh/mm/Kconfig
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/sh/kernel/vmlinux.lds.S
// ---
// <bcoles@gmail.com>

#ifndef KASLD_SH_H
#define KASLD_SH_H

#error "SuperH architecture is not supported!"

#define KASLR_SUPPORTED 0

#endif /* KASLD_SH_H */
