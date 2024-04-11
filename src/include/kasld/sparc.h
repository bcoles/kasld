// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Definitions for SPARC (sparc / sparc64)
//
// Linux for sparc/sparc64 is largely abandoned and does not support KASLR.
//
// sparc32 kernel text starts at 0xf0004000
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/sparc/kernel/vmlinux.lds.S#L11
//
// sparc64 kernel text starts at 0x00000000_00404000
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/sparc/kernel/head_64.S#L39
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/sparc/kernel/vmlinux.lds.S#L18
// ---
// <bcoles@gmail.com>

#error "SPARC architecture is not supported!"
