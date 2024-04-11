// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Definitions for S390 (24-bit s370 / 32-bit s390 / 64-bit s390x)
//
// KASLR support added in commit b2d24b97b2a9691351920e700bfda4368c177232 in
// kernel v5.2-rc1~186^2~14 on 2019-02-03.
//
// kernel uses 1:1 phys:virt mapping.
// kernel text starts at 0x00000000_00100000 (1MiB) offset.
// Uses 24-bit (amode24), 32-bit (amode31) and 64-bit (amode64) addressing
// modes.
//
// References:
// https://github.com/torvalds/linux/commit/b2d24b97b2a9691351920e700bfda4368c177232
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/s390/mm/vmem.c#L665
// https://www.ibm.com/docs/en/zos-basic-skills?topic=1960s-what-is-virtual-storage
// https://share.confex.com/share/115/webprogram/Handout/Session6865/Understanding%20zOS%20CS%20storage%20use.pdf
// https://www.linux-kvm.org/images/a/ae/KVM_Forum_2018_s390_KVM_memory_management.pdf
// ---
// <bcoles@gmail.com>

#error "S390 architecture is not supported!"
