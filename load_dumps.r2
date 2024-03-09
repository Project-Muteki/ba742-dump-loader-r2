# Load with `r2 -i load_dumps.r2 --`

# Arch-specific stuff
e asm.arch=arm
e asm.bits=32
e asm.cpu=cortex
e anal.cc=arm32
e r2ghidra.lang=ARM:LE:32:v5:
e io.cache=true
# Disable const propagation and do not guess what is constant since it seems to cause problems
# This is a hack and we need to figure out why r2ghidra is doing this erratic const propagation
#e r2ghidra.roprop=0
". ./imx233.r2i"

# Label locations
fs+sections
f section.sram 0x8000 @ 0x0
f section.sdram 0x2000000 @ 0x40000000
f section.sdram.code 0x380000 @ 0x40000000
f section.sdram.bss 0x180000 @ 0x40380000
f section.sdram.heapbase 0x1b00000 @ 0x40500000

# These are obtained from diffing and looking at the data. Might be misleading down the line so disabled for now.
#f section.sdram.text 0x2ac334 @ section.sdram
#f section.sdram.rodata 0x57284 @ section.sdram.text + `fl @ section.sdram.text`
#f section.sdram.bss 0x77fb8 @ 0x40380000
fs-
fs *

# Map files
of "private/sram@0x0.dmp"
om 3 section.sram `fl @ section.sram` 0x0 rwx sram
of "private/sdram@0x40000000.dmp"
om 4 section.sdram.code `fl @ section.sdram.code` 0x0 r-x sdram.code
om 4 section.sdram.bss `fl @ section.sdram.bss` `?v section.sdram.bss - section.sdram` rwx sdram.bss
om 4 section.sdram.heapbase `fl @ section.sdram.heapbase` `?v section.sdram.heapbase - section.sdram` rwx sdram.heap
# idk why these are needed
omf 3 rwx
omf 4 rwx

# Import SRAM layout
". ./vectors.r2i"
f fcn.__excvec_reset @ section.sram+0x40
f fcn.__excvec_fiq_handler @ section.sram+0x58
f fcn.__excvec_irq_handler @ section.sram+0x70
f fcn.__excvec_illegal_inst @ section.sram+0x88
f fcn.__excvec_svc @ section.sram+0xa0
f fcn.__excvec_data_abort @ section.sram+0xb8
f fcn.__excvec_prefetch_abort @ section.sram+0xd0

# Load extra functions and flags
". ./miscfcns.r2i"

# Load per-dump memchunk info
". ./private/memchunks.r2i"

# Load syscalls (requires miscfcns.r2i)
". ./syscalls_sdk.r2i"
". ./syscalls_sdk_hpprime.r2i"
". ./syscalls_krnl.r2i"

# Load syscall signature overrides
". ./syscall_sig.r2i"

# Seek to main memory
s section.sdram
