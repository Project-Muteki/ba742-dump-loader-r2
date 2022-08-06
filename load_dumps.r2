# Load with `r2 -i load_dumps.r2 --`

# Arch-specific stuff
e asm.arch=arm
e asm.bits=32
e asm.cpu=cortex
". ./imx233.r2i"

# Label locations
fs+sections
f section.sram 0x8000 @ 0x0
f section.sdram 0x2000000 @ 0x40000000
f section.sdram.heapbase @ 0x40500000
fs-
fs *

# Map files
o "private/sram@0x0.dmp" section.sram rwx
e anal.cc=arm32
o "private/sdram@0x40000000.dmp" section.sdram rwx
e anal.cc=arm32

# Import SRAM layout
". ./vectors.r2i"
af fcn.__excvec_reset @ section.sram+0x40
af fcn.__excvec_fiq_handler @ section.sram+0x58
af fcn.__excvec_irq_handler @ section.sram+0x70
af fcn.__excvec_illegal_inst @ section.sram+0x88
af fcn.__excvec_svc @ section.sram+0xa0
af fcn.__excvec_data_abort @ section.sram+0xb8
af fcn.__excvec_prefetch_abort @ section.sram+0xd0

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
