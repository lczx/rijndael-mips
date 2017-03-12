# Università di Pavia, Facoltà di Ingegneria, 2014
# MIPS I '85 32-bit R3000A compatible SPIM/MARS IO SYSCALL (AT&T SYNTAX)
#
# Luca Zanussi [410841] <luca.z@outlook.com>
#
# FIPS-197 / NIST Advanced Encryption Standard (Rijndael)
#  http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf
#  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
#
# > Example program implementing the AES library
#

# Function signatures format:
#
#   [return values] function(registers values)(stack values)
#
# parameters are passed left to right in registers and from lower
# RAM to higher addreses in stack (keep things simple) and no,
# they are not curried functions from Haskell and Scala.

.globl main

.data # >>> Testing keys & data

.align 2 # align word

    sys_dstptr:     .space 128
    sys_srcptr:     .ascii "perfect!"
    sys_keyptr:     .byte 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0a 0x0b 0x0c 0x0d 0x0e 0x0f
    
    sys_srcdsiz:    .word 8 # Provided source size
    sys_dstdsiz:    .word 128 # Destination allocated space in bytes
    
    sys_128ksiz:    .word 16  # Provided 128 bits key size in bytes
    sys_192ksiz:    .word 24  # Provided 192 bits key size in bytes
    sys_256ksiz:    .word 32  # Provided 256 bits key size in bytes
    
    
    
    # TEST 1 -------------------------------------------------------
    dbg1_plaintext: .byte 0x32 0x43 0xf6 0xa8 0x88 0x5a 0x30 0x8d 0x31 0x31 0x98 0xa2 0xe0 0x37 0x07 0x34
    
    dbg1_128key:    .byte 0x2b 0x7e 0x15 0x16 0x28 0xae 0xd2 0xa6 0xab 0xf7 0x15 0x88 0x09 0xcf 0x4f 0x3c

    dbg1_192key:    .byte 0x8e 0x73 0xb0 0xf7 0xda 0x0e 0x64 0x52 0xc8 0x10 0xf3 0x2b 0x80 0x90 0x79 0xe5
                          0x62 0xf8 0xea 0xd2 0x52 0x2c 0x6b 0x7b

    dbg1_256key:    .byte 0x60 0x3d 0xeb 0x10 0x15 0xca 0x71 0xbe 0x2b 0x73 0xae 0xf0 0x85 0x7d 0x77 0x81
                          0x1f 0x35 0x2c 0x07 0x3b 0x61 0x08 0xd7 0x2d 0x98 0x10 0xa3 0x09 0x14 0xdf 0xf4
    
    # TEST 2 -------------------------------------------------------
    dbg2_plaintext:  .byte 0x00 0x11 0x22 0x33 0x44 0x55 0x66 0x77 0x88 0x99 0xaa 0xbb 0xcc 0xdd 0xee 0xff
    
    # Other keys are subsets of this one, only passed key size change is necessary
    dbg2_key:       .byte 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0a 0x0b 0x0c 0x0d 0x0e 0x0f
                          0x10 0x11 0x12 0x13 0x14 0x15 0x16 0x17 0x18 0x19 0x1a 0x1b 0x1c 0x1d 0x1e 0x1f
                          
    # expected 128 out: 69c4e0d8 6a7b0430 d8cdb780 70b4c55a
    # expected 192 out: dda97ca4 864cdfe0 6eaf70a0 ec0d7191
    # expected 256 out: 8ea2b7ca 516745bf eafc4990 4b496089
    
.text

# Application entry point
main:
    jal     debug
    
    li      $v0, 10
    syscall                                     # SYSCALL 10 - Exit application

# [--] debug()
#   Uses predefined debug keys and data and checks return values
debug:
    # 1st stack entry never used...
    # otherwise if used before, it will be overwritten
    add     $sp, $sp, -4
    sw      $ra, 0($sp)                         # Save return address as usual
    
    # Theoretically we should respect the convention and pass 4+ arguments on the stack; but here,
    # for the sake of my mental illness, we are passing "something here, something there".
    # Params are so fuzzy for internal optimization (length vars discarded after checks).
    lw      $a0, sys_srcdsiz                    # 1st argument: Source data size
    lw      $a1, sys_dstdsiz                    # 2nd argument: Destination data size
    lw      $a2, sys_128ksiz                    # 3rd argument: Key size
    li      $a3, 0x09                           # 4th argument: Mode of operation 0x00000001 (AES-128-ECB-NOPAD)
    # 0x03 0011 - 256 nopad
    # 0x0b 1011 - 256 pad
    # 0x09 1001 - 128 pad
    
    add     $sp, $sp, -12
    la      $t0, sys_srcptr
    sw      $t0, 0($sp)                         # 1st stackarg: Source data pointer
    la      $t0, sys_dstptr
    sw      $t0, 4($sp)                         # 2nd stackarg: Destination data pointer
    la      $t0, sys_keyptr
    sw      $t0, 8($sp)                         # 3rd stackarg: Key pointer
    
    jal     aes_encrypt                         # [errcode] aes_encrypt(src_sz, dst_sz, key_sz, opflags)(src_ptr, dest_ptr, key_ptr)
    
    add     $sp, $sp, 12                        # Cleanup params from stack
    
    #
    #
    # Do something with results here...
    #
    #
    
    lw      $ra, 0($sp)
    add     $sp, $sp, 4                         # Retrieve return address from stack
    jr      $ra                                 # Return to caller
