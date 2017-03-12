# Università di Pavia, Facoltà di Ingegneria, 2014
# MIPS I '85 32-bit R3000A compatible SPIM/MARS IO SYSCALL (AT&T SYNTAX)
#
# Luca Zanussi [410841] <luca.z@outlook.com>
#
# FIPS-197 / NIST Advanced Encryption Standard (Rijndael)
#  http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf
#  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
#
# > AES Library encryption core utility
#

# Function signatures format:
#
#   [return values] function(registers values)(stack values)
#
# parameters are passed left to right in registers and from lower
# RAM to higher addreses in stack (keep things simple) and no,
# they are not curried functions from Haskell and Scala.

.include "mmap" # Include custom memory map

.globl aes_iencr

.data DRAM_AESCORE_ADDR

.align 2 # align word

    # The size of a block is 4 * Nb (Nb is the size in DWORD), always 16.
    #  .extern block_encr 16
        
    block_buffer:     .space 16
    


.text TEXT_AESCORE_ADDR

# [errcode] aes_iencr(..., src_ptr, dst_ptr, ...)
#   --> Preserves $sX registers.
#   The internal encryption procedure uses 'aes_prepare' parameters and 
#   the key generated in 'key_schedule' to encrypt the given block and store
#   the result in the global 'block_encr'.
#   NOTE: The 1st stack thingy is the return address from the previous.
aes_iencr:
    # Save registers on stack
    add     $sp, $sp, -20
    sw      $s0,  0($sp)
    sw      $s1,  4($sp)
    sw      $s2,  8($sp)
    sw      $s3, 12($sp)
    sw      $s4, 16($sp)
    # $s5, $s6, $s7 always preserved as mode params.

    # PREVOIOUS SIGNATURE [errcode] aes_iencr(..., ..., ..., ...)(///, src_ptr, ..., ...)
    # Using directly the final output pointer as destination
    # so we will have the result in it after an even number of rounds, and so of buffer swaps.
    # lw      $s0, 4($sp)                       # Get source data pointer argument, initial source index
    move    $s0, $a1                            # ^^ new format
    la      $s1, key_schedule                   # Get pointer to current key schedule
    # la      $s2, block_encr                   # Get destination addr
    move    $s2, $a2                            # ^^ new format
    
    move    $s3, $zero                          # Initialize counter
    
    # $s0 Source data ptr.
    # $s1 Key sch. data ptr.
    # $s2 Destination data ptr.
    # $s3 Iteration counter
    # $s4 End iteration value
    # $s5, $s6, $s7   - from configuration -
    
    # $t0, $t1, $t2, $t3
    # $t4 Lookup pointer / key data buffer
    
aes_iencr$r1loop:
    lw      $t0, ($s0)                          # Get source dword
    lw      $t1, ($s1)                          # Get key dword
    xor     $t0, $t0, $t1                       # XOR key and value for 1st round
    sw      $t0, ($s2)                          # Save into destination address @block_buffer
    
    addi    $s0, $s0, 4                         # Increment source pointer
    addi    $s1, $s1, 4                         # Increment key schedule pointer
    addi    $s2, $s2, 4                         # Increment destination pointer
    
    addi    $s3, $s3, 1                         # Increment word counter
    blt     $s3, $s6, aes_iencr$r1loop          # Jump if not reached block size (Nb)
    
    # End 1st round, (round 0) prepare for next ops.
    # la      $s0, block_encr                   # Reset source ptr, from now operation constant, to the buffer just filled.
    move    $s0, $a2                            # ^^ new format
    la      $s1, key_schedule                   # Reset also this
    la      $s2, block_buffer                   # New destination ptr, we will swap these on each round, we will have 'block_encr'
                                                # here in the final round.
    # The instruction does not point to the given source argument because we don't want to overwrite source data.
    
    # Note that the counder $s3 is not resetted, we have done the 1st round already (spec. doesn't define it as a round).
    mul     $s4, $s6, $s7                       # Nb * Nr (block size x rounds)
aes_iencr$rnloop:
    # PLEASE NOTE: Following comments may not respect the content of instructions,
    # which work on little-endian words.
    
    add     $t0, $s3, 0                         # /// X0 ///
    rem     $t0, $t0, 4                         # (i + 0) % 4
    mul     $t0, $t0, 4                         # DWORD align
    add     $t0, $t0, $s0                       # Add source ptr. offset
    lw      $t0, ($t0)
    srl     $t0, $t0, 0
    and     $t0, 0xff                           # buf[(i + 0) % 4] >> 24 ( '& 0xff' NOT NECESSARY )
    la      $t4, te0
    mul     $t0, $t0, 4                         # DWORD align
    add     $t0, $t0, $t4                       # Add lookup ptr. offset
    lw      $t0, ($t0)                          # te0[ buf[(i + 0) % 4] >> 24 ]
    
    add     $t1, $s3, 1                         # /// X1 ///
    rem     $t1, $t1, 4                         # (i + 1) % 4
    mul     $t1, $t1, 4                         # DWORD align
    add     $t1, $t1, $s0                       # Add source ptr. offset
    lw      $t1, ($t1)
    srl     $t1, $t1, 8
    and     $t1, 0xff                           # buf[(i + 1) % 4] >> 16 & 0xff
    la      $t4, te1
    mul     $t1, $t1, 4                         # DWORD align
    add     $t1, $t1, $t4                       # Add lookup ptr. offset
    lw      $t1, ($t1)                          # te1[ buf[(i + 1) % 4] >> 16 & 0xff ]
    
    add     $t2, $s3, 2                         # /// X2 ///
    rem     $t2, $t2, 4                         # (i + 2) % 4
    mul     $t2, $t2, 4                         # DWORD align
    add     $t2, $t2, $s0                       # Add source ptr. offset
    lw      $t2, ($t2)
    srl     $t2, $t2, 16
    and     $t2, 0xff                           # buf[(i + 2) % 4] >> 8 & 0xff
    la      $t4, te2
    mul     $t2, $t2, 4                         # DWORD align
    add     $t2, $t2, $t4                       # Add lookup ptr. offset
    lw      $t2, ($t2)                          # te2[ buf[(i + 2) % 4] >> 8 & 0xff ]
    
    add     $t3, $s3, 3                         # /// X3 ///
    rem     $t3, $t3, 4                         # (i + 3) % 4
    mul     $t3, $t3, 4                         # DWORD align
    add     $t3, $t3, $s0                       # Add source ptr. offset
    lw      $t3, ($t3)
    srl     $t3, $t3, 24
    and     $t3, 0xff                           # buf[(i + 3) % 4] & 0xff (SHIFT NOT NECESSARY)
    la      $t4, te3
    mul     $t3, $t3, 4                         # DWORD align
    add     $t3, $t3, $t4                       # Add lookup ptr. offset
    lw      $t3, ($t3)                          # te3[ buf[(i + 3) % 4] & 0xff ]
    
    mul     $t4, $s3, 4                         # DWORD align of index
    add     $t4, $t4, $s1                       # Add offset (key ptr.)
    lw      $t4, ($t4)                          # = ksched[i]
    
    # ret[i % 4] = x0 ^ x1 ^ x2 ^ x3 ^ ksched[i]
    xor     $t0, $t0, $t1
    xor     $t0, $t0, $t2
    xor     $t0, $t0, $t3

    # We must change endianness of the words after MixColumns() due to the format of the tables.
    andi    $t1, $t0, 0x00ff00ff
    sll     $t1, $t1, 8
    andi    $t0, $t0, 0xff00ff00
    srl     $t0, $t0, 8                         # Shifted bytes
    or      $t0, $t0, $t1                       # Merge
    sll     $t1, $t0, 16
    srl     $t0, $t0, 16                        # Shifted HIWORD and LOWORD
    or      $t0, $t0, $t1                       # Merge
    
    # Now we can XOR with the correct endianness of the key schedule.
    xor     $t0, $t0, $t4                       # = x0 ^ x1 ^ x2 ^ x3 ^ ksched[i]
    
    # Get word inside block and write
    rem     $t5, $s3, 4                         # i % 4 (stored in $t5, because reused later)
    mul     $t4, $t5, 4                         # DWORD align
    add     $t4, $t4, $s2                       # Add offset (dest. ptr.)
    sw      $t0, ($t4)                          # ret[i % 4] = x0 ^ x1 ^ x2 ^ x3 ^ ksched[i]
    
    bne     $t5, 3, aes_iencr$rnloop2
    # Swap buffers if last of block
    move    $t0, $s2                            # tmp = ret   // 'buf' is always LATEST calculated block
    move    $s2, $s0                            # ret = buf   // 'ret' can be OVERWRITTEN
    move    $s0, $t0                            # buf = tmp   // 'tmp' value is INDETERMINED (= buf)
    
aes_iencr$rnloop2:
    add     $s3, $s3, 1                         # Increment iterator
    blt     $s3, $s4, aes_iencr$rnloop
    
    
    add     $s4, $s4, $s6                       # Start by adding another block size to the value that the counter shall reach:
                                                # It's like adding another round, so that (block size x (rounds + 1)),
                                                # BECAUSE THE FIRST DOESN'T REALlY COUNT AS A ROUND.
aes_iencr$reloop:
    # Only one round left, buffers already swapped, no MixColumns() so we use the '01' in the lookup tables generation vector.
    # Ok, this can be better looking, but...
    
        #	for (int i = opParams.Nb * opParams.Nr; i < opParams.Nb * (opParams.Nr + 1); i++) {
#		x1 = t->t2[ buf[(i + 0) % 4] >> 24        ] & 0xff000000;
#		x2 = t->t3[ buf[(i + 1) % 4] >> 16 & 0xff ] & 0x00ff0000;
#		x3 = t->t0[ buf[(i + 2) % 4] >>  8 & 0xff ] & 0x0000ff00;
#		x4 = t->t1[ buf[(i + 3) % 4]       & 0xff ] & 0x000000ff;
#		ret[i % 4] = x1 ^ x2 ^ x3 ^ x4 ^ rkeyd[i];
#	}

    #SAMPLE
    add     $t0, $s3, 0                         # /// XE0 ///
    rem     $t0, $t0, 4                         # (i + 0) % 4
    mul     $t0, $t0, 4                         # DWORD align
    add     $t0, $t0, $s0                       # Add source ptr. offset
    lw      $t0, ($t0)
    srl     $t0, $t0, 0
    and     $t0, 0xff                           # buf[(i + 0) % 4] & 0xff
    la      $t4, te2
    mul     $t0, $t0, 4                         # DWORD align
    add     $t0, $t0, $t4                       # Add lookup ptr. offset
    lw      $t0, ($t0)                          # te2[ buf[(i + 0) % 4] & 0xff ]
    
    add     $t1, $s3, 1                         # /// XE1 ///
    rem     $t1, $t1, 4                         # (i + 1) % 4
    mul     $t1, $t1, 4                         # DWORD align
    add     $t1, $t1, $s0                       # Add source ptr. offset
    lw      $t1, ($t1)
    srl     $t1, $t1, 8
    and     $t1, 0xff                           # buf[(i + 1) % 4] >> 8 & 0xff
    la      $t4, te3
    mul     $t1, $t1, 4                         # DWORD align
    add     $t1, $t1, $t4                       # Add lookup ptr. offset
    lw      $t1, ($t1)                          # te3[ buf[(i + 1) % 4] >> 8 & 0xff ]
    
    add     $t2, $s3, 2                         # /// X2 ///
    rem     $t2, $t2, 4                         # (i + 2) % 4
    mul     $t2, $t2, 4                         # DWORD align
    add     $t2, $t2, $s0                       # Add source ptr. offset
    lw      $t2, ($t2)
    srl     $t2, $t2, 16
    and     $t2, 0xff                           # buf[(i + 2) % 4] >> 16 & 0xff
    la      $t4, te0
    mul     $t2, $t2, 4                         # DWORD align
    add     $t2, $t2, $t4                       # Add lookup ptr. offset
    lw      $t2, ($t2)                          # te0[ buf[(i + 2) % 4] >> 16 & 0xff ]
    
    add     $t3, $s3, 3                         # /// X3 ///
    rem     $t3, $t3, 4                         # (i + 3) % 4
    mul     $t3, $t3, 4                         # DWORD align
    add     $t3, $t3, $s0                       # Add source ptr. offset
    lw      $t3, ($t3)
    srl     $t3, $t3, 24
    and     $t3, 0xff                           # buf[(i + 3) % 4] >> 24 & 0xff (SHIFT NOT NECESSARY)
    la      $t4, te1
    mul     $t3, $t3, 4                         # DWORD align
    add     $t3, $t3, $t4                       # Add lookup ptr. offset
    lw      $t3, ($t3)                          # te1[ buf[(i + 3) % 4] >> 24 & 0xff ]
    
    # This time we isolate the bytes multiplicated by '01' (i.e. the sbox value).
    andi    $t0, 0xff000000
    andi    $t1, 0x00ff0000
    andi    $t2, 0x0000ff00
    andi    $t3, 0x000000ff
    
    
    # FROM NOW ON AWESOME COPY-PASTE -------------------------------
    
    mul     $t4, $s3, 4                         # DWORD align of index
    add     $t4, $t4, $s1                       # Add offset (key ptr.)
    lw      $t4, ($t4)                          # = ksched[i]
    
    # ret[i % 4] = x0 ^ x1 ^ x2 ^ x3 ^ ksched[i]
    xor     $t0, $t0, $t1
    xor     $t0, $t0, $t2
    xor     $t0, $t0, $t3

    # We must change endianness of the words after MixColumns() due to the format of the tables.
    andi    $t1, $t0, 0x00ff00ff
    sll     $t1, $t1, 8
    andi    $t0, $t0, 0xff00ff00
    srl     $t0, $t0, 8                         # Shifted bytes
    or      $t0, $t0, $t1                       # Merge
    sll     $t1, $t0, 16
    srl     $t0, $t0, 16                        # Shifted HIWORD and LOWORD
    or      $t0, $t0, $t1                       # Merge
    
    # Now we can XOR with the correct endianness of the key schedule.
    xor     $t0, $t0, $t4                       # = x0 ^ x1 ^ x2 ^ x3 ^ ksched[i]
    
    # Get word inside block and write
    rem     $t5, $s3, 4                         # i % 4 (stored in $t5, because reused later) (NOT TRUE, COPYPASTE)
    mul     $t4, $t5, 4                         # DWORD align
    add     $t4, $t4, $s2                       # Add offset (dest. ptr.)
    sw      $t0, ($t4)                          # ret[i % 4] = x0 ^ x1 ^ x2 ^ x3 ^ ksched[i]
    
    # END OF COPY-PASTE --------------------------------------------
    
    add     $s3, $s3, 1                         # Increment iterator
    blt     $s3, $s4, aes_iencr$reloop          # Do another loop if not finished yet
    
    
    # TEMP DEBUG INTERRUPT
    #li    $v0, 17
    #li    $a0, 99
    #syscall
    
    # Load registers on stack
    lw      $s0,  0($sp)
    lw      $s1,  4($sp)
    lw      $s2,  8($sp)
    lw      $s3, 12($sp)
    lw      $s4, 16($sp)
    add     $sp, $sp, 20
    # $s5, $s6, $s7 always preserved as mode params.
    
    jr    $ra
