# /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# /// SHITTY IMPLEMENTATION HERE //////////////////////////////////////////////////////////////////////////////////////////////////////////

    # ----- Now we schedule encryption mode of operation considering padding.
    # $s4: block size in bytes (16 Bytes)
    # $a0: source size (used once)
    # $s3: Remaining block amount (to pad)                  $s0: Source current address
    # $a1: Passed source address (can be altered buffer)    $s1: Source end address
    # $a2: Destination current address
    
    mul     $s4, $s6, 4                         # Get block size in bytes (should be 16)
    div     $a0, $s4                            # Divide source size by number of blocks (so we can get iterations and padding)
    mfhi    $s3                                 # Get (optional) remaining partial block size (MOD or REM)

    # 'dst_sz' ($a1) and 'key_sz' ($a2) used only for checks, can now be overwritten as args of 'aes_iencr'
    mflo    $t0                                 # Get number of full blocks (DIV)
    mul     $t0, $t0, $s4                       # Mult. # blocks per block size...
    lw      $s0, 4($sp)                         # Load base source address
    add     $s1, $s0, $t0                       # ... and add base address to get end addr.
    
    lw      $a2, 8($sp)                         # Load destination address
    
    la      $t2, init_vector                    # Load IV
    
loop1:
    and     $t0, $a3, 0x04
    beqz    $t0, loop1_ecb
    
    # CBC Input setup (in: $t2)
    lw      $t4,  0($s0)
    lw      $t8,  0($t2)
    xor     $t4, $t4, $t8                       # Xor 1st part of input
    lw      $t5,  4($s0)
    lw      $t8,  4($t2)
    xor     $t5, $t5, $t8                       # Xor 2nd part of input
    lw      $t6,  8($s0)
    lw      $t8,  8($t2)
    xor     $t6, $t6, $t8                       # Xor 3rd part of input
    lw      $t7, 12($s0)
    lw      $t8, 12($t2)
    xor     $t7, $t7, $t8                       # Xor 4th part of input
    la      $t2, source_prebuf
    sw      $t4,  0($t2)
    sw      $t5,  4($t2)
    sw      $t6,  8($t2)
    sw      $t7, 12($t2)                        # Save in prebuf
    move    $a1, $t2                            # prebuf is source, pass it.
    j loop1_in
    
    # ECB Input setup
loop1_ecb:
    move    $a1, $s0                            # In ECB, source is not altered, just pass it.
    
    # Encrypt full blocks
loop1_in:

    # Execute block cipher task (preserves $aX and $sX registers)
    jal     aes_iencr
    
    
    move    $t2, $a2                            # Set $t2 to the previous encrypted block: XORd at the end in CBC
    add     $s0, $s0, $s4
    add     $a2, $a2, $s4                       # Increment pointers by block size
    blt     $s0, $s1, loop1                     # Loop 'til last last full block
    
    # End of loop, last block (if not aligned)
    and     $t0, $a3, 0x08                      # 'aes_prepare' already managed if this is not aligned
    beqz    $t0, aes_encrypt$eof                # but padding is disabled. If padding is off, we have finished.
    
    # Use PKCS #5 padding format, ($s1 = $s0)  
    add     $s2, $s1, $s4                       # s2: End of full block address (data+pad) (cur. ptr. + block siz.)
    add     $s1, $s1, $s3                       # s1: End of block data address (cur. ptr. + remaining block amt.)
    la      $t0, source_prebuf                  # Destination is the pre-encryption buffer
    
    # Copy final partial block + padding in the prebuf
loop2data:
    lbu     $t1, ($s0) # if s0 < s1             # Byte I/O
    sb      $t1, ($t0)                          # Byte I/O
    add     $s0, $s0, 1                         # Incr. source 1 byte
    add     $t0, $t0, 1                         # Incr. destination 1 byte
    blt     $s0, $s1, loop2data                 # Loop 'til end of PARTIAL DATA
    # End of loop
    
    sub     $t1, $s4, $s3                       # Get padding size (= byte to be written)
loop2pad:
    sb      $t1, ($t0)                          # Byte I/O
    add     $s0, $s0, 1                         # Increment source but out of bounds, used only as counter.
    add     $t0, $t0, 1                         # Increment destination
    blt     $s0, $s2, loop2pad                  # Loop 'til end of FULL BLOCK
    # End of loop
    
    la      $s0, source_prebuf
    
    and     $t0, $a3, 0x04
    beqz    $t0, final_ecb
    
    # CBC Input setup (in: $t2)
    lw      $t4,  0($s0)
    lw      $t8,  0($t2)
    xor     $t4, $t4, $t8                       # Xor 1st part of input
    lw      $t5,  4($s0)
    lw      $t8,  4($t2)
    xor     $t5, $t5, $t8                       # Xor 2nd part of input
    lw      $t6,  8($s0)
    lw      $t8,  8($t2)
    xor     $t6, $t6, $t8                       # Xor 3rd part of input
    lw      $t7, 12($s0)
    lw      $t8, 12($t2)
    xor     $t7, $t7, $t8                       # Xor 4th part of input
    la      $t2, source_prebuf
    sw      $t4,  0($t2)
    sw      $t5,  4($t2)
    sw      $t6,  8($t2)
    sw      $t7, 12($t2)                        # Save in prebuf
    move    $a1, $t2                            # prebuf is source, pass it.
    j loop1_in
    # ECB Input setup
final_ecb:
    move      $a1, $s0                          # In ECB, source is not altered, just pass it.
                                                # Now source is the prebuf
                                                
    # a2 was already set by last encryption loop to last block ptr.
    jal     aes_iencr

# /// END SHITTY IMPLEMENTATION ///////////////////////////////////////////////////////////////////////////////////////////////////////////
# /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
