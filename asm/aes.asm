# Università di Pavia, Facoltà di Ingegneria, 2014
# MIPS I '85 32-bit R3000A compatible SPIM/MARS IO SYSCALL (AT&T SYNTAX)
#
# Luca Zanussi [410841] <luca.z@outlook.com>
#
# FIPS-197 / NIST Advanced Encryption Standard (Rijndael)
#  http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf
#  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
#
# > AES Library core module
#

# Function signatures format:
#
#   [return values] function(registers values)(stack values)
#
# parameters are passed left to right in registers and from lower
# RAM to higher addreses in stack (keep things simple) and no,
# they are not curried functions from Haskell and Scala.

# Supported modes:
#   MODE                    CIPHER KEY SIZE         BLOCK CIPHER MODE OF OPERATION          PADDING
#    AES-128-ECB             128 bits                Electronic code book                    Yes
#    AES-128-ECB-NOPAD       128 bits                Electronic code book                    No
#    AES-128-CBC             128 bits                Cipher block chaining                   Yes
#    AES-128-CBC-NOPAD       128 bits                Cipher block chaining                   No
#    AES-192-ECB             192 bits                Electronic code book                    Yes
#    AES-192-ECB-NOPAD       192 bits                Electronic code book                    No
#    AES-192-CBC             192 bits                Cipher block chaining                   Yes
#    AES-192-CBC-NOPAD       192 bits                Cipher block chaining                   No
#    AES-256-ECB             256 bits                Electronic code book                    Yes
#    AES-256-ECB-NOPAD       256 bits                Electronic code book                    No
#    AES-256-CBC             256 bits                Cipher block chaining                   Yes
#    AES-256-CBC-NOPAD       256 bits                Cipher block chaining                   No

# PLEASE NOTE: Data decryption not supported yet, please use OpenSSL or similar software to decrypt
#              the obtained ciphertext.

# OPFLAGS nibble reference format:
#   0x0000PBMM
#           ^^ Expected key size: 00 (reserved), 01 (128 bits), 10 (192 bits), 11 (256 bits)
#          ^ Block cipher mode: 0 (Electronic code book), 1 (Cipher block chaining)
#         ^ Padding: 0 (no), 1 (PKCS #5)

.include "mmap" # Include custom memory map

.globl aes_encrypt

.data DROM_AESAPI_ADDR

#  Strings
LPSZ_ERR01_PREP_MODE_NOT_VALID:
    .asciiz "The specified mode of operation is unknown. Please check if the 'opflags' parameter is correctly formatted.\n"
LPSZ_ERR02_PREP_KEYSIZE_MISMATCH:
    .asciiz "Input key size must match operation mode specification. Please check input parameters.\n"
LPSZ_ERR03_PREP_NOT_ENOUGH_DST_SPACE:
    .asciiz "Allocated memory for results is not big enough,\nplease allocate at least the same size of input data.\n"
LPSZ_ERR04_PREP_NOT_ENOUGH_DST_SPACE_AND_PAD:
    .ascii "Allocated memory for results is not big enough,\nsince your data is aligned to block size,"
    .asciiz "please consider to allocate more memory\nto accomodate padding or disable padding at all.\n"
LPSZ_ERR05_PREP_SOURCE_NOT_ALIGNED:
    .asciiz "Source data is not aligned to 16 bytes boundary, consider enabling padding.\n"

.data DRAM_AESAPI_ADDR

.align 2 # align word

# The padded source buffer is used when the source data block shall be padded before encryption,
# i.e. when padding needs to be added to a partial block.
paddedsource_buffer: .space 16

iv_ptr: .word 0 # Local pointer to init. vector
cbc_started_chain: .word 0 # This will be set to 1 when 1st block was encoded with IV,
                           # so next rounds will use previous block.


.text TEXT_AESAPI_ADDR

## TODOS:
# - Each time we call aes_iencr, check for return value, if not valid return it to caller thru EOF


# [errcode] aes_encrypt(src_sz, dst_sz, key_sz, opflags)(src_ptr, dest_ptr, key_ptr, iv_ptr)
#   Encrypts the given data with the given key, has hardcoded references
#   to lookup tables in "aes-tables.asm" to simplify code and speed-up operations.
aes_encrypt:
    add     $sp, $sp, -4
    sw      $ra, 0($sp)                         # Save return address as usual
    
    # Store IV pointer to local memory (add 4 because we have just added an element to stack)
    lw      $t0, 16($sp)
    sw      $t0, iv_ptr

    # Check if everything is ok and set up constants in ($s5 : $s7)
    jal     aes_prepare
    bnez    $v0, aes_encrypt$eof                # Something bad happened... bypass given error code.
    
    # Generate key schedule in the global 'key_schedule'
    jal     aes_keyexpand

    # Here starts the encryption mode of operation scheduler, contents of registers are:
    # s0: Number of complete source blocks    s4: Utility, block size in bytes
    # s1: Size of remaining block in bytes    s2: Counter (preserved)
    # s3: Permanent source pointer (to convert in a1 by method)

    # Get useful informations from trusted source size
    mul     $s4, $s6, 4                         # Get block size in bytes (should be 16)
    div     $a0, $s4                            # Divide source size by number of blocks (so we can get iterations and padding)
    mfhi    $s1                                 # Get number of bytes on last partial block (if 0 padding is disabled, otherwise error)
    mflo    $s0                                 # Get full block iteration count
    
    # Prepare for main loop
    lw      $s3, 4($sp)                         # Load in addr.
    lw      $a2, 8($sp)                         # Load out addr.
    beq     $s0, $zero, aes_encrypt$taskpart_pr # Skip full block operation if we have not full sized blocks (source < 16 bytes)
    
    move    $s2, $zero                          # Initialize counter to zero
aes_encrypt$taskfull: # --- Full block handling ---
    jal     aes_encr_transform_source           # (ECB/CBC) s3 -> a1
    jal     aes_iencr                           # Encrypt source to destination
    
    # Increment pointers and counter
    add     $s2, $s2, 1
    add     $s3, $s3, $s4                       # Increment in addr. of block size
    add     $a2, $a2, $s4                       # Increment out addr. of block size
    
    blt     $s2, $s0, aes_encrypt$taskfull      # Repeat till end of full blocks.
    # End of loop
    
aes_encrypt$taskpart_pr: # --- Partial block handling: data PREINITIALIZATION ---
    # Write last block with padding bytes in the "padded source buffer" if padding is enabled,
    # otherwise if the source is not block aligned, 'aes_prepare' should already have thrown an exception.
    and     $t0, $a3, 0x08                      # Do we want padding? Lets mask bits...
    beqz    $t0, aes_encrypt$eof                # If no padding, we have finished.
    
    move    $t1, $s3                            # Get current source pointer for byte copy (assuming now at start of partial block)
    la      $s3, paddedsource_buffer            # Retrieve encryption source pointer...
    move    $t2, $s3                            # ... that equals destination pointer for byte copy
    
    move    $s2, $zero                          # Initialize counter to zero, MUST NOT BE RESETTED IN 'taskppad_*'
    beq     $s2, $s1, aes_encrypt$taskppad_pr   # If this is true (counter = 0 = bytes in partial block, our source is aligned, skip data write.    
aes_encrypt$taskpart: # --- Partial block handling: data ---
    # In addr. and out addr. already at right positions, once copied data to buffer, set permanently in addr to buf. addr.
    # Source bLock address ($a0) can be altered, it will then be overwritten
    
    lbu     $t0, 0($t1)                         # Byte IO
    sb      $t0, 0($t2)
    
    # Increment pointers and counter
    add     $s2, $s2, 1
    add     $t1, $t1, 1                         # Increment in addr. of 1 byte
    add     $t2, $t2, 1                         # Increment out addr. of 1 byte
    
    blt     $s2, $s1, aes_encrypt$taskpart      # Repeat till end of valid bytes

aes_encrypt$taskppad_pr:
    sub     $t0, $s4, $s1                       # Repeated pattern to write: padding size = block size - partial block size
aes_encrypt$taskppad: # --- Partial block handling: padding ---

    sb      $t0, 0($t2)
    
    # Increment pointer and counter
    add     $s2, $s2, 1
    add     $t2, $t2, 1                         # Increment out addr. of 1 byte (in addr not required, placed at end of source)
    
    blt     $s2, $s4, aes_encrypt$taskppad     # Repeat till we reach block size
    # End of loop
    
    # Source and destination parameters already set (src=paddedsource_buffer, dst=[as last iteration])
    jal     aes_encr_transform_source           # (ECB/CBC) s3 -> a1
    jal     aes_iencr                           # Encrypt last block to destination
    
    li      $v0, 0 # No error
    # OK, return
aes_encrypt$eof:
    lw      $ra, 0($sp)
    add     $sp, $sp, 4                         # Retrieve return address from stack
    jr      $ra                                 # Return to caller with value in $v0


# [a1->transfd_block] aes_encr_transform_source(s3 -> src_block, a2->cdst_ptr, a3->opflags, s4->blocksize)
#   This non-canonical function ensures that a correctly formed source block is feed into the internal encryption function 'aes_iencr'.
#   'paddedsource_buffer' may be used for temporary data storage.
#   ECB mode in 'opflags':
#     transfd_block = src_block
#   CBC mode in 'opflags':
#     if not_first_flag == 0    transfd_block = (paddedsource_buffer) src_block ^ init_vector
#     else                      transfd_block = (paddedsource_buffer) src_block ^ (cdst_ptr - blocksize)
#   SHOULD NOT CAUSE PROBLEMS IF 'src_block' IS ALREADY 'paddedsource_buffer'
aes_encr_transform_source:
    and     $t0, $a3, 0x04                      # Are we operating in ECB or CBC?
    beqz    $t0, aes_encr_transform_source$ecb  # Little trade-off, redirect the faster implementation
aes_encr_transform_source$cbc:
    # Let 't0' point to data to XOR with (IV or last encryption output)
    lw      $t0, cbc_started_chain              # This is our 'not_first_flag'
    bnez    $t0, aes_encr_transform_source$cbc_nextround # If 'not_first_flag' != 0, then branch
aes_encr_transform_source$cbc_firstround:
    li      $t0, 1
    sw      $t0, cbc_started_chain              # Set the flag to 1, from now on we won't use the IV again.
    lw      $t0, iv_ptr                         # Let 't0' point to the IV (use 'la' if loading direct), we have just started after all...
    j       aes_encr_transform_source$cbc_proc
aes_encr_transform_source$cbc_nextround:
    subu    $t0, $a2, $s4                       # Let 't0' be a pointer to the last output block (cdst_ptr - blocksize), we are rolling...
aes_encr_transform_source$cbc_proc:
    lw      $t2,  0($s3)                        # Load source block
    lw      $t3,  4($s3)
    lw      $t4,  8($s3)
    lw      $t5, 12($s3)
    lw      $t6,  0($t0)                        # Load previously encrypted block or IV
    lw      $t7,  4($t0)
    lw      $t8,  8($t0)
    lw      $t9, 12($t0)
    
    xor     $t2, $t2, $t6                       # XOR blocks (here x86's SIMD SSE PXOR may be very useful, XMM1!!)
    xor     $t3, $t3, $t7
    xor     $t4, $t4, $t8
    xor     $t5, $t5, $t9
    
    la      $t0, paddedsource_buffer            # Use temporary storage inside the padded source buffer for processed data
    sw      $t2,  0($t0)                        # Save them all!
    sw      $t3,  4($t0)
    sw      $t4,  8($t0)
    sw      $t5, 12($t0)
    
    move    $a1, $t0                            # Return in 'a1'
    jr      $ra
aes_encr_transform_source$ecb:
    move    $a1, $s3                            # Return in 'a1'
    jr      $ra






# [errcode] aes_prepare(src_sz, dst_sz, key_sz, opflags)
#   Checks if buffer sizes are OK and sets encryption parameters basing on key bit count.
#   NOTE: Not pure functional, side effects on $s5, $s7
aes_prepare:
    # An address table may be too much code for this little 'switch-case'
    and     $t0, $a3, 0x03                      # Get key size from opflags
    beq     $t0, 0x01, aes_prepare$128par       # Set params for AES-128 core
    beq     $t0, 0x02, aes_prepare$192par       # Set params for AES-192 core
    beq     $t0, 0x03, aes_prepare$256par       # Set params for AES-256 core
    # Invalid value, error
    j       aes_prepare$eret1                   # Go to error-EOF
    
aes_prepare$128par:
    li      $s5,  4                             # Nk, key length in words
    li      $s6,  4                             # Nb, block size in words
    li      $s7, 10                             # Nr, number of rounds
    j       aes_prepare$check1
aes_prepare$192par:
    li      $s5,  6                             # Nk, key length in words
    li      $s6,  4                             # Nb, block size in words
    li      $s7, 12                             # Nr, number of rounds
    j       aes_prepare$check1
aes_prepare$256par:
    li      $s5,  8                             # Nk, key length in words
    li      $s6,  4                             # Nb, block size in words
    li      $s7, 14                             # Nr, number of rounds
    j       aes_prepare$check1
    
    # Check if given key size matches the selected mode calculated size.
aes_prepare$check1:
    mul     $t1, $s5, 4                         # Get key size in bytes
    bne     $a2, $t1, aes_prepare$eret2         # key_sz != specification, BOOO!

    # IF WE ARE NOT PADDING, source size must be a multiple of block size
    # and destination size must be equal-greater than source size.
aes_prepare$check2:
    and     $t0, $a3, 0x08                      # Get padding flag from opflags
    mul     $t1, $s6, 4                         # Get block size in bytes (4*Nb)
    rem     $t2, $a0, $t1                       # src_sz % 4*Nb (alignment)
    # Doing this check here, if using padding and source not aligned,
    # this will never be done elsewhere.
    blt     $a1, $a0, aes_prepare$eret3         # Destination memory size is less than source length! BLAH
    bnez    $t0, aes_prepare$check3             # If padding, we go to padding-mode tests
    bnez    $t2, aes_prepare$eret5              # We are not padding, and the source is not aligned... BAAD
    j       aes_prepare$eof                     # We are OK.
   
    # IF WE ARE PADDING and source is block aligned, the destination should
    # be at least source size + block size. 
aes_prepare$check3:
    bnez    $t2, aes_prepare$eof                # Padding ON and not aligned, everything is OK.
    add     $t0, $a0, $t1                       # Padding and alignment together may cause trouble:
    blt     $a1, $t0, aes_prepare$eret4         # if dst_sz < (src_sz + 4*Nb) and we are padding... OOH SHITT!    
    # Everything OK, no need to jump.

    # Now returning. Are we fine? Are we in trouble? Nevermind.
aes_prepare$eof:
    move    $v0, $zero                          # Returning, no errors.
    jr      $ra

aes_prepare$eret1:
    la      $a0, LPSZ_ERR01_PREP_MODE_NOT_VALID
    li      $t0, 1                              # Error 01 - Mode not valid
    j       aes_prepare$eeof
aes_prepare$eret2:
    la      $a0, LPSZ_ERR02_PREP_KEYSIZE_MISMATCH
    li      $t0, 2                              # Error 02 - Key size mismatch
    j       aes_prepare$eeof
aes_prepare$eret3:
    la      $a0, LPSZ_ERR03_PREP_NOT_ENOUGH_DST_SPACE
    li      $t0, 3                              # Error 03 - Allocated memory for results not big enough.
    j       aes_prepare$eeof
aes_prepare$eret4:
    la      $a0, LPSZ_ERR04_PREP_NOT_ENOUGH_DST_SPACE_AND_PAD
    li      $t0, 4                              # Error 04 - Allocated memory for results+pad not big enough.
    j       aes_prepare$eeof
aes_prepare$eret5:
    la      $a0, LPSZ_ERR05_PREP_SOURCE_NOT_ALIGNED
    li      $t0, 5                              # Error 05 - Source not aligned to block size
aes_prepare$eeof:
    li      $v0, 4                              # Display error and nevermind if we are losing
    syscall                                     # $a0 (src_sz), we are returning anyway.
    move    $v0, $t0                            # Move in place errorcode retval.
    jr      $ra                                 # And the troubleful journey ends...
