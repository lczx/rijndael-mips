# Università di Pavia, Facoltà di Ingegneria, 2014
# MIPS I '85 32-bit R3000A compatible SPIM/MARS IO SYSCALL (AT&T SYNTAX)
#
# Luca Zanussi [410841] <luca.z@outlook.com>
#
# FIPS-197 / NIST Advanced Encryption Standard (Rijndael)
#  http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf
#  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
#
# > AES Library key schedule utility
#

# Function signatures format:
#
#   [return values] function(registers values)(stack values)
#
# parameters are passed left to right in registers and from lower
# RAM to higher addreses in stack (keep things simple) and no,
# they are not curried functions from Haskell and Scala.

.include "mmap" # Include custom memory map

.globl aes_keyexpand key_schedule

.data DRAM_AESKEYX_ADDR
    # This size should be 4 * Nb * (Nr + 1), but let's allocate the maximum
    # possible assuming Nb = 4, Nr = 14 @ AES256
    key_schedule: .space 240 # COULD USE '.extern' but address not controllable


.text TEXT_AESKEYX_ADDR

# [errcode] aes_keyexpand(..., ..., ..., ...)(///, ..., ..., key_ptr)
#   Expands the given encryption key into the key schedule,
#   using parameters specified by 'aes_prepare'.
#   Data is stored into the 'key_schedule' global variable.
#   NOTE: The 1st stack thingy is the return address from the previous.
aes_keyexpand:
    # This is the old method using syscall to allocate heap, not
    # reallocable in the case of multiple block operations.
      ## Save in $s0 the argument to preserve from syscall
      #move    $s0, $a0
      ## Save in $a0 the amount of heap to allocate in bytes
      #addi    $a0, $s7, 1                         # $a0 = Nr + 1
      #mul     $a0, $a0, $s6                       # $a0 = Nb * (Nr + 1)
      #mul     $a0, $a0, 4                         # $a0 = 4 * Nb * (Nr + 1)
      #li      $v0, 9
      #syscall                                     # Now v0 is an address to allocated memory
      #                                            # if we don't modify it again during the
      #                                            # procedure, it is out return value.
    
    lw      $t0, 12($sp)                        # Get key pointer argument, initial source index
    la      $t1, key_schedule                   # Get destination global space address, initial dest. idx
    
    mul     $t3, $s5, 4                         # Amount of bytes to write (4 * Nk)
    add     $t3, $t3, $t1                       # Offset init. dest. addr. added to previous,
                                                # now $t3 is end address.
    
    # The first part of the key schedule is simply the original key, here is where we copy it.
    #   $t0: source copy index   $t2: copy buffer
    #   $t1: dest. copy index    $t4: dest. end
aes_keyexpand$copy:
    lw      $t2, ($t0)                          # Copy word in buffer...
    sw      $t2, ($t1)                          # ... and store to destination
    
    addi    $t0, $t0, 4                         # Increment pointers
    addi    $t1, $t1, 4
    
    bne     $t1, $t3, aes_keyexpand$copy        # Copy finished check
    
    # Here is the legacy code derived from my older junky C implementation,
    # which performed an endianness conversion while copying... slower.
    # If you want to use this, remember to change the RCON in 'aes-tables.asm' consequently.
      #lbu     $t2, 0($t0)       #sb      $t2, 3($t1)
      #lbu     $t2, 1($t0)       #sb      $t2, 2($t1)
      #lbu     $t2, 2($t0)       #sb      $t2, 1($t1)
      #lbu     $t2, 3($t0)       #sb      $t2, 0($t1)      
      #addi    $t0, $t0, 4       #addi    $t1, $t1, 4
      #bne     $t1, $t3, aes_keyexpand$copyloop    # Loop if not already end address
    
    # End of copy.


    # Here comes the real processing, CRAZINESS HERE I COME:
    # store the last generated dword in a 'temp' variable,
    #  - if idx % Nk == 0: (mix A) temp = lookup, rotate, mask, xor, RCON
    #  - if Nk > 6 (AES-256) $$ idx % Nk == 4: (mix B) temp = lookup, alt. rotate, mask, xor
    # finally, computed dword is (Nk dwords before) ^ temp
    #   $s0: byte index (not address!)
    #   $s1: final byte index (= necessary memory amount)
    #   $s2: pointer to actual cell
    #   $s3: 'temp' value
    #   $s4: key length utility CONSTANT (4 * Nk)
    #   $s5 ... $s7: params registered by 'aes_prepare', DO NOT OVERWRITE
    #   $t1: base addr (pointer to heap) in initial loop
    #   $t0, $t1: TEMPORARY FOR BRANCHES AND SUCH
    # LOOP (IN WORDS) FROM Nk TO Nb * (Nr + 1)
    
    mul     $s4, $s5, 4                         # Set $s4 to key length (4 * Nk)
    move    $s0, $s4                            # 4 * Nk is in fact our initial index
    
    # Set $s1 to amount of memory necessary, it is our final index
    addi    $s1, $s7, 1                         # $a0 = Nr + 1
    mul     $s1, $s1, $s6                       # $a0 = Nb * (Nr + 1)
    mul     $s1, $s1, 4                         # $a0 = 4 * Nb * (Nr + 1)
    
aes_keyexpand$loop:
    la      $t1, key_schedule                   # Load base address
    addu    $s2, $s0, $t1                       # Calculate pointer from index
    
    lw      $s3, -4($s2)                        # temp = (DWORD)key_schedule[i - 1]

    # Check if i % Nk == 0 (byteidx % 4 * Nk == 0), $s4 is 4 * Nk, $t0 is result of remainder
    rem     $t0, $s0, $s4                       # $t0 = byteidx % (4 * Nk)
    beqz    $t0, aes_keyexpand$mixa             # Branch if condition is true
    
    # Check if Nk > 6 && i % Nk == 4 ($s5 > 6 && byteidx % 4 * Nk == 4 * 4), $t0 already calculated
    seq     $t0, $t0, 16                        # Condition #2 true if byteidx % (4 * Nk) == 4 * 4
    beqz    $t0, aes_keyexpand$eochks           # SHORT CIRCUIT, if this is false, AND will never be true
    
    sgt     $t0, $s5, 6                         # Condition #1 true if Nk > 6
    beqz    $t0, aes_keyexpand$eochks           # If less-or-equal, proceed like nothing happened too
    
    j       aes_keyexpand$mixb                  # Both tests succeeded, go to mix mode B.

    # Note that we took advantage of the short circuit by putting the less probable condition first and
    # eventually skipping the other one.
    
    # End of checks, 'temp' ($s3) is set, still in loop,
    # here is the returning point from mixes.
aes_keyexpand$eochks:
    sub     $t0, $s2, $s4                       # Set $t0 to index of Nk words ago
    lw      $t0, 0($t0)                         # Load value of key_schedule[i - Nk]
    xor     $t0, $t0, $s3                       # Do ^ of key_schedule[i - Nk] and 'temp'
    sw      $t0, 0($s2)                         # Store calculation result to actual cell.

    add     $s0, $s0, 4                         # Pass to the next DWORD...
    bne     $s0, $s1, aes_keyexpand$loop        # ... and continue loop if we have still work to do.

    jr      $ra                                 # All done, hooray!

    # Here we have the mixing procedures...
aes_keyexpand$mixa:
    # temp is $s3, this can be optimized, I believe (16 8 0 24)
    # If I remember, commented values are for the endianness converting version.
    
    srl     $t0, $s3, 0 #16                     # <INIT 0> temp >> 0 (useless)
    andi    $t0, 0xff                           # (temp >> 0) & 0xff
    mulu    $t0, $t0, 4                         # convert in order to address dword index in lookup
    lw      $t0, te2($t0)
    andi    $t0, 0xff000000                     # te2[(temp >> 0) & 0xff] & 0xff000000
    
    srl     $t1, $s3, 24 #8                     # <INIT 1>
    andi    $t1, 0xff
    mulu    $t1, $t1, 4                         # convert in order to address dword index in lookup
    lw      $t1, te3($t1)
    andi    $t1, 0x00ff0000                     # te3[(temp >> 24) & 0xff] & 0x00ff0000
    
    srl     $t2, $s3, 16 #0                     # <INIT 2>
    andi    $t2, 0xff
    mulu    $t2, $t2, 4                         # convert in order to address dword index in lookup
    lw      $t2, te0($t2)
    andi    $t2, 0x0000ff00                     # te0[(temp >> 16) & 0xff] & 0x0000ff00
    
    srl     $t3, $s3, 8 #24                     # <INIT 3>
    andi    $t3, 0xff
    mulu    $t3, $t3, 4                         # convert in order to address dword index in lookup
    lw      $t3, te1($t3)
    andi    $t3, 0x000000ff                     # te1[(temp >> 8) & 0xff] & 0x000000ff
    
    div     $t4, $s0, $s4                       # <INIT 4> i / Nk (byteidx / (4 * Nk))
    sub     $t4, $t4, 1                         # i / Nk - 1
    mulu    $t4, $t4, 4                         # convert in order to address dword index in lookup
    lw      $t4, rcon($t4)                      # rcon[i / Nk - 1]
    
    xor     $t0, $t0, $t1
    xor     $t1, $t2, $t3
    xor     $s3, $t0, $t1
    xor     $s3, $s3, $t4                       # temp = $t0 ^ $t1 ^ $t2 ^ $t3 ^ $t4
    
    j       aes_keyexpand$eochks
    
aes_keyexpand$mixb:
    # temp is $s3, something can be merged with the previous, maybe...
    # THE SAME WORKS BOTH WITH BIG AND LITTLE ENDIAN!!!
    
    srl     $t0, $s3, 24                        # temp >> 24
    andi    $t0, 0xff
    mulu    $t0, $t0, 4                         # convert in order to address dword index in lookup
    lw      $t0, te2($t0)
    andi    $t0, 0xff000000                     # te2[(temp >> 24) & 0xff] & 0xff000000
    
    srl     $t1, $s3, 16
    andi    $t1, 0xff
    mulu    $t1, $t1, 4                         # convert in order to address dword index in lookup
    lw      $t1, te3($t1)
    andi    $t1, 0x00ff0000                     # te3[(temp >> 16) & 0xff] & 0x00ff0000
    
    srl     $t2, $s3, 8
    andi    $t2, 0xff
    mulu    $t2, $t2, 4                         # convert in order to address dword index in lookup
    lw      $t2, te0($t2)
    andi    $t2, 0x0000ff00                     # te0[(temp >> 8) & 0xff] & 0x0000ff00
    
    srl     $t3, $s3, 0
    andi    $t3, 0xff
    mulu    $t3, $t3, 4                         # convert in order to address dword index in lookup
    lw      $t3, te1($t3)
    andi    $t3, 0x000000ff                     # te1[(temp >> 0) & 0xff] & 0x000000ff
    
    xor     $t0, $t0, $t1
    xor     $t1, $t2, $t3
    xor     $s3, $t0, $t1                       # temp = $t0 ^ $t1 ^ $t2 ^ $t3
    
    j       aes_keyexpand$eochks
