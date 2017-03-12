# Università di Pavia, Facoltà di Ingegneria, 2014
# MIPS I '85 32-bit R300A compatible SPIM/MARS IO SYSCALL (AT&T SYNTAX)
#
# Luca Zanussi [410841] <luca.z@outlook.com>
#
# FIPS-197 / NIST Advanced Encryption Standard (Rijndael)
#  http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf
#  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
#
# > Example program with argument parsing implementing the AES library
#

# Function signatures format:
#
#   [return values] function(register values)(stack values)
#
# parameters are passed left to right in registers and from lower
# RAM to higher addresses in stack (keep things simple) and no,
# they are not curried functions from Haskell and Scala.

.include "mmap" # Include custom memory map

.globl main

.data DROM_KERNEL_ADDR
  # ROM Constants ------------------------------------------------------------------------

  # > Buffers informations
  iobufsiz:            .word 65536 # Size of I/O buffers
  
  # > Argument parser configuration
  aprs_tablesiz:       .word 11 # Amount of possible keywords ROM  
  aprs_lpsz_keywords:  .word # Array of pointers to matchable keywords
    aprs_keyword_ifn aprs_keyword_ofn aprs_keyword_key aprs_keyword_iv aprs_keyword_128e aprs_keyword_128c
    aprs_keyword_192e aprs_keyword_192c aprs_keyword_256e aprs_keyword_256c aprs_keyword_nopad
  aprs_lpfn_handlers:  .word # Array of pointes to keyword handling procedures
    parseargs$h_ifn parseargs$h_ofn parseargs$h_key parseargs$h_iv parseargs$h_128e parseargs$h_128c
    parseargs$h_192e parseargs$h_192c parseargs$h_256e parseargs$h_256c parseargs$h_nopad

  # > Argument parser resources (matchable keywords)
  aprs_keyword_ifn:     .asciiz "-in"
  aprs_keyword_ofn:     .asciiz "-out"
  aprs_keyword_key:     .asciiz "-K"
  aprs_keyword_iv:      .asciiz "-iv"
  aprs_keyword_128e:    .asciiz "-aes-128-ecb"
  aprs_keyword_128c:    .asciiz "-aes-128-cbc"
  aprs_keyword_192e:    .asciiz "-aes-192-ecb"
  aprs_keyword_192c:    .asciiz "-aes-192-cbc"
  aprs_keyword_256e:    .asciiz "-aes-256-ecb"
  aprs_keyword_256c:    .asciiz "-aes-256-cbc"
  aprs_keyword_nopad:   .asciiz "-nopad"

  # > Console messsages store
  LPSZ_ARGV_NOOUTFN:    .asciiz "You need to pass an output filename thru the commandline using \"-out [filename]\".\n"
  LPSZ_ARGV_NOOPFLAGS:  .ascii  "A mode of operation was not specified, "
                         .asciiz "please run the application without arguments for documentation.\n"
  LPSZ_ARGV_IEMPTY:     .asciiz "Nothing to do. Input file was empty.\n"
  LPSZ_ARGV_UNEXSIZ:    .asciiz "Malformed command line: value expected but argument list end encountered.\n"    
  LPSZ_FILE_IERR:       .ascii  "File not found (input). No access rights? "
                         .asciiz "More probably the file does not exists (wrong parh).\n"
  LPSZ_FILE_OERR:       .asciiz "Cannot open output file. Not enough access rights? Malformed path? I blame you!\n"
  LPSZ_FILE_MAXBUFSZ:   .asciiz "THE PASSED FILE IS LARGER THAN 64KiB! This may cause unexpected behavior.\n"

  # > Documentation page
  _hlp_:
    .ascii  "\nAES-ASM r1 MIPS-I 32, (c) 2007-2014 Luca Zanussi, 7 Set 2014\n"
    .ascii  "This is a bugged/free software/open source/whatever implementation of Rijndael.\n"
    .ascii  "FIPS-197 NIST Advanced Encryption Standard, PKCS \#5, NIST SP 800-38A\n"
    .ascii  "\n"
    .ascii  "Usage:\taes-encrypt <mode> <options>\n"
    .ascii  "\n"
    .ascii  "Arguments can be passed in the preferred order.\n"
    .ascii  "\n"
    .ascii  "<mode> - Cause I don't know what to do...\n"
    .ascii  "Allows you to select from the following encryption algorithms:\n"
    .ascii  "  -aes-128-ecb    -aes-192-ecb    -aes-256-ecb\n"
    .ascii  "  -aes-128-cbc    -aes-192-cbc    -aes-256-cbc\n"
    .ascii  "\n"
    .ascii  "<options> - Use your wrench to tweak that...\n"
    .ascii  "To specify algorithm IO, key data and further options:\n"
    .ascii  "  -in <file>\tInput file\n"
    .ascii  "  -out <file>\tOutput file\n"
    .ascii  "  -K <key>\tKey in hex is the next argument\n"
    .ascii  "  -iv <iv>\tIV in hex is the next argument (not used in ECB)\n"
    .ascii  "  -nopad\tDisable PKCS #5 block padding, input must be mult. of 16 bytes\n"
    .ascii  "\n"
    .ascii  "This software is provided \"as is\" without any warranty,\n"
    .asciiz "if you are an Apple/MS user, it will probably start teasing you.\n"



.data DRAM_KERNEL_ADDR
  # RAM Variables ------------------------------------------------------------------------
  
  # Some items aligned on word boundary,
  # so key schedule algorithm and such can take their arguments with 'lw'
  .align 2 # Keep following aligned until we reach something with size % 4 != 0
  
  # > I/O data buffers (size from 'iobufsiz')
  _idata:
  _odata:
    .space 65536 #RAM
  # AWESOM-O! The same buffer can be used for input-output!

  # > Argument store  
  filename_in:         .space 260 # Input file name (should equal WINAPI MAX_PATH)
  filename_out:        .space 260 # Output file name (same as before)
  argument_key:        .space 32 # Maximum size of key, 256 bits
  argument_iv:         .space 16 # Size of IV, (same as block size)
  argument_opflags:    .word 0 # Opflags value 
  
  # > I/O data variables
  idatasiz:            .word 0 # Amount of read bytes
  ikeymsiz:            .word 0 # Size of provided key material

  # DEBUGGING key and data material ------------------------------------------------------
  
  # sys_dstptr:     .space 128
  # sys_srcptr:     .ascii "perfect!"
  # sys_keyptr:     .byte 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0a 0x0b 0x0c 0x0d 0x0e 0x0f
  #
  # sys_srcdsiz:    .word 8 # Provided source size
  # sys_dstdsiz:    .word 128 # Destination allocated space in bytes
  # 
  # sys_128ksiz:    .word 16  # Provided 128 bits key size in bytes
  # sys_192ksiz:    .word 24  # Provided 192 bits key size in bytes
  # sys_256ksiz:    .word 32  # Provided 256 bits key size in bytes
  #
  # > TEST #1
  # dbg1_plaintext: .byte 0x32 0x43 0xf6 0xa8 0x88 0x5a 0x30 0x8d 0x31 0x31 0x98 0xa2 0xe0 0x37 0x07 0x34
  # dbg1_128key:    .byte 0x2b 0x7e 0x15 0x16 0x28 0xae 0xd2 0xa6 0xab 0xf7 0x15 0x88 0x09 0xcf 0x4f 0x3c
  # dbg1_192key:    .byte 0x8e 0x73 0xb0 0xf7 0xda 0x0e 0x64 0x52 0xc8 0x10 0xf3 0x2b 0x80 0x90 0x79 0xe5
  #                       0x62 0xf8 0xea 0xd2 0x52 0x2c 0x6b 0x7b
  # dbg1_256key:    .byte 0x60 0x3d 0xeb 0x10 0x15 0xca 0x71 0xbe 0x2b 0x73 0xae 0xf0 0x85 0x7d 0x77 0x81
  #                       0x1f 0x35 0x2c 0x07 0x3b 0x61 0x08 0xd7 0x2d 0x98 0x10 0xa3 0x09 0x14 0xdf 0xf4
  #
  # > TEST #2
  # dbg2_plaintext:  .byte 0x00 0x11 0x22 0x33 0x44 0x55 0x66 0x77 0x88 0x99 0xaa 0xbb 0xcc 0xdd 0xee 0xff
  # # Other keys are subsets of this one, only passed key size change is necessary
  # dbg2_key:       .byte 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0a 0x0b 0x0c 0x0d 0x0e 0x0f
  #                       0x10 0x11 0x12 0x13 0x14 0x15 0x16 0x17 0x18 0x19 0x1a 0x1b 0x1c 0x1d 0x1e 0x1f
  # # expected 128 out: 69c4e0d8 6a7b0430 d8cdb780 70b4c55a
  # # expected 192 out: dda97ca4 864cdfe0 6eaf70a0 ec0d7191
  # # expected 256 out: 8ea2b7ca 516745bf eafc4990 4b496089

.text TEXT_KERNEL_ADDR

  main:
    beqz $a0, printusage # If no arguments were given, print usage.
  
    # Parse arguments, at the end $t7 contains opflags.
    jal parseargs
    
    # Load source data into memory...
    jal getdata
    
    # Check if everything is OK...
    jal checkargs
    
    # DO SOMETHIN' (with data)
    jal troublemaker    
    
    # Save everything out...
    jal flushdata
    
    # End, no need to 'j eof'
  
  # Exit program calls
  eof: # EXIT_SUCCESS
    li $a0, 0
    li $v0, 17 # SYSCALL exit2 (with result)
    syscall
  eeof_msg: # EXIT_FAILURE + message in $a0
    li $v0, 4 # SYSCALL, print string
    syscall # Perform call with pointer in $a0
  eeof: # EXIT_FAILURE
    li $a0, 1 # ERRORLEVEL 1 = EXIT_FAILURE <cstdlib>
    li $v0, 17 # SYSCALL, exit2 (terminate with value)
    syscall # Exit immediately with errorcode


  # Simple, prints application usage text to stdout thru syscall.
  printusage:
    la $a0, _hlp_
    li $v0, 4 # SYSCALL print string
    syscall
    j eof



  # Preliminary check to verify that necessary arguments were specified
  checkargs:
    # Why check filename_in if we already tried to open 'dat file?
    
    lbu $t0, filename_out # This should not be done, but we know that our memory is initalized to zero so...
    beqz $t0, checkargs$nooutfile # We don't have specified '-out' on the command line!
    
    # We cannot perform checks on argument_key and argument_iv without more complex code, someone can specify a NUL block
    # (all zeros) and we cant perform an ASCII-friendly check like in filename_out.
    # i.e. If we don't specify a key, all zeros will be used, the same for IV if we are in CBC
    
    lw $t0, argument_opflags
    beqz $t0, checkargs$noopflags # Operation directives were not given on the commandline
    
    lw $t0, idatasiz
    beqz $t0, checkargs$emptysource # The input file was empty
    
    jr $ra # Everything OK, all tests passed.
  checkargs$nooutfile:
    la $a0, LPSZ_ARGV_NOOUTFN
    j eeof_msg
  checkargs$noopflags:
    la $a0, LPSZ_ARGV_NOOPFLAGS
    j eeof_msg
  checkargs$emptysource:
    la $a0, LPSZ_ARGV_IEMPTY
    j eeof_msg
  
  
  
  # Reads the file previously got from arguments.
  getdata:
    li $v0, 13 # SYSCALL, open file
    la $a0, filename_in # Input file path
    li $a1, 0 # Flags: read only
    syscall
    
    bltz $v0, getdata$nofile # If file descriptor is < 0, something wrong happened.
                             # No access rights? More probably the file does not exists (or wrong parh).
    move $a0, $v0 # Move descriptor to argument
    la $a1, _idata # Where to save data
    lw $a2, iobufsiz # 65536 bytes, maximum data size
    li $v0, 14 # SYSCALL, read from file
    syscall
    
    beq $v0, $a2, getdata$maxsiz # Number of bytes read = Buffer size,
                                 # We are not so nice to allocate more RAM, warn.
    sw $v0, idatasiz # Store file size
    
    li $v0, 16 # SYSCALL, close file
    syscall # $a0 already holds descriptor, invalidate it.
    
    jr $ra # Return
  
  getdata$nofile:
    la $a0, LPSZ_FILE_IERR
    j eeof_msg
  getdata$maxsiz:
    la $a0, LPSZ_FILE_MAXBUFSZ
    j eeof_msg
  
  
  
  # Result data just computed from internal algorithm, flush the content of the output buffer (_odata)
  flushdata:
    lw $t0, idatasiz
    
    lw $t1, argument_opflags
    andi $t1, 0x08 # isolate 1xxx padding bit
    beqz $t1, flushdata$open # Skip next calculus if we don't have padding, WE ALSO ASSUME THAT INPUT IS BLOCK ALIGNED
        
    # We have padding so... ($s6 should contain block size in DWORDs after a call to the AES library)
    # Avoid multiplications!
    mul $t2, $s6, 4 # get block size in bytes
    rem $t1, $t0, $t2 # get size of partial block from idatasiz % 4Nb... (can be zero)
    sub $t1, $t2, $t1 # ... then amount needed to complete block (4Nb - ANS, padding size, can be at most the size of a block)
    add $t0, $t0, $t1 # Add to 'idatasiz' the padding amount in bytes, here's out output data size.
  
  flushdata$open:
    # Open file, we have already done checks on valid filename_out
    li $v0, 13 # SYSCALL, open file
    la $a0, filename_out # Output file path
    li $a1, 1 # Flags: write only + create
    syscall
    
    bltz $v0, flushdata$fileerr # Something wrong? If descriptor < 0, then yes... EPIC FAIL CONGRATS N00B
    
    move $a0, $v0 # Move descriptor to argument
    la $a1, _odata # Pointer to write buffer
    move $a2, $t0 # The value previously calculated of bytes to write, considering padding (if any).
    li $v0, 15 # SYSCALL, write to file
    syscall
    
    # Just ignore written bytes amount, we could check for errors ($v0 < 0) but...
    # with the file already open, the only problem possible may be only not enough space on disk, I think.
    
    li $v0, 16 # SYSCALL, close file
    syscall # $a0 already holds descriptor, invalidate it.
    
    jr $ra # Return
    
  flushdata$fileerr:
    la $a0, LPSZ_FILE_OERR
    j eeof_msg



  # Parses the given arguments in $a0 (argc) and $a1 (argv), as a MARS convention.
  # OPFLAGS are not stored, but kept in the $t7 register.
  parseargs:
    # t8: arg idx   t9: kwd idx
    # s0: arg max   s1: kwd max  
    # s2: args ptr   s3: kwds ptr   s4: k()s ptr
    # a0: arg  ptr   a1: kwd  ptr
    # t7: OPFLAGS
    
    add $sp, $sp, -4
    sw  $ra, 0($sp)
    li $t7, 0x08 # Clean opflags, by default padding is enabled
  
    # a0: argc, a1: argv
    move $s0, $a0           # Argument count
    lw   $s1, aprs_tablesiz # Possible arguments / Handlers count
    move $s2, $a1 # Arg. array ptr.
    la   $s3, aprs_lpsz_keywords # Possible keywords ptr.
    la   $s4, aprs_lpfn_handlers # Handlers ptr. array ptr.
    
    move $t8, $zero # Current argument index
  parseargs$argloop:
    mul  $a0, $t8, 4
    add  $a0, $s2, $a0
    lw   $a0, 0($a0) # argv[i]
    
    move $t9, $zero # Current handler index
  parseargs$kwdloop:
    mul  $a1, $t9, 4
    add  $a1, $s3, $a1
    lw   $a1, 0($a1) # keywords[i]
    
    jal strcmp
    beqz $v0, parseargs$match # If returned zero, we have a match!
    
    add $t9, $t9, 1 # Increment handler ID
    blt $t9, $s1, parseargs$kwdloop # Try 'till we run out of handlers
    
    # If we are here: Unrecognized argument, ignore
    
  parseargs$nextarg:
    add $t8, $t8, 1 # Increment argument index in argv
    blt $t8, $s0, parseargs$argloop # If we reached argc, we have run out of arguments
    # Now finished parsing, incoming final operations

    sw $t7, argument_opflags # Store opflags value in the case its register gets overwritten
   
    lw  $ra, 0($sp)
    add $sp, $sp, 4
    jr  $ra # All done!
    
  parseargs$match:
    # Matched! Load handler address and jump
    mul  $t0, $t9, 4
    add  $t0, $s4, $t0
    lw   $t0, 0($t0) # handlers[i]
    jr   $t0 # Jump to handler pointer
    
  parseargs$getvaluearg:
    # Utility function for handlers, loads in $a2 the pointer to the next value argument,
    # incrementing the argument counter and so skipping the value parsing.
    add $t8, $t8, 1 # Go to next value argument (and skip its parsing)
    beq $t8, $s0, parseargs$getvaluearg_err # Like in 'parseargs$nextarg', branch if we have finished our arguments, no value.
    mul $a2, $t8, 4
    add $a2, $s2, $a2
    lw  $a2, 0($a2) # argv[i+1]  # String source
    jr  $ra # Ret. to handler
  parseargs$getvaluearg_err:
    la  $a0, LPSZ_ARGV_UNEXSIZ
    j eeof_msg # Value argument expected, but end reached

  parseargs$h_ifn:
    jal parseargs$getvaluearg    # Stores source in $a2
    la  $a3, filename_in         # String destination
    jal strcpy # Copy string
    j parseargs$nextarg # Process next argument
  parseargs$h_ofn:
    jal parseargs$getvaluearg    # Stores source in $a2
    la  $a3, filename_out        # String destination
    jal strcpy # Copy string
    j parseargs$nextarg # Process next argument
  parseargs$h_key:
    jal parseargs$getvaluearg    # Stores source in $a2
    la  $a3, argument_key
    jal hexconv # Convert hex string to byte array, ARGUMENT PTRs PRESERVED
    jal strlen # Calculates the given argument value string length (to get key length)
    srl $v0, $v0, 1 # Divide result by 2 (ascii_hex -> byte)
    sw $v0, ikeymsiz # Store to key size
    j parseargs$nextarg # Process next argument
  parseargs$h_iv:
    jal parseargs$getvaluearg    # Stores source in $a2
    la  $a3, argument_iv
    jal hexconv # Convert hex string to byte array
    j parseargs$nextarg # Process next argument
  parseargs$h_128e:
    ori $t7, 0x01 # 0001 -> 128 bits, ECB
    j parseargs$nextarg # Process next argument
  parseargs$h_128c:
    ori $t7, 0x05 # 0101 -> 128 bits, CBC
    j parseargs$nextarg # Process next argument
  parseargs$h_192e:
    ori $t7, 0x02 # 0010 -> 192 bits, ECB
    j parseargs$nextarg # Process next argument
  parseargs$h_192c:
    ori $t7, 0x06 # 0110 -> 192 bits, CBC
    j parseargs$nextarg # Process next argument
  parseargs$h_256e:
    ori $t7, 0x03 # 0011 -> 256 bits, ECB
    j parseargs$nextarg # Process next argument
  parseargs$h_256c:
    ori $t7, 0x07 # 0111 -> 256 bits, CBC
    j parseargs$nextarg # Process next argument
  parseargs$h_nopad:
    andi $t7, 0xf7 # 1xxx -> padding flag reset with AND mask 0xf7 (1111 0111)
    j parseargs$nextarg # Process next argument
  
  
  
  # Troublemaker!
  troublemaker:
    add     $sp, $sp, -4
    sw      $ra, 0($sp)                         # Save return address as usual
    
    # Theoretically we should respect the convention and pass 4+ arguments on the stack; but here,
    # for the sake of my mental illness, we are passing "something here, something there".
    # Params are so fuzzy for internal optimization (length vars discarded after checks).
    lw      $a0, idatasiz                       # 1st argument: Source data size
    lw      $a1, iobufsiz                       # 2nd argument: Destination data size
    lw      $a2, ikeymsiz                       # 3rd argument: Key size
    lw      $a3, argument_opflags               # 4th argument: Mode of operation (e.x. 0x00000001 -> AES-128-ECB-NOPAD)
    
    add     $sp, $sp, -16                       # Reserve space in stack
    la      $t0, _idata
    sw      $t0,  0($sp)                        # 1st stackarg: Source data pointer
    la      $t0, _odata
    sw      $t0,  4($sp)                        # 2nd stackarg: Destination data pointer
    la      $t0, argument_key
    sw      $t0,  8($sp)                        # 3rd stackarg: Key pointer
    la      $t0, argument_iv
    sw      $t0, 12($sp)                        # 4th stackarg: Initialization vector pointer
    
    jal     aes_encrypt                         # [errcode] aes_encrypt(src_sz, dst_sz, key_sz, opflags)(src_ptr, dest_ptr, key_ptr, iv_ptr)
    bnez    $v0, eeof
    
    add     $sp, $sp, 16                        # Cleanup params from stack
    
    #
    #
    # Do something with results here...
    #
    #
    
    lw      $ra, 0($sp)
    add     $sp, $sp, 4                         # Retrieve return address from stack
    jr      $ra                                 # Return to caller



  # Copies a null-terminated string from $a2 to $a3.
  # Given addresses are preserved for reuse.
  strcpy:
    move $t0, $a2
    move $t1, $a3
  strcpy$loop:
    lbu  $t2, 0($t0)
    sb   $t2, 0($t1)
    beqz $t2, strcpy$end
    add  $t0, $t0, 1
    add  $t1, $t1, 1
    j strcpy$loop
  strcpy$end:
    jr $ra
  
  
  
  # Converts an hex ASCII string in $a2 to a byte array in $a3, watch out for endianness! Preserves arguments
  hexconv:
    move $t0, $a2
    move $t1, $a3
    # Ok, can be done better, SIMD like
  hexconv$loop:
    # Upper nibble
    lbu  $t2, 0($t0)
    beqz $t2, hexconv$end # We have reached end of null-terminated string
    move $t5, $zero # Reset result0
    andi $t4, $t2, 0x40 # AND with 01000000 (0x40), if != 0 we are treating not numeric values
    beqz $t4, hexconv$isnum0
    addi $t5, $zero, 9 # Add 10 to result because we are in a-f | A-F values, but remove one because of ASCII
  hexconv$isnum0:
    andi $t4, $t2, 0x0f # AND with 00001111 keeps the lower bits, converting ASCII to BCD
    add  $t5, $t5, $t4 # Add result bias to BCD value
    
    # Lower nibble
    lbu  $t2, 1($t0)
    beqz $t2, hexconv$end # Condition of odd numbered characters, ignore pair
    move $t6, $zero # Reset result1
    andi $t4, $t2, 0x40 # TO treat not numeric values, like before
    beqz $t4, hexconv$isnum1
    addi $t6, $zero, 9 # Add 10 - 1 to result like before if in chars
  hexconv$isnum1:
    andi $t4, $t2, 0x0f # Get BCD
    add  $t6, $t6, $t4
    
    sll  $t5, $t5, 4 # Move upper nibble
    or   $t5, $t5, $t6 # Merge
    sb   $t5, 0($t1) # Save
    
    # Increment pointers
    add  $t0, $t0, 2
    add  $t1, $t1, 1
    
    j hexconv$loop # No checks needed here, exits from within
  hexconv$end:
    jr $ra
  
  
  
  # Compares string at $a0 with string at $a1, returns 0 (in $v0) if they are equal.
  # Given addresses are preserved for multiple checks.
  strcmp:
    move $v0, $zero
    move $t0, $a0
    move $t1, $a1
  strcmp$loop1:
    lbu  $t2, 0($t0)
    lbu  $t3, 0($t1)
    beq  $t2, $t3, strcmp$loop2
    li   $v0, 1
    jr   $ra
  strcmp$loop2:
    add  $t0, $t0, 1
    add  $t1, $t1, 1
    bne  $t2, $zero, strcmp$loop1
    jr   $ra



  # Calculates length of string @ $a2 and saves it in $v0.
  strlen:
    move $v0, $a2 # Preserve arg. (not convention)
  strlen$lp:
    lbu $t0, 0($v0) # Get byte (char)
    add $v0, $v0, 1 # ptr++
    bnez $t0, strlen$lp # loop while char != 0
    # End cycle
    sub $v0, $v0, $a2 # End ptr. - start ptr. = length
    sub $v0, $v0, 1 # Subtract 1 from string termination
    jr $ra
