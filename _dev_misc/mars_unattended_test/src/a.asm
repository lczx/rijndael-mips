.globl main

.data
str: .asciiz "Ah!"

.text

break 0

main:
  la $t0, gdt
  add $t1, $t0, 32
  li $t2, 0xff
inc:
  sb $t2, 0($t0)
  add $t0, $t0, 1
  bne $t0, $t1, inc
  
  li $v0, 4
  la $a0, str
  syscall
