@echo off
:: sm: Start execution at global main
:: nc: Do not display copyright notice
:: p:  Project mode, assemble all files
:: pa: Program arguments following
java -jar mars4_4.jar sm nc p "src/a.asm" pa
pause>nul
