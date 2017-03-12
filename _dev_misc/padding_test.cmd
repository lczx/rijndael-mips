:: provide dec.txt
@echo off
openssl enc -e -aes-128-ecb -in dec.txt -out enc.txt -K 000102030405060708090a0b0c0d0e0f -iv 0000000000000000 
openssl enc -d -aes-128-ecb -in enc.txt -out dpd.txt -K 000102030405060708090a0b0c0d0e0f -iv 0000000000000000 -nopad
xxd enc.txt
echo.
xxd dpd.txt

del enc.txt
del dpd.txt

pause