@echo off
:: Because we LOVE batch scripts...
set "in=%1"
set "encparams=-K 000102030405060708090a0b0c0d0e0f -iv 0000000000000000"
openssl enc -e -aes-128-cbc -in "%in:"=%" -out ~enc %encparams%
openssl enc -d -aes-128-cbc -in ~enc -out ~dpd %encparams% -nopad

echo 1. Input:
xxd "%in:"=%"
echo.

echo 2. Encoded:
xxd ~enc
echo.

echo 3. Decoded (ignoring padding):
xxd ~dpd
echo.

del ~*
pause
