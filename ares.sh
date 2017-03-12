#!/bin/sh
entry_point=asm/main.asm

# Parameters:
#   start execution at global main (sm), do not display copyright notice (nc),
#   assemble all files as a project (p), use parameters following (pa).
java -jar lib/Mars4_4.jar sm nc p $entry_point pa $@ >&2
errno=$?
echo \>\> Process terminated with error code $errno
exit $errno
