# rijndael-mips
An implementation of the [Rijndael AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
symmetric encryption algorithm (FIPS PUB 197).

The code is written in MIPS assembly, can encrypt or decrypt data in both ECB and CBC
[modes of operation](https://en.wikipedia.org/wiki/Block_cipher_modes_of_operation),
handles optional OpenSSL-style padding and accepts 128, 192 or 256 bit sized keys.
It has a wrapper designed to work in the [MARS simulator](http://courses.missouristate.edu/KenVollmar/MARS/).

## Structure

The assembly source is placed in the `asm` folder:

- `aes.asm`: Top level algorithm, initialization, padding management, mode conversions (ECB/CBC);
- `aes-encrypt.asm`: Inner encryption rounds (`AddRoundKey`, `SubBytes`, `ShiftRows`, `MixColumns`);
- `aes-ksched.asm`: Key expansion ([see here](https://en.wikipedia.org/wiki/Rijndael_key_schedule));
- `aes-tables.asm`: Lookup tables calculated using broken source in `_dev_misc\partial_cpp_impl`;
- `main.asm`: Application entry point, argument parsing, conversion and validation, wraps library with MARS `syscall` I/O;
- `mmap`: Segment addresses for code, read-only data and RW memory.

`lib` contains the simulator, some testing libraries and the MARS UI settings I used while developing.

## Running

You will need OpenSSL, Java **and the Scala REPL** in your path for this to work.

Running `ares.cmd` will start the application in MARS:
run the program without any parameter to show usage (the arguments are intentionally similar to OpenSSL).

`testtool.cmd` is a fancy test script which verifies the algorithm against OpenSSL by comparing their output.

I am sorry, but for now I am only providing batch scripts; anyway it is only a wrapper to Scala code and so can
easily be run any platform with small changes.

## Why MIPS?
I made this in a week for a computer assembly course I attended in 2014.
Our professor wanted us to make a *small* MIPS program to be evaluated as a final test.

A friend of mine ([@lucad93](https://github.com/lucad93)) made a tool to calculate the date of Easter on a given year,
another one made an implementation of the Caesar cipher, which inspired me.

#### "Woo! Your prof. must've been impressed!"

Well, not really: in my case the "small program" grew a little larger and at the test it
was tagged as "*not my own work*" and criticized by my idea of writing comments in english.

Then I was asked to draw a small but detailed flowchart describing the algorithm in less
than a couple of minutes, obviously failing.

At the end he resigned and made me write a prime number generator in place.
