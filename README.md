# CA647: Secure Programming Course from DCU

This is my answer to the secure programming assignment from Dublin City University.
The goal was to gain a remote access on a server exploiting a buffer overflow vulnerability.

## Explanations
I put extra explanations in readme.md under explanation folder. It looks like a phrack paper. So if you wanna know what I really try to do just take a look a it. It's quite long (959 lines). Also I let you the extra shellcodes I tried. All the files are in the archive called explanation.

+ `sh.s` contains a socket descriptor reuse shellcode that allows us to display a shell on the server side.

+ `binls.s` contains a socket descriptor reuse shellcode that should execute the `/bin/ls -l` command on the client side but it freezes....

+ `binsh.` contains this time a socket descriptor reuse shellcode that should execute `/bin/sh` on the client side but it also freezes

+ `bindshell.sh` contains a port binding shellcode that should execute `/bin/sh` on client side but the prompt also freezes.


**Note** : `sh.s` works but not binsh. There is a problem with the `dup2` function or something that makes the prompt freeze on client side...

## Usage
The correct shellcode is implemented in `exploit.c` file. If you want to change the shellcode you should change
the variable `shellcode` from `exploit.c` by yours. Obviously the shellcode (ASM instructions) should be coded
using hexadecimal format.


## Note
If I remember correctly the shellcode must not exceed 140 characters otherwise the execution of the code will not be able to overwrite the return code.
