# BufferOverflow
I put extra explanations in explanation.txt. It looks 
like a phrack paper. So if you wanna know what I really
try to do just take a look a it. It's quite long (959 lines)
Also I let you the extra shellcodes I tried. All the files are
in archive called explanation.

sh.s contains a socket descriptor reuse shellcode that allows
use to display a shell on the server side.

binls contains a socket descriptor reuse shellcode that should 
execute the /bin/ls -l command on the client side but it freezes....

binsh contains this time a socket descriptor reuse shellcode 
that should execute /bin/sh on the client side but it also freezes

bindshell.sh contains a port binding shellcode that should execute
/bin/sh on client side but the prompt also freezes.


Note : sh.s works but not binsh. There is a problem with the dup2
function or something that makes the prompt freeze on client side...
