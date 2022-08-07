#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './zerostorage1'

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

bps = [0x1628]
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
    p.recvuntil('7. Exit\n')
    p.recvuntil('==================\n')
    p.recvuntil('Your choice: ')

def create(size, content):
    eat()
    p.sendline('1')
    p.recvuntil('Length of new entry: ')
    p.sendline(str(size))
    p.recvuntil('Enter your data: ')
    p.send(content)

def edit(index,size,content):
    eat()
    p.sendline('2')
    p.recvuntil('Entry ID: ')
    p.sendline(str(index))
    p.recvuntil('Length of new entry: ')
    p.sendline(str(size))
    p.recvuntil('Enter your data: ')
    p.send(content)

def merge(fromm, to, s):
    eat()
    p.sendline('3')
    p.recvuntil('Merge from Entry ID: ')
    p.sendline(str(fromm))
    p.recvuntil('Merge to Entry ID: ')
    p.sendline(str(to))

def delete(index):
    eat()
    p.sendline('4')
    p.recvuntil('Entry ID: ')
    p.sendline(str(index))

def show(index):
    eat()
    p.sendline('5')
    p.recvuntil('Entry ID: ')
    p.sendline(str(index))

def list(index):
    eat()
    p.sendline('6')


create(0x18, '1'*0x18)


p.interactive()

