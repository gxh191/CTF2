#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
void init(){
    setvbuf(stdout,0,2,0);
    setvbuf(stdin,0,2,0);
    setvbuf(stderr,0,2,0);
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    struct sock_filter sfi[] ={
        {0x20,0x00,0x00,0x00000004},
        {0x15,0x00,0x04,0xc000003e},
        {0x20,0x00,0x00,0x00000000},
        {0x15,0x02,0x00,0x0000000a},
        {0x15,0x01,0x00,0x0000003b},
        {0x06,0x00,0x00,0x7fff0000},
        {0x06,0x00,0x00,0x00050000}
    };
    struct sock_fprog sfp = {7, sfi};
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &sfp);
    alarm(0x20);
}
void backDoor(){
    __asm__("syscall;ret");
    __asm__("pop rdx;ret");
    __asm__("pop rdi;ret");
    __asm__("pop rsi;ret");
    __asm__("pop rax;ret");
    __asm__("push rax;pop rcx;ret");
    __asm__("mov rdi,rcx;ret");
}
char bssBuf[0x300] = {0};
char bingDwenDwen[0x200] = {0};
int main(){
    char buf[0x8] = {0};
    init();
    puts("Hello,Do You Like Bing Dwen Dwen?");
    read(0,bingDwenDwen,0x200);
    memcpy(buf,bingDwenDwen,0x200);
    puts("Good Bye~");
    close(0);
    close(1);
    close(2);
}