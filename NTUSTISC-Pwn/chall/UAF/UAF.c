#include <stdio.h>
#include <stdlib.h>

// gcc UAF.c -o UAF

void init()
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
}

int main()
{
    init();

    char *buf[0x10];
    char *ptr1 = malloc(0x20);
    char *ptr2 = malloc(0x20);
    char *ptr3 = malloc(0x20);

    free(ptr1);
    free(ptr2);
    free(ptr3);

    ptr1= 0
    ptr2=0;

    // ptr1, ptr2 are dangling pointers now.

    memcpy(buf, ptr1, 0x10);
    printf("ptr1 fd: %#llx\n", *(unsigned long long *)buf);

    memcpy(buf, ptr2, 0x10);
    printf("ptr2 fd: %#llx\n", *(unsigned long long *)buf);

    memcpy(buf, ptr3, 0x10);
    printf("ptr3 fd: %#llx\n", *(unsigned long long *)buf);

    return 0;
}
