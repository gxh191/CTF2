#include <stdio.h>
#include <stdlib.h>

// Testing in libc-2.31
// gcc hooks.c -o hooks

void init()
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
}

void get_shell()
{
    system("/bin/sh");
}

int main(void)
{
    init();

    unsigned long long ptr;
    unsigned long long value;

    printf("backdoor: %p\n", get_shell);
    printf("printf  : %p\n", printf);

    printf("Address:\n");
    scanf("%llx", &ptr);

    printf("Value:\n");
    scanf("%llx", &value);

    *(unsigned long long *)ptr = value;

    malloc(0x20);

    return 0;
}
